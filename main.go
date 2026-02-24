package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"syscall"
)

func runCommand(ctx context.Context, cmd ...string) error {
	rest := func() []string {
		if len(cmd) > 1 {
			return cmd[1:]
		}

		return nil
	}

	command := exec.CommandContext(ctx, cmd[0], rest()...)
	output, err := command.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}

		return fmt.Errorf("running command: %v: %w", string(output), err)
	}

	return nil

}

func mustRunCommand(ctx context.Context, cmd ...string) {
	err := runCommand(ctx, cmd...)
	if err != nil {
		fatal(err)
	}
}

func lookupDockerIPv4(ctx context.Context) (net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", "host.docker.internal")
	if err != nil {
		return nil, err
	}

	if len(ips) == 0 {
		return nil, errors.New("dialer did not return any results")
	}

	return ips[0], nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "Fatal error: ", err)
	os.Exit(1)
}

const iptablesNamespace = "DOCKER_PROXY_ANYTHING"

const iptablesNamespaceTproxy = iptablesNamespace + "_TPROXY"

func cleanupIptables(ctx context.Context) {
	// Ignore errors during cleanup
	for _, iptables := range []string{"iptables", "ip6tables"} {
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesNamespaceTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-F", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-X", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespaceTproxy)
	}

	for _, version := range []string{"-4", "-6"} {
		runCommand(ctx, "ip", version, "rule", "del", "fwmark", "1", "table", "100")
		runCommand(ctx, "ip", version, "route", "del", "local", "default", "dev", "lo", "table", "100")
	}
}

func rstTCPConnection(conn net.Conn) error {
	defer conn.Close()

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return errors.New("not tcp connection, closing anyway")
	}

	// Send a RST to the connection
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		tcpConn.Close()
		return err
	}

	var setSockErr error
	err = rawConn.Control(func(fd uintptr) {
		// Set SO_LINGER with a timeout of 0
		linger := syscall.Linger{Onoff: 1, Linger: 0}
		setSockErr = syscall.SetsockoptLinger(int(fd), syscall.SOL_SOCKET, syscall.SO_LINGER, &linger)
	})

	tcpConn.Close()
	if err != nil {
		return err
	}

	if setSockErr != nil {
		return setSockErr
	}

	return nil
}

// ErrConnRefused is returned when the gateway is up, but the origin is closed for example
var ErrConnRefused = errors.New("connection has been refused by origin")

var ErrNon2xx = errors.New("non 2xx status code returned")

type closeWriter interface {
	CloseWrite() error
}

type closeReader interface {
	CloseRead() error
}

type closeReadWriter interface {
	net.Conn
	closeWriter
	closeReader
}

type bufioNetConn struct {
	closeReadWriter
	reader *bufio.Reader
}

func (c *bufioNetConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func dialHTTPConnect(ctx context.Context, network string, address, sourceAddress string, gateway net.Addr) (closeReadWriter, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, gateway.Network(), gateway.String())
	if err != nil {
		return nil, fmt.Errorf("dialing gateway: %w", err)
	}

	switch conn.(type) {
	case *net.UDPConn:
		return nil, errors.New("udp connections are not accepted")
	case *net.UnixConn, *net.TCPConn:
	default:
		return nil, fmt.Errorf("unknown connection type: %T", conn)
	}

	ur := url.URL{
		Host: address,
	}

	headers := http.Header{}
	headers.Add("User-Agent", "proxy-everything/0.0.1/"+sourceAddress)
	headers.Add("Connection", "close")
	headers.Add("Host", address)
	headers.Add("X-Forwarded-For", sourceAddress)
	headers.Add("X-Proto", network)

	proxyHTTPRequest := &http.Request{
		Method:     http.MethodConnect,
		URL:        &ur,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
		Host:       address,
	}

	if err := proxyHTTPRequest.Write(conn); err != nil {
		return nil, fmt.Errorf("http write: %w", err)
	}

	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, proxyHTTPRequest)
	if err != nil {
		return nil, fmt.Errorf("reading proxy http request: %w", err)
	}

	if res.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%v: %w", res.StatusCode, ErrConnRefused)
	}

	return &bufioNetConn{conn.(closeReadWriter), reader}, nil
}

var egressPort *int = flag.Int("http-egress-port", 49121, "the port where the gateway is going to be reaching to in order to receive connections")
var proxyAnythingAddress *string = flag.String("address", "127.0.0.3:41209", "default address that proxy-everything will intercept traffic in")
var proxyAnythingV6Address *string = flag.String("address-v6", "[::1]:41209", "default address that proxy-everything will intercept traffic in ipv6")
var dockerGatewayCidr *string = flag.String("docker-gateway-cidr", "172.17.0.0/16", "the docker gateway to be used")

type proxy struct {
	addr       *net.TCPAddr
	listener   net.Listener
	egressAddr net.Addr
}

func newProxy(ctx context.Context, addr *net.TCPAddr, egressAddr net.Addr) *proxy {
	config := net.ListenConfig{
		Control: func(network string, addr string, conn syscall.RawConn) error {
			return conn.Control(func(fd uintptr) {
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
					fatal(fmt.Errorf("setsockoptint: %w", err))
				}
			})
		},
	}

	listener, err := config.Listen(ctx, "tcp", addr.String())
	if err != nil {
		fatal(fmt.Errorf("couldn't listen on port, is another proxy-everything running?: %w", err))
	}

	return &proxy{addr: addr, listener: listener, egressAddr: egressAddr}
}

func (p *proxy) Close() error {
	return p.listener.Close()
}

func (p *proxy) run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Go(func() {
		for {
			conn, err := p.listener.Accept()
			if err != nil {
				log.Println(err)
				return
			}

			containerConnection := conn.(*net.TCPConn)
			sourceAddr := containerConnection.RemoteAddr().(*net.TCPAddr)

			// This might look counter-intuitive, but this is how it works with TPROXY
			dstAddr := conn.LocalAddr().(*net.TCPAddr)

			wg.Go(func() {
				wg := &sync.WaitGroup{}
				defer wg.Wait()

				log.Println("debug: received connection", sourceAddr, "to", dstAddr)

				originConnection, err := dialHTTPConnect(ctx, dstAddr.Network(), dstAddr.String(), sourceAddr.String(), p.egressAddr)
				if err != nil {
					if err := rstTCPConnection(containerConnection); err != nil {
						log.Println("error sending rst to connection:", err)
					}

					log.Println("error: connecting to origin:", err)
					return
				}

				// container -> gateway
				wg.Go(func() {
					defer containerConnection.CloseRead()
					defer originConnection.CloseWrite()
					io.Copy(originConnection, containerConnection)
				})

				// gateway -> container
				wg.Go(func() {
					defer originConnection.CloseRead()
					defer containerConnection.CloseWrite()
					io.Copy(containerConnection, originConnection)
				})
			})
		}
	})

}

func entrypoint(ctx context.Context) {
	ip, err := lookupDockerIPv4(ctx)
	if err != nil {
		fatal(err)
	}

	// unused for now but indicates future feature work
	flag.Int("http-ingress-port", 49122, "the port where the gateway is going to be listening in to receive connections")

	flag.Parse()

	egressAddress, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(*egressPort)))
	if err != nil {
		fatal(err)
	}

	_, dockerNetwork, err := net.ParseCIDR(*dockerGatewayCidr)
	if err != nil {
		fatal(err)
	}

	if !dockerNetwork.Contains(egressAddress.IP.To4()) {
		fatal(fmt.Errorf("docker network %v does not contain resolved egress address %v", dockerNetwork, egressAddress))
	}

	proxyAnythingAddressTCP, err := net.ResolveTCPAddr("tcp4", *proxyAnythingAddress)
	if err != nil {
		fatal(fmt.Errorf("resolving tcp addr: %w", err))
	}

	proxyAnythingAddressV6TCP, err := net.ResolveTCPAddr("tcp6", *proxyAnythingV6Address)
	if err != nil {
		fatal(fmt.Errorf("resolving tcp v6 addr: %w", err))
	}

	proxies := []*proxy{
		newProxy(ctx, proxyAnythingAddressTCP, egressAddress),
		newProxy(ctx, proxyAnythingAddressV6TCP, egressAddress),
	}

	fmt.Printf("Proxy address: %s, Port: %d\n", proxyAnythingAddressTCP.IP.String(), proxyAnythingAddressTCP.Port)

	cleanupIptables(ctx)

	type ipTablesSetup struct {
		ipTablesCmd     string
		ipVersion       string
		ignoreAddresses []string
		proxy           *proxy
	}

	ipTablesSetupList := []ipTablesSetup{
		{
			ipTablesCmd:     "iptables",
			ipVersion:       "-4",
			ignoreAddresses: []string{"127.0.0.1/8", *dockerGatewayCidr},
			proxy:           proxies[0],
		},
		{
			ipTablesCmd:     "ip6tables",
			ipVersion:       "-6",
			ignoreAddresses: []string{"::1/128"},
			proxy:           proxies[1],
		},
	}

	for _, iptablesSetup := range ipTablesSetupList {
		iptables := iptablesSetup.ipTablesCmd

		// 0. Set up routing for marked packets
		mustRunCommand(ctx, "ip", iptablesSetup.ipVersion, "rule", "add", "fwmark", "1", "table", "100")
		mustRunCommand(ctx, "ip", iptablesSetup.ipVersion, "route", "add", "local", "default", "dev", "lo", "table", "100")

		// 1. Create the DIVERT chain in the mangle table
		mustRunCommand(ctx, iptables, "-t", "mangle", "-N", "DIVERT")

		// 2. Set the routing mark (1) for packets entering this chain
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "DIVERT", "-j", "MARK", "--set-mark", "1")

		// 3. Accept the packet (stop further processing in the mangle table for these packets)
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "DIVERT", "-j", "ACCEPT")

		// 4. In PREROUTING, check if there is an existing socket for this TCP packet.
		// If yes, send it to the DIVERT chain.
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "DIVERT")

		const iptablesNamespaceTproxy = iptablesNamespace + "_TPROXY"

		// 5. Setup the TPROXY rules in our namespace
		mustRunCommand(ctx, iptables, "-t", "mangle", "-N", iptablesNamespaceTproxy)

		// ensure the chain starts empty before adding rules
		mustRunCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceTproxy)

		for _, cidrToIgnore := range iptablesSetup.ignoreAddresses {
			mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceTproxy, "-d", cidrToIgnore, "-j", "RETURN")
		}

		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceTproxy, "-m", "mark", "-p", "tcp", "--mark", "100", "-j", "RETURN")

		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceTproxy, "-p", "tcp", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-port",
			strconv.Itoa(iptablesSetup.proxy.addr.Port), "--on-ip", iptablesSetup.proxy.addr.IP.String())

		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "PREROUTING", "-p", "tcp", "-j", iptablesNamespaceTproxy)

		// 6. Now time to do the new namespace for local rules, we will mark all matching egress with 0x1
		mustRunCommand(ctx, iptables, "-t", "mangle", "-N", iptablesNamespace)

		// ensure the chain starts empty before adding rules
		mustRunCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespace)

		for _, cidrToIgnore := range iptablesSetup.ignoreAddresses {
			mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespace, "-d", cidrToIgnore, "-j", "RETURN")
		}

		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespace, "-m", "mark", "-p", "tcp", "--mark", "100", "-j", "RETURN")

		// mark it so it's processed by loopback by the table 100
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespace, "-j", "MARK", "--set-mark", "1")

		// Everything that tries to egress, process through the iptablesNamespace
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "OUTPUT", "-p", "tcp", "-j", iptablesNamespace)

		// flush the cache
		mustRunCommand(ctx, "ip", iptablesSetup.ipVersion, "route", "flush", "cache")
	}

	// TODO: IPv6

	wg := &sync.WaitGroup{}
	for _, proxy := range proxies {
		defer proxy.Close()
	}

	defer wg.Wait()
	for _, proxy := range proxies {
		proxy.run(ctx, wg)
	}
}

func main() {
	if os.Getenv("SERVER") == "1" {
		flag.Parse()
		addrString := net.JoinHostPort("0.0.0.0", strconv.Itoa(*egressPort))
		addr, err := net.ResolveTCPAddr("tcp", addrString)
		if err != nil {
			fatal(err)
		}

		startDummyServer(addr)
		return
	}

	// TODO: Terminal signalling
	entrypoint(context.Background())
}
