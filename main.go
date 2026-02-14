package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"sync"
	"syscall"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

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

const nftTableName = "proxy_anything"

// cleanupNftables removes our nftables table and policy routing rules.
// Errors are silently ignored to support idempotent restarts.
func cleanupNftables() {
	nftConn, err := nftables.New()
	if err != nil {
		return
	}

	for _, family := range []nftables.TableFamily{nftables.TableFamilyIPv4, nftables.TableFamilyIPv6} {
		nftConn.DelTable(&nftables.Table{Name: nftTableName, Family: family})
	}
	_ = nftConn.Flush()

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			continue
		}
		for _, rule := range rules {
			if rule.Mark == 1 && rule.Table == 100 {
				_ = netlink.RuleDel(&rule)
			}
		}

		lo, err := netlink.LinkByName("lo")
		if err != nil {
			continue
		}
		var dst *net.IPNet
		if family == netlink.FAMILY_V4 {
			dst = &net.IPNet{IP: net.IP{0, 0, 0, 0}, Mask: net.CIDRMask(0, 32)}
		} else {
			dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
		}
		_ = netlink.RouteDel(&netlink.Route{
			LinkIndex: lo.Attrs().Index,
			Dst:       dst,
			Table:     100,
			Type:      unix.RTN_LOCAL,
		})
	}
}

// setupPolicyRouting sets up: ip rule add fwmark 1 table 100
// and: ip route add local default dev lo table 100
func setupPolicyRouting(family int) error {
	rule := netlink.NewRule()
	rule.Family = family
	rule.Table = 100
	rule.Mark = 1
	mask := uint32(0xFFFFFFFF)
	rule.Mask = &mask
	if err := netlink.RuleAdd(rule); err != nil {
		return fmt.Errorf("rule add fwmark 1 table 100 (family %d): %w", family, err)
	}

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("looking up lo: %w", err)
	}

	// Equivalent: ip route add local default dev lo table 100
	// RTN_LOCAL requires RT_SCOPE_HOST, otherwise the kernel rejects it.
	// Must use To4(), as net.IPv4zero is interpreted as a valid IPv6.
	var dst *net.IPNet
	if family == netlink.FAMILY_V4 {
		dst = &net.IPNet{IP: net.IPv4zero.To4(), Mask: net.CIDRMask(0, 32)}
	} else {
		dst = &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	}
	if err := netlink.RouteAdd(&netlink.Route{
		LinkIndex: lo.Attrs().Index,
		Dst:       dst,
		Scope:     netlink.SCOPE_HOST,
		Table:     100,
		Type:      unix.RTN_LOCAL,
	}); err != nil {
		return fmt.Errorf("route add local default dev lo table 100 (family %d): %w", family, err)
	}

	return nil
}

type nftSetupConfig struct {
	family          nftables.TableFamily
	ignoreAddresses []string
	proxy           *proxy
}

// setupNftables configures TPROXY interception via nftables:
//   - "prerouting" chain: divert existing sockets, skip ignored CIDRs, tproxy new TCP
//   - "output" chain (type route): mark egress TCP with fwmark 1 for policy re-routing
func setupNftables(configs []nftSetupConfig) error {
	nftConn, err := nftables.New()
	if err != nil {
		return fmt.Errorf("nftables connection: %w", err)
	}

	for _, cfg := range configs {
		table := nftConn.AddTable(&nftables.Table{
			Name:   nftTableName,
			Family: cfg.family,
		})

		// Single prerouting chain. The socket-transparent rule acts as the "divert":
		// packets with an existing transparent socket get marked and accepted before
		// reaching the tproxy rule. Unlike iptables, nftables accept in a base chain
		// does NOT skip other base chains at the same hook, so everything must be in
		// one chain for accept to work as an early-exit.
		prerouting := nftConn.AddChain(&nftables.Chain{
			Name:     "prerouting",
			Table:    table,
			Type:     nftables.ChainTypeFilter,
			Hooknum:  nftables.ChainHookPrerouting,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(-150)), // mangle
		})

		// iptables equivalent: -t mangle -A PREROUTING -p tcp -m socket -j DIVERT
		// where DIVERT does: -j MARK --set-mark 1 then -j ACCEPT
		nftConn.AddRule(&nftables.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Socket{Key: expr.SocketKeyTransparent, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uint32ToBytes(1)},
				&expr.Immediate{Register: 1, Data: uint32ToBytes(1)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
				&expr.Verdict{Kind: expr.VerdictAccept},
			},
		})

		// iptables equivalent: -t mangle -A <chain> -d <cidr> -j RETURN
		for _, cidr := range cfg.ignoreAddresses {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("parsing CIDR %s: %w", cidr, err)
			}

			nftConn.AddRule(&nftables.Rule{
				Table: table,
				Chain: prerouting,
				Exprs: matchDestCIDR(cfg.family, ipNet, &expr.Verdict{Kind: expr.VerdictReturn}),
			})
		}

		// iptables equivalent: -t mangle -A <chain> -m mark --mark 100 -p tcp -j RETURN
		nftConn.AddRule(&nftables.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: matchMark(100, &expr.Verdict{Kind: expr.VerdictReturn}),
		})

		// iptables equivalent: -t mangle -A <chain> -p tcp -j TPROXY --tproxy-mark 0x1/0x1 --on-port PORT --on-ip IP
		nftConn.AddRule(&nftables.Rule{
			Table: table,
			Chain: prerouting,
			Exprs: buildTproxyExprs(cfg.family, cfg.proxy.addr),
		})

		// iptables equivalent: -t mangle OUTPUT chain
		// type "route" triggers re-routing after mark is set, like mangle OUTPUT in iptables.
		output := nftConn.AddChain(&nftables.Chain{
			Name:     "output",
			Table:    table,
			Type:     nftables.ChainTypeRoute,
			Hooknum:  nftables.ChainHookOutput,
			Priority: nftables.ChainPriorityRef(nftables.ChainPriority(-150)),
		})

		for _, cidr := range cfg.ignoreAddresses {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				return fmt.Errorf("parsing CIDR %s: %w", cidr, err)
			}

			nftConn.AddRule(&nftables.Rule{
				Table: table,
				Chain: output,
				Exprs: matchDestCIDR(cfg.family, ipNet, &expr.Verdict{Kind: expr.VerdictReturn}),
			})
		}

		nftConn.AddRule(&nftables.Rule{
			Table: table,
			Chain: output,
			Exprs: matchMark(100, &expr.Verdict{Kind: expr.VerdictReturn}),
		})

		// iptables equivalent: -t mangle -A <chain> -j MARK --set-mark 1
		nftConn.AddRule(&nftables.Rule{
			Table: table,
			Chain: output,
			Exprs: []expr.Any{
				&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
				&expr.Immediate{Register: 1, Data: uint32ToBytes(1)},
				&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
			},
		})
	}

	if err := nftConn.Flush(); err != nil {
		return fmt.Errorf("nftables flush: %w", err)
	}

	return nil
}

// matchMark matches tcp packets with the given fwmark and applies a verdict.
func matchMark(mark uint32, verdict *expr.Verdict) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: uint32ToBytes(mark)},
		verdict,
	}
}

func matchDestCIDR(family nftables.TableFamily, ipNet *net.IPNet, verdict *expr.Verdict) []expr.Any {
	var offset, length uint32
	if family == nftables.TableFamilyIPv4 {
		offset = 16 // IPv4 dst addr offset
		length = 4
	} else {
		offset = 24 // IPv6 dst addr offset
		length = 16
	}

	ip := ipNet.IP
	mask := ipNet.Mask
	if family == nftables.TableFamilyIPv4 {
		ip = ip.To4()
	}

	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: []byte(mask), Xor: make([]byte, length)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte(ip.Mask(mask))},
		verdict,
	}
}

func buildTproxyExprs(family nftables.TableFamily, addr *net.TCPAddr) []expr.Any {
	var nfproto uint32
	var addrBytes []byte
	if family == nftables.TableFamilyIPv4 {
		nfproto = uint32(unix.NFPROTO_IPV4)
		addrBytes = addr.IP.To4()
	} else {
		nfproto = uint32(unix.NFPROTO_IPV6)
		addrBytes = addr.IP.To16()
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(addr.Port))

	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Immediate{Register: 1, Data: addrBytes},
		&expr.Immediate{Register: 2, Data: portBytes},
		&expr.TProxy{Family: byte(nfproto), TableFamily: byte(nfproto), RegAddr: 1, RegPort: 2},
		&expr.Immediate{Register: 1, Data: uint32ToBytes(1)},
		&expr.Meta{Key: expr.MetaKeyMARK, Register: 1, SourceRegister: true},
	}
}

func uint32ToBytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.NativeEndian.PutUint32(b, v)
	return b
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

	cleanupNftables()

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		if err := setupPolicyRouting(family); err != nil {
			fatal(err)
		}
	}

	nftConfigs := []nftSetupConfig{
		{
			family:          nftables.TableFamilyIPv4,
			ignoreAddresses: []string{"127.0.0.1/8", *dockerGatewayCidr},
			proxy:           proxies[0],
		},
		{
			family:          nftables.TableFamilyIPv6,
			ignoreAddresses: []string{"::1/128"},
			proxy:           proxies[1],
		},
	}

	if err := setupNftables(nftConfigs); err != nil {
		fatal(err)
	}

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
