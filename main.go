package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
	"sync/atomic"
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

const iptablesNamespaceDNS = "DOCKER_PROXY_DNS"

const iptablesNamespaceDNSTproxy = iptablesNamespaceDNS + "_TPROXY"

func cleanupIptables(ctx context.Context) {
	// Ignore errors during cleanup
	for _, iptables := range []string{"iptables", "ip6tables"} {
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-j", iptablesNamespaceTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesNamespaceDNSTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "PREROUTING", "-p", "tcp", "-m", "socket", "-j", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-D", "OUTPUT", "-p", "tcp", "-j", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-D", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesNamespaceDNS)
		runCommand(ctx, iptables, "-t", "mangle", "-F", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-X", "DIVERT")
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespace)
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespaceTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceDNS)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespaceDNS)
		runCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceDNSTproxy)
		runCommand(ctx, iptables, "-t", "mangle", "-X", iptablesNamespaceDNSTproxy)
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
	reader io.Reader
}

func (c *bufioNetConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

// dialHTTPConnect sends an HTTP CONNECT request to the gateway.
// When sni is non-empty, it includes an X-Tls-Sni header. When hostname is
// non-empty, it includes an X-Hostname header. The gateway responds 200 when
// it wants to receive decrypted plaintext (the caller should terminate TLS)
// or 202 when the caller should pass bytes through unmodified.
// shouldDecryptTLS reflects this decision.
func dialHTTPConnect(ctx context.Context, network string, address, sourceAddress string, gateway net.Addr, sni string, hostname string) (closeReadWriter, bool, error) {
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, gateway.Network(), gateway.String())
	if err != nil {
		return nil, false, fmt.Errorf("dialing gateway: %w", err)
	}

	switch conn.(type) {
	case *net.UDPConn:
		return nil, false, errors.New("udp connections are not accepted")
	case *net.UnixConn, *net.TCPConn:
	default:
		return nil, false, fmt.Errorf("unknown connection type: %T", conn)
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

	if sni != "" {
		headers.Add("X-Tls-Sni", sni)
	}

	if hostname != "" {
		headers.Add("X-Hostname", hostname)
	}

	proxyHTTPRequest := &http.Request{
		Method:     http.MethodConnect,
		URL:        &ur,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     headers,
		Host:       address,
	}

	if err := proxyHTTPRequest.Write(conn); err != nil {
		return nil, false, fmt.Errorf("http write: %w", err)
	}

	reader := bufio.NewReader(conn)
	res, err := http.ReadResponse(reader, proxyHTTPRequest)
	if err != nil {
		return nil, false, fmt.Errorf("reading proxy http request: %w", err)
	}

	if res.StatusCode == http.StatusBadRequest {
		return nil, false, fmt.Errorf("%v: %w", res.StatusCode, ErrConnRefused)
	}

	if res.StatusCode >= 300 {
		return nil, false, fmt.Errorf("%v: %w", res.StatusCode, ErrNon2xx)
	}

	// 200 means the gateway wants decrypted plaintext; 202 means pass through.
	shouldDecryptTLS := sni != "" && res.StatusCode == http.StatusOK
	return &bufioNetConn{conn.(closeReadWriter), reader}, shouldDecryptTLS, nil
}

var egressPort *int = flag.Int("http-egress-port", 49121, "the port where the gateway is going to be reaching to in order to receive connections")
var ingressAddress *string = flag.String("http-ingress-address", "", "the address where the ingress HTTP CONNECT listener will accept connections; empty disables it")
var proxyAnythingAddress *string = flag.String("address", "127.0.0.3:41209", "default address that proxy-everything will intercept traffic in")
var proxyAnythingV6Address *string = flag.String("address-v6", "[::1]:41209", "default address that proxy-everything will intercept traffic in ipv6")
var dockerGatewayCidr *string = flag.String("docker-gateway-cidr", "172.17.0.0/16", "the docker gateway to be used")
var disableIPv6 *bool = flag.Bool("disable-ipv6", false, "disable ipv6 if not necessary")
var gatewayIP *string = flag.String("gateway-ip", "", "set to override looking up the host-gateway")
var tlsIntercept *bool = flag.Bool("tls-intercept", false, "enable TLS interception for outbound HTTPS")

type egressConfiguration struct {
	port            atomic.Int64
	internetEnabled atomic.Bool
	dns             atomic.Pointer[dnsRuntimeConfiguration]
}

type dnsRuntimeConfiguration struct {
	AllowPatterns []string
}

func newEgressConfiguration(port int) (*egressConfiguration, error) {
	if err := validatePort(port); err != nil {
		return nil, err
	}

	config := &egressConfiguration{}
	config.port.Store(int64(port))
	config.internetEnabled.Store(true)
	config.dns.Store(&dnsRuntimeConfiguration{
		AllowPatterns: []string{"*"},
	})
	return config, nil
}

func (t *egressConfiguration) Port() int {
	return int(t.port.Load())
}

func (t *egressConfiguration) SetPort(port int) error {
	if err := validatePort(port); err != nil {
		return err
	}

	t.port.Store(int64(port))

	return nil
}

func (t *egressConfiguration) dnsConfig() dnsRuntimeConfiguration {
	config := t.dns.Load()
	if config == nil {
		return dnsRuntimeConfiguration{AllowPatterns: []string{"*"}}
	}

	cloned := *config
	cloned.AllowPatterns = append([]string(nil), cloned.AllowPatterns...)
	return cloned
}

func (t *egressConfiguration) InternetEnabled() bool {
	return t.internetEnabled.Load()
}

func (t *egressConfiguration) DNSAllowPatterns() []string {
	return t.dnsConfig().AllowPatterns
}

func (t *egressConfiguration) SetInternetEnabled(enabled *bool) {
	if enabled == nil {
		return
	}

	t.internetEnabled.Store(*enabled)
}

func (t *egressConfiguration) SetDNSConfig(allowHostnames []string) error {
	config := t.dnsConfig()
	if allowHostnames != nil {
		config.AllowPatterns = normalizeDNSAllowPatterns(allowHostnames)
	}

	t.dns.Store(&config)
	return nil
}

func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %d", port)
	}

	return nil
}

type ingressServer struct {
	addr     *net.TCPAddr
	listener net.Listener
	egress   *egressConfiguration
}

func newIngressServer(addr *net.TCPAddr, egress *egressConfiguration) *ingressServer {
	listener, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		fatal(fmt.Errorf("couldn't listen on ingress address %s: %w", addr.String(), err))
	}

	return &ingressServer{addr: addr, listener: listener, egress: egress}
}

func (s *ingressServer) Close() error {
	return s.listener.Close()
}

func (s *ingressServer) run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Go(func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}

				log.Println("error accepting ingress connection:", err)
				return
			}

			wg.Go(func() {
				s.handleConn(ctx, conn)
			})
		}
	})
}

func (s *ingressServer) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	// Wrap in a buffered reader so ReadRequest can peek on the connection and
	// we can read the buffered bytes that were stored through the peek.
	reader := bufio.NewReader(conn)

	// We have to do the ReadRequest because this can be a HTTP CONNECT!
	req, err := http.ReadRequest(reader)
	if err != nil {
		log.Println("error reading ingress request:", err)
		return
	}

	defer req.Body.Close()
	switch req.Method {
	case http.MethodConnect:
		// proxy to the target destination
		s.handleConnect(ctx, conn, reader, req)
	case http.MethodGet:
		// handleGet can read resources
		s.handleGet(conn, req)
	case http.MethodPut:
		// handlePut can update configuration
		s.handlePut(conn, req)
	default:
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusMethodNotAllowed}).Write(conn); err != nil {
			log.Println("error writing method not allowed response:", err)
		}
	}
}

func (s *ingressServer) handleConnect(ctx context.Context, clientConn net.Conn, reader *bufio.Reader, req *http.Request) {
	targetAddr, err := ingressTargetAddrFromHeader(req)
	if err != nil {
		if writeErr := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusBadRequest}).Write(clientConn); writeErr != nil {
			log.Println("error writing missing target response:", writeErr)
		}

		log.Println("error resolving ingress target address:", err)
		return
	}

	originConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", targetAddr)
	response := http.Response{ProtoMajor: 1, ProtoMinor: 1}
	if err != nil {
		response.StatusCode = http.StatusBadRequest
		if writeErr := response.Write(clientConn); writeErr != nil {
			log.Println("error writing ingress dial failure response:", writeErr)
		}

		log.Println("error dialing ingress target", targetAddr, err)
		return
	}
	defer originConn.Close()

	response.StatusCode = http.StatusOK
	if err := response.Write(clientConn); err != nil {
		log.Println("error writing ingress connect response:", err)
		return
	}

	var tunnelWG sync.WaitGroup
	tunnelWG.Go(func() {
		defer tryClosingWriteSide(originConn)
		defer tryClosingReadSide(clientConn)
		io.Copy(originConn, reader)
	})

	tunnelWG.Go(func() {
		defer tryClosingWriteSide(clientConn)
		defer tryClosingReadSide(originConn)
		io.Copy(clientConn, originConn)
	})

	tunnelWG.Wait()
}

func ingressTargetAddrFromHeader(req *http.Request) (string, error) {
	targetAddr := req.Header.Get("X-Dst-Addr")
	if targetAddr == "" {
		return "", errors.New("missing X-Dst-Addr header")
	}

	host, port, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return "", errors.New("X-Dst-Addr must be IP:port")
	}

	if host == "" {
		return "", errors.New("empty host in X-Dst-Addr header")
	}

	if port == "" {
		return "", errors.New("empty port in X-Dst-Addr header")
	}

	if net.ParseIP(host) == nil {
		return "", errors.New("X-Dst-Addr host must be an IP address")
	}

	return net.JoinHostPort(host, port), nil
}

func (s *ingressServer) handleGet(conn net.Conn, req *http.Request) {
	if req.URL.Path != "/ca" {
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusNotFound}).Write(conn); err != nil {
			log.Println("error writing not found response:", err)
		}

		return
	}

	certPEM, err := os.ReadFile("/ca/ca.crt")
	if err != nil {
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusNotFound}).Write(conn); err != nil {
			log.Println("error writing cert not found response:", err)
		}

		log.Println("error reading CA certificate:", err)
		return
	}

	resp := &http.Response{
		ProtoMajor:    1,
		ProtoMinor:    1,
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {"application/x-pem-file"}},
		Body:          io.NopCloser(bytes.NewReader(certPEM)),
		ContentLength: int64(len(certPEM)),
	}

	if err := resp.Write(conn); err != nil {
		log.Println("error writing CA certificate response:", err)
	}
}

func (s *ingressServer) handlePut(conn net.Conn, req *http.Request) {
	if req.URL.Path != "/egress" {
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusNotFound}).Write(conn); err != nil {
			log.Println("error writing not found response:", err)
		}

		return
	}

	var payload struct {
		Port     *int `json:"port,omitempty"`
		Internet *struct {
			Enabled *bool `json:"enabled,omitempty"`
		} `json:"internet,omitempty"`
		DNS *struct {
			AllowHostnames []string `json:"allowHostnames,omitempty"`
		} `json:"dns,omitempty"`
	}

	if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusBadRequest}).Write(conn); err != nil {
			log.Println("error writing bad put response:", err)
		}

		log.Println("error decoding egress configuration update:", err)
		return
	}

	if payload.Port == nil && payload.Internet == nil && payload.DNS == nil {
		if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusBadRequest}).Write(conn); err != nil {
			log.Println("error writing empty put response:", err)
		}

		log.Println("error updating egress configuration: empty payload")
		return
	}

	if payload.Port != nil {
		if err := s.egress.SetPort(*payload.Port); err != nil {
			if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusBadRequest}).Write(conn); err != nil {
				log.Println("error writing invalid port response:", err)
			}

			log.Println("error updating egress configuration:", err)
			return
		}

		log.Println("updated shared egress port to", *payload.Port)
	}

	if payload.Internet != nil {
		s.egress.SetInternetEnabled(payload.Internet.Enabled)
		log.Println("updated shared internet configuration")
	}

	if payload.DNS != nil {
		if err := s.egress.SetDNSConfig(payload.DNS.AllowHostnames); err != nil {
			if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusBadRequest}).Write(conn); err != nil {
				log.Println("error writing invalid dns response:", err)
			}

			log.Println("error updating dns configuration:", err)
			return
		}

		log.Println("updated shared dns configuration")
	}

	if err := (&http.Response{ProtoMajor: 1, ProtoMinor: 1, StatusCode: http.StatusNoContent}).Write(conn); err != nil {
		log.Println("error writing put success response:", err)
	}
}

type proxy struct {
	addr       *net.TCPAddr
	listener   net.Listener
	egressIP   net.IP
	egress     *egressConfiguration
	tlsFactory TLSServerFactory // nil when TLS interception is disabled
}

func newProxy(ctx context.Context, addr *net.TCPAddr, egressIP net.IP, egress *egressConfiguration, tlsFactory TLSServerFactory) *proxy {
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

	return &proxy{addr: addr, listener: listener, egressIP: egressIP, egress: egress, tlsFactory: tlsFactory}
}

func (p *proxy) gatewayAddr() net.Addr {
	return &net.TCPAddr{IP: append(net.IP(nil), p.egressIP...), Port: p.egress.Port()}
}

func (p *proxy) Close() error {
	return p.listener.Close()
}

// peekSNI peeks at the first bytes of a buffered connection. If they look
// like a TLS ClientHello, it parses and returns the SNI hostname. Returns
// empty string if the traffic is not TLS or SNI cannot be determined.
// Does not consume the bufio.Reader as it peeks.
func peekSNI(r *bufio.Reader) string {
	// Peek a single byte first so non-TLS connections aren't blocked
	// waiting for more bytes that may never arrive.
	first, err := r.Peek(1)
	if err != nil {
		return ""
	}

	if first[0] != 0x16 { // not a TLS handshake record
		return ""
	}

	// Now we know it looks like TLS. Read the rest of the record header.
	// TLS record header: content_type(1) + legacy_version(2) + length(2)
	const tlsRecordHeaderLen = 5

	header, err := r.Peek(tlsRecordHeaderLen)
	if err != nil {
		return ""
	}

	recordLen := int(header[3])<<8 | int(header[4])
	peekLen := min(r.Size(), tlsRecordHeaderLen+recordLen)
	record, err := r.Peek(peekLen)
	if err != nil {
		return ""
	}

	sni, err := extractSNI(record)
	if err != nil {
		return ""
	}

	return sni
}

const maxPeekedHTTPHeaderBytes = 128 * 1024

var errPeekedHTTPHeadersTooLarge = errors.New("peeked http headers exceed 128KiB")
var errNotHTTP = errors.New("not an http request")

func readHostname(r *bufio.Reader) (string, io.Reader, error) {
	var captured bytes.Buffer
	var chunk [4096]byte
	firstLineChecked := false

	for {
		remaining := maxPeekedHTTPHeaderBytes - captured.Len()
		if remaining <= 0 {
			replayReader := io.MultiReader(bytes.NewReader(captured.Bytes()), r)
			return "", replayReader, errPeekedHTTPHeadersTooLarge
		}

		readSize := len(chunk)
		readSize = min(remaining, readSize)
		n, err := r.Read(chunk[:readSize])
		if err != nil {
			replayReader := io.MultiReader(bytes.NewReader(captured.Bytes()), r)
			return "", replayReader, err
		}

		captured.Write(chunk[:n])
		capturedBytes := captured.Bytes()

		if !firstLineChecked {
			if !looksLikeHTTPRequestPrefix(capturedBytes) {
				replayReader := io.MultiReader(bytes.NewReader(capturedBytes), r)
				return "", replayReader, errNotHTTP
			}

			if bytes.Contains(capturedBytes, []byte("\r\n")) {
				firstLineChecked = true
			}
		}

		if bytes.Contains(capturedBytes, []byte("\r\n\r\n")) {
			break
		}
	}

	capturedBytes := captured.Bytes()
	replayReader := io.MultiReader(bytes.NewReader(capturedBytes), r)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(capturedBytes)))
	if err != nil {
		return "", replayReader, err
	}

	return req.Host, replayReader, nil
}

func looksLikeHTTPRequestLine(line []byte) bool {
	for _, method := range [...]string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	} {
		if bytes.HasPrefix(line, []byte(method+" ")) {
			return true
		}
	}

	return false
}

func looksLikeHTTPRequestPrefix(prefix []byte) bool {
	for _, method := range [...]string{
		http.MethodGet,
		http.MethodHead,
		http.MethodPost,
		http.MethodPut,
		http.MethodPatch,
		http.MethodDelete,
		http.MethodConnect,
		http.MethodOptions,
		http.MethodTrace,
	} {
		methodPrefix := []byte(method + " ")
		if len(prefix) <= len(methodPrefix) {
			if bytes.HasPrefix(methodPrefix, prefix) {
				return true
			}
			continue
		}

		if bytes.HasPrefix(prefix, methodPrefix) {
			return true
		}
	}

	return false
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

				var sni string
				var hostname string
				containerBuf := bufio.NewReaderSize(containerConnection, 4096)
				var containerReader io.Reader = containerConnection
				if p.tlsFactory != nil {
					containerReader = containerBuf
					sni = peekSNI(containerBuf)
				}

				if sni == "" && dstAddr.Port == 80 {
					var hostnameErr error
					hostname, containerReader, hostnameErr = readHostname(containerBuf)
					if errors.Is(hostnameErr, errNotHTTP) {
						hostnameErr = nil
					}

					if hostnameErr != nil {
						log.Println("error: hostname extraction failed:", hostnameErr)
						rstTCPConnection(containerConnection)
						return
					}
				}

				originConnection, shouldDecryptTLS, err := dialHTTPConnect(
					ctx,
					dstAddr.Network(),
					dstAddr.String(),
					sourceAddr.String(),
					p.gatewayAddr(),
					sni,
					hostname,
				)
				if err != nil {
					if err := rstTCPConnection(containerConnection); err != nil {
						log.Println("error sending rst to connection:", err)
					}

					log.Println("error: connecting to origin:", err)
					return
				}

				// Build the container-side connection used for the pump.
				// Three cases: raw TCP, buffered TCP (peeked but passthrough),
				// or TLS-terminated (plaintext <> gateway).
				var containerRW closeReadWriter = containerConnection
				if shouldDecryptTLS && p.tlsFactory != nil {
					bc := &bufioNetConn{reader: containerBuf, closeReadWriter: containerConnection}
					tlsConn, err := p.tlsFactory.NewServer(bc)

					if err != nil {
						log.Println("error: TLS handshake with container:", err)
						if err := rstTCPConnection(containerConnection); err != nil {
							log.Println("error sending rst to connection:", err)
						}

						originConnection.Close()
						return
					}

					// it's a buffered tlsConn
					containerRW = &tlsCloseConn{Conn: tlsConn, onCloseRead: containerConnection.CloseRead}
				} else if containerBuf != nil {
					containerRW = &bufioNetConn{
						closeReadWriter: containerConnection,
						reader:          containerReader,
					}
				}

				// container -> gateway
				wg.Go(func() {
					defer containerRW.CloseRead()
					defer originConnection.CloseWrite()
					io.Copy(originConnection, containerRW)
				})

				// gateway -> container
				wg.Go(func() {
					defer originConnection.CloseRead()
					defer containerRW.CloseWrite()
					io.Copy(containerRW, originConnection)
				})
			})
		}
	})

}

func networkDeviceCIDRs() (ipv4 []string, ipv6 []string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("listing network interfaces: %w", err)
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			cidr := addr.String() // already in CIDR notation (e.g. "10.0.0.1/24")
			ip, _, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if ip.To4() != nil {
				ipv4 = append(ipv4, cidr)
			} else {
				ipv6 = append(ipv6, cidr)
			}
		}
	}

	return ipv4, ipv6, nil
}

func entrypoint(ctx context.Context) {
	flag.Parse()

	dockerGatewayIP, err := lookupDockerIPv4(ctx)
	if err != nil {
		fatal(err)
	}

	var gatewayIPResolved net.IP = nil
	if *gatewayIP != "" {
		gatewayIPResolved = net.ParseIP(*gatewayIP)
	}

	egressIP := dockerGatewayIP
	if gatewayIPResolved != nil {
		egressIP = gatewayIPResolved
	}

	var tlsFactory TLSServerFactory
	if *tlsIntercept {
		if err := createCA("/ca/ca.crt", "/ca/ca.key"); err != nil {
			fatal(fmt.Errorf("creating TLS intercept CA: %w", err))
		}

		certPEM, err := os.ReadFile("/ca/ca.crt")
		if err != nil {
			fatal(fmt.Errorf("reading CA cert: %w", err))
		}

		keyPEM, err := os.ReadFile("/ca/ca.key")
		if err != nil {
			fatal(fmt.Errorf("reading CA key: %w", err))
		}

		factory, err := NewTLSInterceptor(certPEM, keyPEM)
		if err != nil {
			fatal(fmt.Errorf("creating TLS interceptor: %w", err))
		}

		tlsFactory = factory
		log.Println("TLS interception enabled, CA written to /ca/ca.crt")
	}

	egressConfig, err := newEgressConfiguration(*egressPort)
	if err != nil {
		fatal(err)
	}

	var ingressServer *ingressServer
	var ingressAddressTCP *net.TCPAddr
	if *ingressAddress != "" {
		ingressAddressTCP, err = net.ResolveTCPAddr("tcp", *ingressAddress)
		if err != nil {
			fatal(fmt.Errorf("resolving ingress tcp addr: %w", err))
		}

		ingressServer = newIngressServer(ingressAddressTCP, egressConfig)
	}

	_, dockerNetwork, err := net.ParseCIDR(*dockerGatewayCidr)
	if err != nil {
		fatal(err)
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
		newProxy(ctx, proxyAnythingAddressTCP, egressIP, egressConfig, tlsFactory),
	}

	if !*disableIPv6 {
		proxies = append(proxies,
			newProxy(ctx, proxyAnythingAddressV6TCP, egressIP, egressConfig, tlsFactory))
	}

	var dnsProxyV4 *dnsProxy
	if *dnsEnabled {
		dnsAddr, err := net.ResolveUDPAddr("udp4", *dnsProxyAddress)
		if err != nil {
			fatal(fmt.Errorf("resolving dns addr: %w", err))
		}

		dnsProxyV4 = newDNSProxy(ctx, dnsAddr, egressConfig)
	}

	var dnsProxyV6 *dnsProxy
	if *dnsEnabled && !*disableIPv6 {
		dnsAddr, err := net.ResolveUDPAddr("udp6", *dnsProxyV6Address)
		if err != nil {
			fatal(fmt.Errorf("resolving dns v6 addr: %w", err))
		}

		dnsProxyV6 = newDNSProxy(ctx, dnsAddr, egressConfig)
	}

	fmt.Printf("Proxy address: %s, Port: %d\n", proxyAnythingAddressTCP.IP.String(), proxyAnythingAddressTCP.Port)

	cleanupIptables(ctx)

	deviceCIDRsV4, deviceCIDRsV6, err := networkDeviceCIDRs()
	if err != nil {
		fatal(err)
	}

	type ipTablesSetup struct {
		ipTablesCmd     string
		ipVersion       string
		ignoreAddresses []string
		proxy           *proxy
		dnsProxy        *dnsProxy
	}

	ipv4Ignored := []string{"127.0.0.1/8", dockerNetwork.String(), egressIP.String() + "/24"}
	ipv4Ignored = append(ipv4Ignored, deviceCIDRsV4...)

	ipv6Ignored := []string{"::1/128"}
	ipv6Ignored = append(ipv6Ignored, deviceCIDRsV6...)

	ipTablesSetupList := []ipTablesSetup{
		{
			ipTablesCmd:     "iptables",
			ipVersion:       "-4",
			ignoreAddresses: ipv4Ignored,
			proxy:           proxies[0],
			dnsProxy:        dnsProxyV4,
		},
	}

	if !*disableIPv6 {
		ipTablesSetupList = append(ipTablesSetupList, ipTablesSetup{
			ipTablesCmd:     "ip6tables",
			ipVersion:       "-6",
			ignoreAddresses: ipv6Ignored,
			proxy:           proxies[1],
			dnsProxy:        dnsProxyV6,
		})
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

		// Do not re-mark reply traffic for inbound connections accepted by a local socket.
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespace, "-p", "tcp", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN")

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

		if iptablesSetup.dnsProxy == nil {
			continue
		}

		mustRunCommand(ctx, iptables, "-t", "mangle", "-N", iptablesNamespaceDNSTproxy)
		mustRunCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceDNSTproxy)
		for _, cidrToIgnore := range iptablesSetup.ignoreAddresses {
			mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNSTproxy, "-d", cidrToIgnore, "-j", "RETURN")
		}
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNSTproxy, "-m", "mark", "-p", "udp", "--mark", strconv.Itoa(dnsBypassMark), "-j", "RETURN")
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNSTproxy, "-p", "udp", "--dport", "53", "-j", "TPROXY", "--tproxy-mark", "0x1/0x1", "--on-port",
			strconv.Itoa(iptablesSetup.dnsProxy.addr.Port), "--on-ip", iptablesSetup.dnsProxy.addr.IP.String())
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "PREROUTING", "-p", "udp", "--dport", "53", "-j", iptablesNamespaceDNSTproxy)

		mustRunCommand(ctx, iptables, "-t", "mangle", "-N", iptablesNamespaceDNS)
		mustRunCommand(ctx, iptables, "-t", "mangle", "-F", iptablesNamespaceDNS)
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNS, "-p", "udp", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN")
		for _, cidrToIgnore := range iptablesSetup.ignoreAddresses {
			mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNS, "-d", cidrToIgnore, "-j", "RETURN")
		}
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNS, "-m", "mark", "-p", "udp", "--mark", strconv.Itoa(dnsBypassMark), "-j", "RETURN")
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", iptablesNamespaceDNS, "-p", "udp", "--dport", "53", "-j", "MARK", "--set-mark", "1")
		mustRunCommand(ctx, iptables, "-t", "mangle", "-A", "OUTPUT", "-p", "udp", "--dport", "53", "-j", iptablesNamespaceDNS)
		mustRunCommand(ctx, "ip", iptablesSetup.ipVersion, "route", "flush", "cache")
	}

	wg := &sync.WaitGroup{}
	for _, proxy := range proxies {
		defer proxy.Close()
	}
	if dnsProxyV4 != nil {
		defer dnsProxyV4.Close()
	}
	if dnsProxyV6 != nil {
		defer dnsProxyV6.Close()
	}
	if ingressServer != nil {
		defer ingressServer.Close()
	}

	defer wg.Wait()
	for _, proxy := range proxies {
		proxy.run(ctx, wg)
	}
	if dnsProxyV4 != nil {
		dnsProxyV4.run(ctx, wg)
	}
	if dnsProxyV6 != nil {
		dnsProxyV6.run(ctx, wg)
	}

	if ingressServer != nil {
		ingressServer.run(ctx, wg)
		log.Printf("Ingress listener accepting CONNECT on %s using shared egress configuration", ingressAddressTCP.String())
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
