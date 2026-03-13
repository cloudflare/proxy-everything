package main

import (
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"path"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

const dnsBypassMark = 100
const ipv6RecvOrigDstAddr = 74
const dnsUpstreamTimeout = 5 * time.Second

var dnsAllowedIPv4 = net.IPv4(11, 0, 0, 1).To4()
var dnsAllowedIPv6 = net.ParseIP("fd00::1")

var dnsEnabled = flag.Bool("dns-enabled", false, "enable UDP DNS interception")
var dnsProxyAddress = flag.String("dns-address", "127.0.0.9:5000", "address where the UDP DNS TPROXY listener will accept IPv4 port 53 traffic")
var dnsProxyV6Address = flag.String("dns-address-v6", "[::1]:50009", "address where the UDP DNS TPROXY listener will accept IPv6 port 53 traffic")

func normalizeDNSAllowPatterns(hostnames []string) []string {
	patterns := make([]string, 0, len(hostnames))
	for _, pattern := range hostnames {
		pattern = strings.ToLower(strings.TrimSpace(strings.TrimSuffix(pattern, ".")))
		if pattern == "" {
			continue
		}

		patterns = append(patterns, pattern)
	}

	return patterns
}

func dnsAllowedByPatterns(patterns []string, question dns.Question) bool {
	name := strings.ToLower(strings.TrimSuffix(question.Name, "."))
	for _, pattern := range patterns {
		if pattern == "*" || pattern == name {
			return true
		}

		matched, err := path.Match(pattern, name)
		if err != nil {
			log.Println("error matching dns allow pattern:", err)
			continue
		}

		if matched {
			return true
		}
	}

	return false
}

type dnsProxy struct {
	addr   *net.UDPAddr
	conn   *net.UDPConn
	config *egressConfiguration
}

func newDNSProxy(ctx context.Context, addr *net.UDPAddr, config *egressConfiguration) *dnsProxy {
	if addr == nil || addr.IP == nil {
		fatal(errors.New("dns proxy address must be a literal IP:port"))
	}

	listenConfig := net.ListenConfig{
		Control: func(network string, address string, conn syscall.RawConn) error {
			var controlErr error
			if err := conn.Control(func(fd uintptr) {
				controlErr = setTransparentSocketOptions(int(fd), addr.IP.To4() == nil, true)
			}); err != nil {
				return err
			}

			return controlErr
		},
	}

	packetConn, err := listenConfig.ListenPacket(ctx, udpNetworkForIP(addr.IP), addr.String())
	if err != nil {
		fatal(fmt.Errorf("couldn't listen on dns address %s: %w", addr.String(), err))
	}

	udpConn, ok := packetConn.(*net.UDPConn)
	if !ok {
		packetConn.Close()
		fatal(fmt.Errorf("unexpected dns listener type %T", packetConn))
	}

	return &dnsProxy{addr: cloneUDPAddr(addr), conn: udpConn, config: config}
}

func (p *dnsProxy) Close() error {
	return p.conn.Close()
}

func (p *dnsProxy) run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Go(func() {
		packetBuffer := make([]byte, 64*1024)
		oobBuffer := make([]byte, 512)

		for {
			n, oobn, _, sourceAddr, err := p.conn.ReadMsgUDP(packetBuffer, oobBuffer)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}

				log.Println("error reading dns packet:", err)
				return
			}

			originalDst, err := originalDestinationFromOOB(oobBuffer[:oobn])
			if err != nil {
				log.Println("error reading original dns destination:", err)
				continue
			}

			payload := append([]byte(nil), packetBuffer[:n]...)
			source := cloneUDPAddr(sourceAddr)
			destination := cloneUDPAddr(originalDst)
			wg.Go(func() {
				p.handlePacket(ctx, source, destination, payload)
			})
		}
	})
}

func (p *dnsProxy) handlePacket(ctx context.Context, sourceAddr *net.UDPAddr, originalDst *net.UDPAddr, payload []byte) {
	request := &dns.Msg{}
	if err := request.Unpack(payload); err != nil {
		log.Println("error unpacking dns query:", err)
		return
	}

	allowed := len(request.Question) > 0 && dnsAllowedByPatterns(p.config.DNSAllowPatterns(), request.Question[0])

	if p.config.InternetEnabled() {
		response, err := p.forwardToOriginal(ctx, originalDst, payload)
		if err != nil {
			log.Println("error dialing DNS:", err)
			return
		}

		rcode, rcodeErr := dnsResponseRcode(response)

		// If NXDOMAIN, but we should allow this domain, fake the response
		if rcodeErr == nil && rcode == dns.RcodeNameError && allowed {
			allowedResponse, packErr := dnsAllowedResponse(request)
			if packErr != nil {
				log.Println("error packing allowed nxdomain fallback response:", packErr)
				return
			}

			if err := p.replyToClient(ctx, sourceAddr, originalDst, allowedResponse); err != nil {
				log.Println("error replying allowed nxdomain fallback response:", err)
			}

			return
		}

		// Just reply to client with original response
		if err := p.replyToClient(ctx, sourceAddr, originalDst, response); err != nil {
			log.Println("error replying dns upstream response:", err)
		}

		return
	}

	// If not allowed, and internet disabled, just NXDOMAIN
	if !allowed {
		blockedResponse, packErr := dnsResponseWithRcode(request, dns.RcodeNameError).Pack()
		if packErr != nil {
			log.Println("error packing fallback nxdomain response:", packErr)
			return
		}

		if err := p.replyToClient(ctx, sourceAddr, originalDst, blockedResponse); err != nil {
			log.Println("error replying fallback nxdomain response:", err)
		}

		return
	}

	// Create response
	placeholderResponse, packErr := dnsAllowedResponse(request)
	if packErr != nil {
		log.Println("error packing allowed dns fallback response:", packErr)
		return
	}

	// reply to client
	if err := p.replyToClient(ctx, sourceAddr, originalDst, placeholderResponse); err != nil {
		log.Println("error replying allowed dns fallback response:", err)
	}
}

func (p *dnsProxy) forwardToOriginal(ctx context.Context, originalDst *net.UDPAddr, payload []byte) ([]byte, error) {
	dialer := net.Dialer{
		Timeout: dnsUpstreamTimeout,
		Control: func(network string, address string, conn syscall.RawConn) error {
			var controlErr error
			if err := conn.Control(func(fd uintptr) {
				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, dnsBypassMark)
			}); err != nil {
				return err
			}

			return controlErr
		},
	}

	conn, err := dialer.DialContext(ctx, udpNetworkForIP(originalDst.IP), originalDst.String())
	if err != nil {
		return nil, fmt.Errorf("dialing original dns resolver %s: %w", originalDst.String(), err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
		return nil, fmt.Errorf("setting dns upstream deadline: %w", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return nil, fmt.Errorf("writing dns query upstream: %w", err)
	}

	responseBuffer := make([]byte, 64*1024)
	n, err := conn.Read(responseBuffer)
	if err != nil {
		return nil, fmt.Errorf("reading dns response upstream: %w", err)
	}

	return append([]byte(nil), responseBuffer[:n]...), nil
}

func (p *dnsProxy) replyToClient(ctx context.Context, sourceAddr *net.UDPAddr, originalDst *net.UDPAddr, payload []byte) error {
	dialer := net.Dialer{
		LocalAddr: cloneUDPAddr(originalDst),
		Timeout:   dnsUpstreamTimeout,
		Control: func(network string, address string, conn syscall.RawConn) error {
			var controlErr error
			if err := conn.Control(func(fd uintptr) {
				controlErr = setTransparentSocketOptions(int(fd), originalDst.IP.To4() == nil, false)
				if controlErr != nil {
					return
				}

				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				if controlErr != nil {
					return
				}

				controlErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, dnsBypassMark)
			}); err != nil {
				return err
			}

			return controlErr
		},
	}

	conn, err := dialer.DialContext(ctx, udpNetworkForIP(originalDst.IP), sourceAddr.String())
	if err != nil {
		return fmt.Errorf("dialing dns client %s from %s: %w", sourceAddr.String(), originalDst.String(), err)
	}
	defer conn.Close()

	if err := conn.SetWriteDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
		return fmt.Errorf("setting dns reply deadline: %w", err)
	}

	if _, err := conn.Write(payload); err != nil {
		return fmt.Errorf("writing dns reply to client: %w", err)
	}

	return nil
}

func dnsResponseWithRcode(request *dns.Msg, rcode int) *dns.Msg {
	response := new(dns.Msg)
	response.SetRcode(request, rcode)
	response.RecursionAvailable = false
	response.Compress = false
	return response
}

func dnsAllowedResponse(request *dns.Msg) ([]byte, error) {
	response := new(dns.Msg)
	response.SetReply(request)
	response.RecursionAvailable = false
	response.Authoritative = true
	response.Compress = false

	for _, question := range request.Question {
		header := dns.RR_Header{Name: question.Name, Class: question.Qclass, Ttl: 60}

		switch question.Qtype {
		case dns.TypeA:
			response.Answer = append(response.Answer, &dns.A{
				Hdr: headerWithType(header, dns.TypeA),
				A:   append(net.IP(nil), dnsAllowedIPv4...),
			})
		case dns.TypeAAAA:
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr:  headerWithType(header, dns.TypeAAAA),
				AAAA: append(net.IP(nil), dnsAllowedIPv6...),
			})
		case dns.TypeANY:
			response.Answer = append(response.Answer,
				&dns.A{Hdr: headerWithType(header, dns.TypeA), A: append(net.IP(nil), dnsAllowedIPv4...)},
				&dns.AAAA{Hdr: headerWithType(header, dns.TypeAAAA), AAAA: append(net.IP(nil), dnsAllowedIPv6...)},
			)
		}
	}

	return response.Pack()
}

func dnsResponseRcode(payload []byte) (int, error) {
	response := &dns.Msg{}
	if err := response.Unpack(payload); err != nil {
		return 0, err
	}

	return response.Rcode, nil
}

func headerWithType(header dns.RR_Header, rrType uint16) dns.RR_Header {
	header.Rrtype = rrType
	return header
}

func setTransparentSocketOptions(fd int, isIPv6 bool, receiveOriginalDst bool) error {
	if err := syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_TRANSPARENT, 1); err != nil {
		return err
	}

	if !receiveOriginalDst {
		return nil
	}

	if isIPv6 {
		return syscall.SetsockoptInt(fd, syscall.SOL_IPV6, ipv6RecvOrigDstAddr, 1)
	}

	return syscall.SetsockoptInt(fd, syscall.SOL_IP, syscall.IP_RECVORIGDSTADDR, 1)
}

func originalDestinationFromOOB(oob []byte) (*net.UDPAddr, error) {
	controlMessages, err := syscall.ParseSocketControlMessage(oob)
	if err != nil {
		return nil, err
	}

	for _, message := range controlMessages {
		switch {
		case message.Header.Level == syscall.SOL_IP && message.Header.Type == syscall.IP_RECVORIGDSTADDR:
			return udpAddrFromIPv4OriginalDst(message.Data)
		case message.Header.Level == syscall.SOL_IPV6 && message.Header.Type == ipv6RecvOrigDstAddr:
			return udpAddrFromIPv6OriginalDst(message.Data)
		}
	}

	return nil, errors.New("missing original destination control message")
}

func udpAddrFromIPv4OriginalDst(data []byte) (*net.UDPAddr, error) {
	if len(data) < syscall.SizeofSockaddrInet4 {
		return nil, errors.New("short ipv4 original destination payload")
	}

	return &net.UDPAddr{
		IP:   net.IPv4(data[4], data[5], data[6], data[7]).To4(),
		Port: int(binary.BigEndian.Uint16(data[2:4])),
	}, nil
}

func udpAddrFromIPv6OriginalDst(data []byte) (*net.UDPAddr, error) {
	if len(data) < syscall.SizeofSockaddrInet6 {
		return nil, errors.New("short ipv6 original destination payload")
	}

	zone := ""
	scopeID := binary.NativeEndian.Uint32(data[24:28])
	if scopeID != 0 {
		iface, err := net.InterfaceByIndex(int(scopeID))
		if err == nil {
			zone = iface.Name
		}
	}

	return &net.UDPAddr{
		IP:   append(net.IP(nil), data[8:24]...),
		Port: int(binary.BigEndian.Uint16(data[2:4])),
		Zone: zone,
	}, nil
}

func udpNetworkForIP(ip net.IP) string {
	if ip.To4() != nil {
		return "udp4"
	}

	return "udp6"
}

func cloneUDPAddr(addr *net.UDPAddr) *net.UDPAddr {
	if addr == nil {
		return nil
	}

	return &net.UDPAddr{IP: append(net.IP(nil), addr.IP...), Port: addr.Port, Zone: addr.Zone}
}
