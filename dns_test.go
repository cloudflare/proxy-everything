package main

import (
	"bytes"
	"errors"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestDNSProxyRetainsUpstreamResponses(t *testing.T) {
	for _, rcode := range []int{dns.RcodeSuccess, dns.RcodeServerFailure} {
		t.Run(dns.RcodeToString[rcode], func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			listen := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
				var socketError error
				err := raw.Control(func(fd uintptr) {
					socketError = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
				})
				return errors.Join(err, socketError)
			}}
			resolver, err := listen.ListenPacket(t.Context(), "udp4", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer resolver.Close()
			if err := resolver.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			request := new(dns.Msg).SetQuestion("backups.sandbox.internal.", dns.TypeA)
			payload, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}
			response := new(dns.Msg).SetRcode(request, rcode)
			if rcode == dns.RcodeSuccess {
				response.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IPv4(192, 0, 2, 42),
				}}
			}
			expected, err := response.Pack()
			if err != nil {
				t.Fatal(err)
			}
			upstreamDone := make(chan error, 1)
			go func() {
				buffer := make([]byte, 512)
				_, address, err := resolver.ReadFrom(buffer)
				if err == nil {
					_, err = resolver.WriteTo(expected, address)
				}
				upstreamDone <- err
			}()
			config, err := newEgressConfiguration(80)
			if err != nil {
				t.Fatal(err)
			}
			proxy := &dnsProxy{config: config}
			proxy.handlePacket(t.Context(), client.LocalAddr().(*net.UDPAddr), resolver.LocalAddr().(*net.UDPAddr), payload)
			if err := <-upstreamDone; err != nil {
				t.Fatal(err)
			}
			if err := client.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 512)
			n, _, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(buffer[:n], expected) {
				t.Fatalf("upstream response changed: got %x, want %x", buffer[:n], expected)
			}
		})
	}
}

func TestDNSProxyUnavailableResolver(t *testing.T) {
	for _, test := range []struct {
		name     string
		patterns []string
		answer   bool
	}{
		{"intercepted hostname", []string{"backups.sandbox.internal"}, true},
		{"wildcard mapping", []string{"*"}, true},
		{"unmatched hostname", []string{"another.internal"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			resolver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			resolverAddress := resolver.LocalAddr().(*net.UDPAddr)
			if err := resolver.Close(); err != nil {
				t.Fatal(err)
			}

			config, err := newEgressConfiguration(80)
			if err != nil {
				t.Fatal(err)
			}
			if err := config.SetDNSConfig(test.patterns); err != nil {
				t.Fatal(err)
			}
			request := new(dns.Msg).SetQuestion("backups.sandbox.internal.", dns.TypeA)
			payload, err := request.Pack()
			if err != nil {
				t.Fatal(err)
			}
			proxy := &dnsProxy{config: config}
			proxy.handlePacket(t.Context(), client.LocalAddr().(*net.UDPAddr), resolverAddress, payload)

			buffer := make([]byte, 512)
			if !test.answer {
				raw, err := client.SyscallConn()
				if err != nil {
					t.Fatal(err)
				}
				var n int
				var receiveError error
				if err := raw.Control(func(fd uintptr) {
					n, _, receiveError = syscall.Recvfrom(int(fd), buffer, syscall.MSG_DONTWAIT)
				}); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(receiveError, syscall.EAGAIN) {
					t.Fatalf("unmatched query received a reply: bytes=%d error=%v", n, receiveError)
				}
				return
			}
			if err := client.SetReadDeadline(time.Now().Add(dnsUpstreamTimeout)); err != nil {
				t.Fatal(err)
			}
			n, _, err := client.ReadFromUDP(buffer)
			if err != nil {
				t.Fatalf("intercepted query received no fallback: %v", err)
			}
			response := new(dns.Msg)
			if err := response.Unpack(buffer[:n]); err != nil {
				t.Fatal(err)
			}
			if response.Id != request.Id || response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
				t.Fatalf("unexpected fallback: %s", response)
			}
			answer, ok := response.Answer[0].(*dns.A)
			if !ok || !answer.A.Equal(net.IPv4(11, 0, 0, 1)) {
				t.Fatalf("unexpected fallback address: %s", response)
			}
		})
	}
}
