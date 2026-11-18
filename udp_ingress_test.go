package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"syscall"
	"testing"
	"testing/iotest"
	"time"
)

func udpFrame(payload []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(payload))), payload...)
}

func TestReadUDPFrameAcrossSplitReads(t *testing.T) {
	payloads := [][]byte{{}, {0x7f}, bytes.Repeat([]byte{0x5a}, maxUDPPayloadSize)}

	var stream []byte
	for _, payload := range payloads {
		stream = append(stream, udpFrame(payload)...)
	}

	// One byte per read cuts every frame between its two length bytes and inside its payload.
	reader := iotest.OneByteReader(bytes.NewReader(stream))
	buffer := make([]byte, maxUDPFrameSize)

	for i, want := range payloads {
		payload, err := readUDPFrame(reader, buffer)
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}

		if !bytes.Equal(payload, want) {
			t.Errorf("frame %d = %d bytes, want %d", i, len(payload), len(want))
		}
	}

	if _, err := readUDPFrame(reader, buffer); err != io.EOF {
		t.Errorf("read after last frame = %v, want io.EOF", err)
	}
}

func TestReadUDPFrameAssemblesPiecesWrittenSeparately(t *testing.T) {
	frame := udpFrame([]byte("hello"))
	pieces := [][]byte{frame[:1], frame[1:5], frame[5:]}

	pipeReader, pipeWriter := io.Pipe()
	defer pipeReader.Close()

	// io.Pipe hands each write to the reader before the next one starts.
	go func() {
		for _, piece := range pieces {
			if _, err := pipeWriter.Write(piece); err != nil {
				return
			}
		}

		pipeWriter.Close()
	}()

	buffer := make([]byte, maxUDPFrameSize)
	payload, err := readUDPFrame(pipeReader, buffer)
	if err != nil || string(payload) != "hello" {
		t.Fatalf("readUDPFrame = %q, %v, want hello", payload, err)
	}

	if _, err := readUDPFrame(pipeReader, buffer); err != io.EOF {
		t.Errorf("read after the frame = %v, want io.EOF", err)
	}
}

// oversizedFrames returns a 1501-byte frame and a 0xFFFE-byte frame, the smallest and largest lengths
// that are skipped.
func oversizedFrames() []byte {
	var stream []byte
	for _, length := range []int{maxUDPPayloadSize + 1, 0xfffe} {
		stream = append(stream, udpFrame(bytes.Repeat([]byte{0xee}, length))...)
	}

	return stream
}

func TestReadUDPFrameSkipsOversizedFrames(t *testing.T) {
	stream := append(oversizedFrames(), udpFrame([]byte("next"))...)

	readers := map[string]io.Reader{
		"whole reads":    bytes.NewReader(stream),
		"one-byte reads": iotest.OneByteReader(bytes.NewReader(stream)),
	}

	for name, reader := range readers {
		t.Run(name, func(t *testing.T) {
			buffer := make([]byte, maxUDPFrameSize)

			payload, err := readUDPFrame(reader, buffer)
			if err != nil || string(payload) != "next" {
				t.Fatalf("readUDPFrame = %d bytes, %v, want the frame after the oversized ones", len(payload), err)
			}

			if _, err := readUDPFrame(reader, buffer); err != io.EOF {
				t.Errorf("read after the last frame = %v, want io.EOF", err)
			}
		})
	}
}

func TestReadUDPFrameRejectsFlowEnd(t *testing.T) {
	stream := []byte{0xff, 0xff, 0x00}
	if _, err := readUDPFrame(bytes.NewReader(stream), make([]byte, maxUDPFrameSize)); !errors.Is(err, errUDPFlowEndTowardContainer) {
		t.Errorf("FLOW_END frame = %v, want errUDPFlowEndTowardContainer", err)
	}
}

func TestReadUDPFrameReportsTruncatedFrames(t *testing.T) {
	complete := udpFrame([]byte("payload"))
	for cut := 1; cut < len(complete); cut++ {
		if _, err := readUDPFrame(bytes.NewReader(complete[:cut]), make([]byte, maxUDPFrameSize)); err != io.ErrUnexpectedEOF {
			t.Errorf("frame cut at %d bytes = %v, want io.ErrUnexpectedEOF", cut, err)
		}
	}

	skipped := oversizedFrames()[:udpFrameHeaderSize+10]
	if _, err := readUDPFrame(bytes.NewReader(skipped), make([]byte, maxUDPFrameSize)); err != io.ErrUnexpectedEOF {
		t.Errorf("oversized frame cut short = %v, want io.ErrUnexpectedEOF", err)
	}

	if _, err := readUDPFrame(bytes.NewReader(nil), make([]byte, maxUDPFrameSize)); err != io.EOF {
		t.Errorf("empty stream = %v, want io.EOF", err)
	}
}

// testTimeout bounds every blocking step so a broken relay fails the test instead of hanging it.
const testTimeout = 5 * time.Second

var loopbackIPv4 = net.IPv4(127, 0, 0, 1)

func waitForHandler(t *testing.T, done <-chan struct{}) {
	t.Helper()

	select {
	case <-done:
	case <-time.After(testTimeout):
		t.Fatal("ingress handler did not return")
	}
}

// startIngressConnection serves one client connection with the ingress handler. Cleanup cancels the
// handler context and asserts the handler returns.
func startIngressConnection(t *testing.T) (*net.TCPConn, <-chan struct{}) {
	t.Helper()

	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer listener.Close()

	client, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	server, err := listener.Accept()
	if err != nil {
		client.Close()
		t.Fatal(err)
	}

	if err := client.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		client.Close()
		server.Close()
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		(&ingressServer{}).handleConn(ctx, server)
	}()

	t.Cleanup(func() {
		cancel()
		client.Close()
		waitForHandler(t, done)
	})

	return client.(*net.TCPConn), done
}

func setUDPDeadline(t *testing.T, conn *net.UDPConn) {
	t.Helper()

	t.Cleanup(func() { conn.Close() })

	if err := conn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}
}

func listenApplicationUDP(t *testing.T) *net.UDPConn {
	t.Helper()

	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopbackIPv4})
	if err != nil {
		t.Fatal(err)
	}

	setUDPDeadline(t, conn)
	return conn
}

func dialUDP(t *testing.T, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) *net.UDPConn {
	t.Helper()

	conn, err := net.DialUDP("udp4", localAddr, remoteAddr)
	if err != nil {
		t.Fatal(err)
	}

	setUDPDeadline(t, conn)
	return conn
}

// connectUDPSocket points an existing UDP socket at a new peer without changing its local port.
func connectUDPSocket(t *testing.T, conn *net.UDPConn, peer *net.UDPAddr) {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	var connectErr error
	err = rawConn.Control(func(fd uintptr) {
		connectErr = syscall.Connect(int(fd), &syscall.SockaddrInet4{Port: peer.Port, Addr: [4]byte(peer.IP.To4())})
	})

	if err != nil || connectErr != nil {
		t.Fatalf("connecting udp socket: %v, %v", err, connectErr)
	}
}

// waitForPendingSocketError blocks until conn has a pending socket error, without consuming it.
// select reports a pending error as readable, and nothing else sends to conn.
func waitForPendingSocketError(t *testing.T, conn *net.UDPConn) {
	t.Helper()

	rawConn, err := conn.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}

	var ready int
	var selectErr error
	err = rawConn.Control(func(fd uintptr) {
		timeout := syscall.NsecToTimeval(testTimeout.Nanoseconds())
		for {
			var readable syscall.FdSet
			readable.Bits[fd/64] |= 1 << (fd % 64)

			ready, selectErr = syscall.Select(int(fd)+1, &readable, nil, nil, &timeout)
			if selectErr != syscall.EINTR {
				return
			}
		}
	})

	if err != nil || selectErr != nil || ready != 1 {
		t.Fatalf("waiting for icmp port unreachable: ready %d, %v, %v", ready, err, selectErr)
	}
}

// portUnreachablePair returns a flow socket with an ICMP port unreachable pending, and the target socket
// it is connected to, now connected back to the flow socket. The target port is never freed: while the
// target is connected elsewhere, no socket accepts datagrams from the flow socket.
func portUnreachablePair(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()

	elsewhere := listenApplicationUDP(t)
	target := dialUDP(t, &net.UDPAddr{IP: loopbackIPv4}, elsewhere.LocalAddr().(*net.UDPAddr))
	flow := dialUDP(t, nil, target.LocalAddr().(*net.UDPAddr))

	if _, err := flow.Write([]byte("unreachable")); err != nil {
		t.Fatal(err)
	}

	waitForPendingSocketError(t, flow)
	connectUDPSocket(t, target, flow.LocalAddr().(*net.UDPAddr))
	return flow, target
}

// connectRequest builds the ingress CONNECT that workerd sends; an empty protocol omits X-Dst-Protocol.
func connectRequest(dstAddr string, protocol string) string {
	request := "CONNECT " + dstAddr + " HTTP/1.1\r\nHost: " + dstAddr + "\r\nX-Dst-Addr: " + dstAddr + "\r\n"
	if protocol != "" {
		request += "X-Dst-Protocol: " + protocol + "\r\n"
	}

	return request + "\r\n"
}

func readResponseHead(t *testing.T, reader *bufio.Reader) string {
	t.Helper()

	var head bytes.Buffer
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}

		head.WriteString(line)
		if line == "\r\n" {
			return head.String()
		}
	}
}

// openUDPFlow writes the request head and earlyData in one write, before the response arrives, and
// checks the 200 response.
func openUDPFlow(t *testing.T, client net.Conn, application *net.UDPConn, earlyData []byte) *bufio.Reader {
	t.Helper()

	request := append([]byte(connectRequest(application.LocalAddr().String(), "udp")), earlyData...)
	if _, err := client.Write(request); err != nil {
		t.Fatal(err)
	}

	reader := bufio.NewReader(client)
	response, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatal(err)
	}

	if response.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.StatusCode)
	}

	return reader
}

func writeFrames(t *testing.T, client net.Conn, frames ...[]byte) {
	t.Helper()

	if _, err := client.Write(bytes.Join(frames, nil)); err != nil {
		t.Fatal(err)
	}
}

func readDatagram(t *testing.T, reader *bufio.Reader) []byte {
	t.Helper()

	payload, err := readUDPFrame(reader, make([]byte, maxUDPFrameSize))
	if err != nil {
		t.Fatal(err)
	}

	return payload
}

func receiveFromFlow(t *testing.T, application *net.UDPConn) ([]byte, *net.UDPAddr) {
	t.Helper()

	buffer := make([]byte, 64*1024)
	n, peer, err := application.ReadFromUDP(buffer)
	if err != nil {
		t.Fatal(err)
	}

	return buffer[:n], peer
}

func sendToFlow(t *testing.T, application *net.UDPConn, peer *net.UDPAddr, payload []byte) {
	t.Helper()

	if _, err := application.WriteToUDP(payload, peer); err != nil {
		t.Fatal(err)
	}
}

func TestIngressUDPConnectAnswersExactlyLikeTCPConnect(t *testing.T) {
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	defer origin.Close()

	if err := origin.(*net.TCPListener).SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}

	tcpClient, _ := startIngressConnection(t)
	if _, err := io.WriteString(tcpClient, connectRequest(origin.Addr().String(), "")); err != nil {
		t.Fatal(err)
	}

	tcpHead := readResponseHead(t, bufio.NewReader(tcpClient))

	// The handler dials before it answers, so the origin connection is already queued.
	originConn, err := origin.Accept()
	if err != nil {
		t.Fatal(err)
	}

	defer originConn.Close()

	if err := originConn.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}

	if _, err := io.WriteString(tcpClient, "ping"); err != nil {
		t.Fatal(err)
	}

	received := make([]byte, len("ping"))
	if _, err := io.ReadFull(originConn, received); err != nil || string(received) != "ping" {
		t.Fatalf("tcp origin received %q, %v, want ping", received, err)
	}

	application := listenApplicationUDP(t)
	udpClient, _ := startIngressConnection(t)
	if _, err := io.WriteString(udpClient, connectRequest(application.LocalAddr().String(), "udp")); err != nil {
		t.Fatal(err)
	}

	udpHead := readResponseHead(t, bufio.NewReader(udpClient))

	if !strings.HasPrefix(tcpHead, "HTTP/1.1 200 ") {
		t.Fatalf("tcp response head = %q, want 200", tcpHead)
	}

	if udpHead != tcpHead {
		t.Fatalf("udp response head = %q, want the tcp head %q", udpHead, tcpHead)
	}
}

func TestIngressConnectRejectsInvalidRequests(t *testing.T) {
	cases := map[string]string{
		"missing destination": "CONNECT 127.0.0.1:53 HTTP/1.1\r\nHost: 127.0.0.1:53\r\nX-Dst-Protocol: udp\r\n\r\n",
		"hostname target":     connectRequest("localhost:53", "udp"),
		"missing port":        connectRequest("127.0.0.1", "udp"),
		"ipv6 udp target":     connectRequest("[::1]:53", "udp"),
		"unknown protocol":    connectRequest("127.0.0.1:53", "sctp"),
		"uppercase protocol":  connectRequest("127.0.0.1:53", "UDP"),
		"explicit tcp":        connectRequest("127.0.0.1:53", "tcp"),
	}

	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			client, done := startIngressConnection(t)

			if _, err := io.WriteString(client, request); err != nil {
				t.Fatal(err)
			}

			response, err := http.ReadResponse(bufio.NewReader(client), nil)
			if err != nil {
				t.Fatal(err)
			}

			if response.StatusCode != http.StatusBadRequest {
				t.Errorf("status = %d, want 400", response.StatusCode)
			}

			waitForHandler(t, done)
		})
	}
}

func TestIngressUDPRoundTripsDatagrams(t *testing.T) {
	application := listenApplicationUDP(t)
	client, _ := startIngressConnection(t)

	earlyData := append(udpFrame([]byte("early-1")), udpFrame([]byte("early-2"))...)
	reader := openUDPFlow(t, client, application, earlyData)

	received, peer := receiveFromFlow(t, application)
	if string(received) != "early-1" {
		t.Fatalf("application received %q, want the first early frame", received)
	}

	if received, _ := receiveFromFlow(t, application); string(received) != "early-2" {
		t.Fatalf("application received %q, want the second early frame", received)
	}

	split := udpFrame([]byte("split"))
	writeFrames(t, client, split[:1])
	writeFrames(t, client, split[1:])

	if received, _ := receiveFromFlow(t, application); string(received) != "split" {
		t.Fatalf("application received %q, want the frame written in two pieces", received)
	}

	for _, payload := range [][]byte{{}, {0x7f}, bytes.Repeat([]byte{0x5a}, maxUDPPayloadSize)} {
		writeFrames(t, client, udpFrame(payload))

		received, _ := receiveFromFlow(t, application)
		if !bytes.Equal(received, payload) {
			t.Fatalf("application received %d bytes, want %d", len(received), len(payload))
		}

		sendToFlow(t, application, peer, payload)

		if returned := readDatagram(t, reader); !bytes.Equal(returned, payload) {
			t.Fatalf("tunnel received %d bytes, want %d", len(returned), len(payload))
		}
	}
}

func TestIngressUDPDropsOversizedDatagramsFromApplication(t *testing.T) {
	application := listenApplicationUDP(t)
	client, _ := startIngressConnection(t)

	reader := openUDPFlow(t, client, application, udpFrame([]byte("hello")))
	_, peer := receiveFromFlow(t, application)

	sendToFlow(t, application, peer, make([]byte, maxUDPPayloadSize+1))
	sendToFlow(t, application, peer, make([]byte, 4000))
	sendToFlow(t, application, peer, []byte("after"))

	if returned := readDatagram(t, reader); string(returned) != "after" {
		t.Fatalf("tunnel received %d bytes, want the datagram after the oversized ones", len(returned))
	}
}

// The tunnel is never half-closed: EOF from the client closes the whole connection and the UDP socket.
func TestIngressUDPTunnelEOFEndsFlowAndClosesUDPSocket(t *testing.T) {
	application := listenApplicationUDP(t)
	client, done := startIngressConnection(t)

	reader := openUDPFlow(t, client, application, udpFrame([]byte("hello")))
	_, peer := receiveFromFlow(t, application)

	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}

	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("tunnel read after EOF = %v, want io.EOF", err)
	}

	waitForHandler(t, done)

	// A connected socket receives the ICMP port unreachable that proves the flow socket is closed.
	connectUDPSocket(t, application, peer)

	if _, err := application.Write([]byte("probe")); err != nil {
		t.Fatal(err)
	}

	if _, err := application.Read(make([]byte, 1)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("read after flow closed = %v, want ECONNREFUSED", err)
	}
}

func TestIngressUDPSkipsOversizedFramesFromTunnel(t *testing.T) {
	application := listenApplicationUDP(t)
	client, _ := startIngressConnection(t)

	openUDPFlow(t, client, application, nil)

	// Separate writes split the skipped frames inside a length and inside their payloads.
	frames := oversizedFrames()
	for _, piece := range [][]byte{frames[:1], frames[1:700], frames[700:40000], frames[40000:]} {
		writeFrames(t, client, piece)
	}

	writeFrames(t, client, udpFrame([]byte("next")))

	if received, _ := receiveFromFlow(t, application); string(received) != "next" {
		t.Fatalf("application received %d bytes, want the datagram after the oversized frames", len(received))
	}
}

func TestIngressUDPFlowEndTowardContainerEndsFlow(t *testing.T) {
	application := listenApplicationUDP(t)
	client, done := startIngressConnection(t)

	reader := openUDPFlow(t, client, application, nil)
	writeFrames(t, client, []byte{0xff, 0xff})

	if _, err := reader.ReadByte(); err != io.EOF {
		t.Fatalf("tunnel read after FLOW_END = %v, want io.EOF", err)
	}

	waitForHandler(t, done)
}

func TestRelayUDPToTunnelIgnoresPortUnreachable(t *testing.T) {
	flow, target := portUnreachablePair(t)

	tunnel, tunnelPeer := net.Pipe()
	defer tunnelPeer.Close()

	if err := tunnelPeer.SetDeadline(time.Now().Add(testTimeout)); err != nil {
		t.Fatal(err)
	}

	relayResult := make(chan error, 1)
	go func() {
		relayResult <- relayUDPToTunnel(flow, tunnel)
	}()

	if _, err := target.Write([]byte("after")); err != nil {
		t.Fatal(err)
	}

	if returned := readDatagram(t, bufio.NewReader(tunnelPeer)); string(returned) != "after" {
		t.Fatalf("tunnel received %q, want the datagram after the port unreachable", returned)
	}

	flow.Close()

	select {
	case err := <-relayResult:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("relay ended with %v, want net.ErrClosed", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("relay did not return after the udp socket closed")
	}
}

func TestRelayTunnelToUDPIgnoresPortUnreachable(t *testing.T) {
	flow, target := portUnreachablePair(t)

	frames := append(udpFrame([]byte("refused")), udpFrame([]byte("after"))...)

	if err := relayTunnelToUDP(bytes.NewReader(frames), flow); err != io.EOF {
		t.Fatalf("relay ended with %v, want io.EOF", err)
	}

	// The pending error fails the first write, so "refused" is normally not sent.
	buffer := make([]byte, 64)
	for {
		n, err := target.Read(buffer)
		if err != nil {
			t.Fatal(err)
		}

		if string(buffer[:n]) == "after" {
			return
		}
	}
}
