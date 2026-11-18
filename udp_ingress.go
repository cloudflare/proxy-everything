package main

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"syscall"
)

// UDP ingress: a CONNECT with X-Dst-Protocol: udp opens one UDP flow to X-Dst-Addr and gets the same
// 200 as TCP. Then each direction carries frames: a 2-byte big-endian length L, then L bytes of one
// datagram. Frames with L above 1500 are skipped and the flow stays open, so the limit can grow later.
// L = 0xFFFF is FLOW_END, which only cc-oxy-router sends; one from workerd is a protocol error that
// ends the flow. EOF or an error on either side also ends it.

const maxUDPPayloadSize = 1500

const udpFrameHeaderSize = 2

const maxUDPFrameSize = udpFrameHeaderSize + maxUDPPayloadSize

// A FLOW_END frame only travels away from the container.
const udpFlowEndLength = 0xffff

var errUDPFlowEndTowardContainer = errors.New("udp FLOW_END frame sent toward the container")

func (s *ingressServer) handleConnectUDP(ctx context.Context, clientConn net.Conn, reader *bufio.Reader, targetAddr string) {
	originConn, err := (&net.Dialer{}).DialContext(ctx, "udp4", targetAddr)
	response := http.Response{ProtoMajor: 1, ProtoMinor: 1}
	if err != nil {
		response.StatusCode = http.StatusBadRequest
		if writeErr := response.Write(clientConn); writeErr != nil {
			log.Println("error writing ingress udp dial failure response:", writeErr)
		}

		log.Println("error dialing ingress udp target", targetAddr, err)
		return
	}

	udpConn := originConn.(*net.UDPConn)
	defer udpConn.Close()

	response.StatusCode = http.StatusOK
	if err := response.Write(clientConn); err != nil {
		log.Println("error writing ingress udp connect response:", err)
		return
	}

	relayUDPFlow(ctx, clientConn, reader, udpConn)
}

// relayUDPFlow returns once both directions have stopped. Half-close is never used on a UDP tunnel:
// EOF or an error in either direction closes the tunnel and the UDP socket.
func relayUDPFlow(ctx context.Context, clientConn net.Conn, reader *bufio.Reader, udpConn *net.UDPConn) {
	closeFlow := func() {
		clientConn.Close()
		udpConn.Close()
	}

	stopAfterFunc := context.AfterFunc(ctx, closeFlow)
	defer stopAfterFunc()

	var flowWG sync.WaitGroup

	flowWG.Go(func() {
		defer closeFlow()

		err := relayTunnelToUDP(reader, udpConn)
		if err != io.EOF && !errors.Is(err, net.ErrClosed) {
			log.Println("ingress udp tunnel to udp relay ended:", err)
		}
	})

	flowWG.Go(func() {
		defer closeFlow()

		err := relayUDPToTunnel(udpConn, clientConn)
		if !errors.Is(err, net.ErrClosed) {
			log.Println("ingress udp udp to tunnel relay ended:", err)
		}
	})

	flowWG.Wait()
}

// relayTunnelToUDP returns io.EOF only when the tunnel ends on a frame boundary.
func relayTunnelToUDP(reader io.Reader, udpConn *net.UDPConn) error {
	buffer := make([]byte, maxUDPFrameSize)

	for {
		payload, err := readUDPFrame(reader, buffer)
		if err != nil {
			return err
		}

		// ICMP port unreachable from an earlier datagram; the application may bind the port later.
		if _, err := udpConn.Write(payload); err != nil && !errors.Is(err, syscall.ECONNREFUSED) {
			return err
		}
	}
}

// relayUDPToTunnel blocks on tunnel writes, so under backpressure the kernel drops at the UDP socket.
func relayUDPToTunnel(udpConn *net.UDPConn, tunnel io.Writer) error {
	frame := make([]byte, maxUDPFrameSize+1)

	for {
		// A datagram over maxUDPPayloadSize fills the extra byte of the buffer.
		n, err := udpConn.Read(frame[udpFrameHeaderSize:])
		if errors.Is(err, syscall.ECONNREFUSED) {
			continue
		}

		if err != nil {
			return err
		}

		if n > maxUDPPayloadSize {
			continue
		}

		binary.BigEndian.PutUint16(frame, uint16(n))
		if _, err := tunnel.Write(frame[:udpFrameHeaderSize+n]); err != nil {
			return err
		}
	}
}

// readUDPFrame reads frames into buffer, which holds at least maxUDPFrameSize bytes, until one carries
// a datagram within maxUDPPayloadSize, and returns its payload. Larger frames are skipped without
// buffering, so a peer can raise its limit without negotiation. io.EOF means the stream ended between
// frames.
func readUDPFrame(reader io.Reader, buffer []byte) ([]byte, error) {
	header := buffer[:udpFrameHeaderSize]

	for {
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}

		length := int(binary.BigEndian.Uint16(header))
		if length == udpFlowEndLength {
			return nil, errUDPFlowEndTowardContainer
		}

		if length <= maxUDPPayloadSize {
			payload := buffer[udpFrameHeaderSize : udpFrameHeaderSize+length]
			if _, err := io.ReadFull(reader, payload); err != nil {
				return nil, unexpectedEOF(err)
			}

			return payload, nil
		}

		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return nil, unexpectedEOF(err)
		}
	}
}

func unexpectedEOF(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}

	return err
}
