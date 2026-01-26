package main

import (
	"bufio"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
)

func tryClosingWriteSide(conn net.Conn) bool {
	connWriter, isCloseWriter := conn.(interface{ CloseWrite() error })
	if isCloseWriter {
		connWriter.CloseWrite()
	} else {
		conn.Close()
	}

	return isCloseWriter
}

func tryClosingReadSide(conn net.Conn) bool {
	connWriter, isCloseRead := conn.(interface{ CloseRead() error })
	if isCloseRead {
		connWriter.CloseRead()
	} else {
		conn.Close()
	}

	return isCloseRead
}

// startDummyServer is a dummy server that just dials to the outside internet
func startDummyServer(addr net.Addr) {
	ln, err := net.Listen(addr.Network(), addr.String())
	if err != nil {
		fatal(err)
	}

	wg := &sync.WaitGroup{}
	defer wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fatal(err)
		}

		wg.Go(func() {
			defer conn.Close()
			wg := &sync.WaitGroup{}
			defer wg.Wait()

			reader := bufio.NewReader(conn)
			req, err := http.ReadRequest(reader)
			if err != nil {
				log.Println("Can't read request:", err)
				return
			}

			if req.Method != http.MethodConnect {
				errRes := (&http.Response{
					ProtoMajor: 1,
					ProtoMinor: 1,
					StatusCode: http.StatusMethodNotAllowed,
				}).Write(conn)
				if errRes != nil {
					log.Println("Error writing response:", errRes)
				}

				log.Println("Error HTTP method is not connect:", req.Method)
				return
			}

			destinationAddr := req.Host
			dialer := net.Dialer{}
			originConn, err := dialer.Dial("tcp", destinationAddr)
			response := http.Response{
				ProtoMajor: 1,
				ProtoMinor: 1,
			}

			if err != nil {
				response.StatusCode = http.StatusBadRequest
				if err := response.Write(conn); err != nil {
					log.Println("Error writing back the response:", err)
				}

				log.Println("Error dialing the origin connection", destinationAddr, err)
				return
			}

			response.StatusCode = http.StatusOK
			if err := response.Write(conn); err != nil {
				log.Println("Error writing back the OK response:", err)
				return
			}

			// client -> origin
			wg.Go(func() {
				defer tryClosingWriteSide(originConn)
				defer tryClosingReadSide(conn)
				io.Copy(originConn, reader)
			})

			// origin -> client
			wg.Go(func() {
				defer tryClosingWriteSide(conn)
				defer tryClosingReadSide(originConn)
				io.Copy(conn, originConn)
			})

		})
	}
}
