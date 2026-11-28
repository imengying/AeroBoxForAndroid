package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	ss "github.com/sagernet/sing-shadowsocks"
)

// The pinned Android transport uses raw QUIC bidirectional streams and h3 ALPN.
// No HTTP/3 frames or Xray-mux metadata are present on these streams.
type quicStream struct {
	*quic.Stream
	connection *quic.Conn
}

func (s *quicStream) LocalAddr() net.Addr  { return s.connection.LocalAddr() }
func (s *quicStream) RemoteAddr() net.Addr { return s.connection.RemoteAddr() }
func (s *quicStream) Close() error {
	s.CancelRead(0)
	return s.Stream.Close()
}

func serveQuic(service ss.Service) {
	listener, err := quic.ListenAddr("127.0.0.1:0", peerTLSConfig([]string{"h3"}), &quic.Config{
		MaxIncomingStreams: 128, MaxIncomingUniStreams: -1, MaxIdleTimeout: 30 * time.Second,
	})
	if err != nil {
		panic(err)
	}
	var access sync.Mutex
	var connections []*quic.Conn
	stats := filepath.Join(os.Getenv("AEROBOX_PEER_CERT_DIR"), "connections")
	if err := os.WriteFile(stats, []byte("0"), 0600); err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.UDPAddr).Port)
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			if scanner.Text() == "close" {
				access.Lock()
				for _, connection := range connections {
					connection.CloseWithError(42, "test reconnect")
				}
				access.Unlock()
				fmt.Println("closed")
			}
		}
	}()
	for {
		connection, err := listener.Accept(context.Background())
		if err != nil {
			panic(err)
		}
		access.Lock()
		connections = append(connections, connection)
		if err := os.WriteFile(stats+".tmp", []byte(strconv.Itoa(len(connections))), 0600); err != nil {
			panic(err)
		}
		if err := os.Rename(stats+".tmp", stats); err != nil {
			panic(err)
		}
		access.Unlock()
		go func() {
			for {
				stream, err := connection.AcceptStream(context.Background())
				if err != nil {
					return
				}
				go func() {
					conn := &quicStream{stream, connection}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(30 * time.Second))
					serveSS(service, conn)
				}()
			}
		}()
	}
}
