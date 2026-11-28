// Independent test peer; never linked into the Rust kernel.
package main

import (
	"aerobox-obfs-peer/gost/http"
	"aerobox-obfs-peer/gost/tls"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	ss "github.com/sagernet/sing-shadowsocks"
	"github.com/sagernet/sing-shadowsocks/shadowaead"
	ss2022 "github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Preserve the first HTTP body boundary for the upstream GOST fixture. Its
// ReadRequest path drops bytes prefetched after Content-Length. Fragmenting
// only that header/body prevents that unrelated peer bug masking SS tests.
type firstHTTPBody struct {
	net.Conn
	header    []byte
	remaining int
	headDone  bool
}

func (c *firstHTTPBody) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if !c.headDone {
		n, err := c.Conn.Read(p[:1])
		c.header = append(c.header, p[:n]...)
		if strings.HasSuffix(string(c.header), "\r\n\r\n") {
			c.headDone = true
			for _, line := range strings.Split(string(c.header), "\r\n") {
				key, value, found := strings.Cut(line, ":")
				if found && strings.EqualFold(key, "Content-Length") {
					c.remaining, err = strconv.Atoi(strings.TrimSpace(value))
					if err != nil {
						return n, err
					}
				}
			}
			c.header = nil
		}
		return n, err
	}
	if c.remaining > 0 {
		if len(p) > c.remaining {
			p = p[:c.remaining]
		}
		n, err := c.Conn.Read(p)
		c.remaining -= n
		return n, err
	}
	return c.Conn.Read(p)
}

func echo(conn net.Conn) error {
	// GOST's first TLS response contains one record. Bound each Write so its
	// first-response path cannot return a length larger than that record.
	buffer := make([]byte, 8192)
	seen := 0
	for {
		n, err := conn.Read(buffer)
		if os.Getenv("AEROBOX_PEER_TRACE") != "" && seen < 8 {
			fmt.Fprintln(os.Stderr, os.Args[1:], "echo read", n, err)
		}
		seen++
		if n > 0 {
			sent, writeErr := conn.Write(buffer[:n])
			if os.Getenv("AEROBOX_PEER_TRACE") != "" && seen < 8 {
				fmt.Fprintln(os.Stderr, os.Args[1:], "echo wrote", sent, writeErr)
			}
			if writeErr != nil {
				return writeErr
			}
			if sent != n {
				return io.ErrShortWrite
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

type handler struct{}

func (handler) NewConnection(_ context.Context, conn net.Conn, _ M.Metadata) error { return echo(conn) }
func (handler) NewPacketConnection(_ context.Context, conn N.PacketConn, _ M.Metadata) error {
	defer conn.Close()
	// udpnat.ReadPacket copies through io.Reader, whose empty Buffer reports
	// EOF. Its packet waiter preserves an empty UDP datagram as a real packet.
	waiter, ok := bufio.CreatePacketReadWaiter(conn)
	if !ok {
		panic("reference UDP association lacks a packet waiter")
	}
	options := N.NewReadWaitOptions(conn, conn)
	options.MTU = 65535
	waiter.InitializeReadWaiter(options)
	for {
		packet, target, err := waiter.WaitReadPacket()
		if err != nil {
			return err
		}
		if err = conn.WritePacket(packet, target); err != nil {
			return err
		}
	}
}
func (handler) NewError(_ context.Context, err error) { fmt.Fprintln(os.Stderr, err) }

func main() {
	mode := os.Args[1]
	var service ss.Service
	var err error
	if len(os.Args) > 2 {
		method := os.Args[2]
		if strings.HasPrefix(method, "2022-") {
			keyLen := 32
			if method == "2022-blake3-aes-128-gcm" {
				keyLen = 16
			}
			key := make([]byte, keyLen)
			for i := range key {
				key[i] = 42
			}
			service, err = ss2022.NewServiceWithPassword(method, base64.StdEncoding.EncodeToString(key), 60, handler{}, time.Now)
		} else {
			service, err = shadowaead.NewService(method, nil, "aerobox-reference", 60, handler{})
		}
		if err != nil {
			panic(err)
		}
	}
	if mode == "quic" {
		serveQuic(service)
		return
	}
	if mode == "udp" {
		listener, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			panic(err)
		}
		fmt.Println(listener.LocalAddr().(*net.UDPAddr).Port)
		conn := bufio.NewPacketConn(listener)
		for {
			packet := buf.NewSize(65535 + 512)
			packet.Resize(256, 0)
			source, err := conn.ReadPacket(packet)
			if err != nil {
				panic(err)
			}
			if err := service.NewPacket(context.Background(), conn, packet, M.Metadata{Source: source}); err != nil {
				panic(err)
			}
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	if mode == "ws" || mode == "wsmux" {
		serveWebsocket(listener, mode, service)
		return
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	for {
		raw, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer raw.Close()
			raw.SetDeadline(time.Now().Add(30 * time.Second))
			var conn net.Conn
			switch mode {
			case "http":
				conn = http.Server(&firstHTTPBody{Conn: raw})
			case "tls":
				conn = tls.Server(raw)
			default:
				panic("unknown obfs mode")
			}
			var serveErr error
			if service == nil {
				serveErr = echo(conn)
			} else {
				serveErr = service.NewConnection(context.Background(), conn, M.Metadata{})
			}
			if serveErr != nil {
				fmt.Fprintln(os.Stderr, serveErr)
			}
		}()
	}
}
