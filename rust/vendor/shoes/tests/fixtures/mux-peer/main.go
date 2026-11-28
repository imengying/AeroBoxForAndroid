// Independent interoperability peer, never linked into the Rust kernel.
package main

import (
	"context"
	"fmt"
	mux "github.com/sagernet/sing-mux"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/debug"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
)

var eventLock sync.Mutex

func event(message string) {
	if path := os.Getenv("AEROBOX_MUX_EVENTS"); path != "" {
		eventLock.Lock()
		defer eventLock.Unlock()
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
		if err != nil {
			panic(err)
		}
		fmt.Fprintln(f, message)
		f.Close()
	}
}

type echo struct{}

func (echo) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	event("tcp")
	io.Copy(conn, conn)
}
func (echo) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	event("udp")
	for {
		packet := buf.NewSize(65535 + 64)
		packet.Resize(64, 0)
		target, err := conn.ReadPacket(packet)
		if err != nil {
			packet.Release()
			return
		}
		if err = conn.WritePacket(packet, target); err != nil {
			return
		}
	}
}
func main() {
	var brutal mux.BrutalOptions
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "brutal":
			if !debug.Enabled {
				panic("Brutal fixture requires go build -tags debug (server kernel fallback only)")
			}
			brutal = mux.BrutalOptions{Enabled: true, SendBPS: 800000, ReceiveBPS: 500000}
		case "reject":
		default:
			panic("unknown fixture mode")
		}
	}
	service, err := mux.NewService(mux.ServiceOptions{
		NewStreamContext: func(ctx context.Context, _ net.Conn) context.Context { return ctx },
		Logger:           logger.NOP(), HandlerEx: echo{}, Brutal: brutal,
	})
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	var count atomic.Uint64
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		event(fmt.Sprintf("carrier %d", count.Add(1)))
		go func() {
			defer conn.Close()
			if err := service.NewConnection(context.Background(), conn, M.Metadata{}); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}
}
