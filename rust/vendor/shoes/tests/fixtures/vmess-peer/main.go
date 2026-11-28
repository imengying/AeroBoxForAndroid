// Independent reference implementation for tests; never linked into the Rust kernel.
package main

import (
	"context"
	"fmt"
	vmess "github.com/sagernet/sing-vmess"
	"github.com/sagernet/sing-vmess/packetaddr"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"strconv"
)

const userID = "d9ad4eab-f118-492b-a99b-e0e27332b4b2"

type echo struct{}

func trace(format string, args ...any) {
	if os.Getenv("AEROBOX_INTEROP_TRACE") != "" {
		fmt.Fprintf(os.Stderr, format+"\n", args...)
	}
}

func (echo) NewConnectionEx(_ context.Context, conn net.Conn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	trace("reference TCP open destination=%v", destination)
	n, err := io.Copy(conn, conn)
	trace("reference TCP closed echoed=%d error=%v", n, err)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
func (echo) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, destination M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	trace("reference UDP open destination=%v", destination)
	for {
		packet := buf.NewSize(65535 + 512)
		packet.Resize(256, 0)
		target, err := conn.ReadPacket(packet)
		trace("reference UDP read length=%d error=%v", packet.Len(), err)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintln(os.Stderr, err)
			}
			packet.Release()
			return
		}
		if destination.Fqdn == packetaddr.SeqPacketMagicAddress {
			endpoint, err := packetaddr.AddressSerializer.ReadAddrPort(packet)
			if err != nil {
				panic(err)
			}
			header := buf.With(packet.ExtendHeader(packetaddr.AddressSerializer.AddrPortLen(endpoint)))
			if err := packetaddr.AddressSerializer.WriteAddrPort(header, endpoint); err != nil {
				panic(err)
			}
		}
		trace("reference UDP write length=%d", packet.Len())
		if err = conn.WritePacket(packet, target); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
	}
}
func main() {
	selectedUserID := userID
	if configured, present := os.LookupEnv("AEROBOX_INTEROP_USER_ID"); present {
		selectedUserID = configured
	}
	var accept func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error
	if len(os.Args) > 1 && os.Args[1] == "vless" {
		service := vless.NewService[string](logger.NOP(), echo{})
		service.UpdateUsers([]string{"test"}, []string{selectedUserID}, []string{""})
		accept = service.NewConnection
	} else {
		alterID := 0
		if len(os.Args) > 2 {
			var err error
			alterID, err = strconv.Atoi(os.Args[2])
			if err != nil || alterID < 0 || alterID > 65535 {
				panic("invalid alter_id")
			}
		}
		service := vmess.NewService[string](echo{})
		if err := service.UpdateUsers([]string{"test"}, []string{selectedUserID}, []int{alterID}); err != nil {
			panic(err)
		}
		if err := service.Start(); err != nil {
			panic(err)
		}
		defer service.Close()
		accept = service.NewConnection
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			if err := accept(context.Background(), conn, M.Socksaddr{}, nil); err != nil {
				fmt.Fprintln(os.Stderr, err)
			}
		}()
	}
}
