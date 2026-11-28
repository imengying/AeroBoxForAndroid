package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/sing-quic/tuic"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/uot"
)

type streamConn struct {
	*quic.Stream
	connection *quic.Conn
}

func (s streamConn) LocalAddr() net.Addr  { return s.connection.LocalAddr() }
func (s streamConn) RemoteAddr() net.Addr { return s.connection.RemoteAddr() }
func openClient(t *testing.T, peer *runningPeer) *quic.Conn {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(peer.cert) {
		t.Fatal("bad test root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, peer.socket.LocalAddr().String(), &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseWithError(0, "done") })
	state := conn.ConnectionState()
	token, err := state.TLS.ExportKeyingMaterial(string(userBytes[:]), []byte(password), 32)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenUniStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	auth := append([]byte{5, 0}, userBytes[:]...)
	auth = append(auth, token...)
	if _, err = stream.Write(auth); err != nil {
		t.Fatal(err)
	}
	if err = stream.Close(); err != nil {
		t.Fatal(err)
	}
	return conn
}
func openTCP(t *testing.T, conn *quic.Conn, target M.Socksaddr) streamConn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	name := target.Fqdn
	request := append([]byte{5, 1, 0, byte(len(name))}, []byte(name)...)
	request = append(request, byte(target.Port>>8), byte(target.Port))
	if _, err = stream.Write(request); err != nil {
		t.Fatal(err)
	}
	stream.SetDeadline(time.Now().Add(5 * time.Second))
	return streamConn{Stream: stream, connection: conn}
}
func TestUotReferenceSeparatesWireModesAndPreservesPackets(t *testing.T) {
	directory := t.TempDir()
	peer, err := startPeer(directory, "accept", true)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.close()
	conn := openClient(t, peer)
	for _, connect := range []bool{true, false} {
		stream := openTCP(t, conn, uot.RequestDestination(2))
		target := M.ParseSocksaddr("192.0.2.9:5353")
		request := uot.Request{IsConnect: connect, Destination: target}
		if err := uot.WriteRequest(stream, request); err != nil {
			t.Fatal(err)
		}
		packets := uot.NewConn(stream, request)
		for _, size := range []int{0, 3, 16384, 65535} {
			data := bytes.Repeat([]byte{byte(size + 17)}, size)
			if _, err := packets.WriteTo(data, target.UDPAddr()); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65535)
			n, _, err := packets.ReadFrom(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(data, buffer[:n]) {
				t.Fatalf("connect=%v size=%d got=%d", connect, size, n)
			}
		}
		_ = packets.Close()
	}
	stream := openTCP(t, conn, M.Socksaddr{Fqdn: "tcp.test", Port: 443})
	payload := bytes.Repeat([]byte{42}, 65537)
	result := make(chan error, 1)
	go func() { _, err := stream.Write(payload); result <- err }()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(stream, received); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(payload, received) {
		t.Fatal("TCP payload mismatch")
	}
	_ = stream.Close()
	file, err := os.Open(filepath.Join(directory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	decoder := json.NewDecoder(file)
	counts := map[string]int{}
	for {
		var record map[string]any
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		counts[record["event"].(string)]++
	}
	if counts["uot_open"] != 2 || counts["uot_packet"] != 8 || counts["tcp_open"] != 1 || counts["unexpected_native_udp"] != 0 {
		t.Fatalf("wrong wire events: %v", counts)
	}
}

type observedCache struct {
	tls.ClientSessionCache
	stored chan struct{}
}

func (c *observedCache) Put(name string, state *tls.ClientSessionState) {
	c.ClientSessionCache.Put(name, state)
	if state != nil {
		select {
		case c.stored <- struct{}{}:
		default:
		}
	}
}
func authenticateClient(t *testing.T, connection *quic.Conn) {
	t.Helper()
	state := connection.ConnectionState()
	token, err := state.TLS.ExportKeyingMaterial(string(userBytes[:]), []byte(password), 32)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := connection.OpenUniStreamSync(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	payload := append(append([]byte{5, 0}, userBytes[:]...), token...)
	if _, err := stream.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}
}
func TestReferenceAcceptsAndRejectsActualResumption(t *testing.T) {
	for _, mode := range []string{"accept", "reject-after-first"} {
		t.Run(mode, func(t *testing.T) {
			directory := t.TempDir()
			peer, err := startPeer(directory, mode, false)
			if err != nil {
				t.Fatal(err)
			}
			defer peer.close()
			roots := x509.NewCertPool()
			roots.AppendCertsFromPEM(peer.cert)
			cache := &observedCache{ClientSessionCache: tls.NewLRUClientSessionCache(8), stored: make(chan struct{}, 8)}
			config := &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h3"}, ClientSessionCache: cache}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			first, err := quic.DialAddr(ctx, peer.socket.LocalAddr().String(), config, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			authenticateClient(t, first)
			warm := openTCP(t, first, M.Socksaddr{Fqdn: "warm.test", Port: 443})
			if _, err := warm.Write([]byte("warm")); err != nil {
				t.Fatal(err)
			}
			if _, err := io.ReadFull(warm, make([]byte, 4)); err != nil {
				t.Fatal(err)
			}
			select {
			case <-cache.stored:
			case <-ctx.Done():
				t.Fatal("no session ticket")
			}
			first.CloseWithError(0, "warm reconnect")
			early, err := quic.DialAddrEarly(ctx, peer.socket.LocalAddr().String(), config, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer early.CloseWithError(0, "done")
			stream, err := early.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			target := "early.test"
			payload := []byte("one early payload")
			request := append([]byte{5, 1, 0, byte(len(target))}, []byte(target)...)
			request = append(request, 1, 187)
			request = append(request, payload...)
			_, writeError := stream.Write(request)
			select {
			case <-early.HandshakeComplete():
			case <-ctx.Done():
				t.Fatal("handshake incomplete")
			}
			state := early.ConnectionState()
			if !state.TLS.DidResume {
				t.Fatal("second connection did not resume")
			}
			if mode == "accept" {
				if !state.Used0RTT {
					t.Fatal("peer did not accept early data")
				}
				if writeError != nil {
					t.Fatal(writeError)
				}
			} else {
				if state.Used0RTT {
					t.Fatal("peer unexpectedly accepted early data")
				}
				if writeError != nil && !errors.Is(writeError, quic.Err0RTTRejected) {
					t.Fatal(writeError)
				}
				if _, err := early.NextConnection(ctx); err != nil {
					t.Fatal(err)
				}
				stream, err = early.OpenStreamSync(ctx)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = stream.Write(request); err != nil {
					t.Fatal(err)
				}
			}
			authenticateClient(t, early)
			stream.SetReadDeadline(time.Now().Add(2 * time.Second))
			received := make([]byte, len(payload))
			if _, err := io.ReadFull(stream, received); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(payload, received) {
				t.Fatal("wrong early payload")
			}
			file, err := os.Open(filepath.Join(directory, "events.jsonl"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			decoder := json.NewDecoder(file)
			earlyOpens := 0
			for {
				var row map[string]any
				if err := decoder.Decode(&row); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal(err)
				}
				if row["event"] == "tcp_open" && row["destination"] == "early.test:443" {
					earlyOpens++
				}
			}
			if earlyOpens != 1 {
				t.Fatalf("early TCP opens = %d, want once", earlyOpens)
			}
		})
	}
}

func TestNativeUdpEmptyPacketKeepsSameAssociationAlive(t *testing.T) {
	directory := t.TempDir()
	peer, err := startPeer(directory, "accept", false)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.close()
	connection := openClient(t, peer)
	target := M.Socksaddr{Fqdn: "packet.test", Port: 5353}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for index, size := range []int{0, 3, 1000} {
		data := bytes.Repeat([]byte{byte(index + 1)}, size)
		var request bytes.Buffer
		request.Write([]byte{5, 2, 0, 9, 0, byte(index), 1, 0})
		binary.Write(&request, binary.BigEndian, uint16(size))
		if err := tuic.AddressSerializer.WriteAddrPort(&request, target); err != nil {
			t.Fatal(err)
		}
		request.Write(data)
		if err := connection.SendDatagram(request.Bytes()); err != nil {
			t.Fatal(err)
		}
		for {
			reply, err := connection.ReceiveDatagram(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(reply, []byte{5, 4}) {
				continue
			}
			if len(reply) < 10 || !bytes.Equal(reply[:4], []byte{5, 2, 0, 9}) || reply[6] != 1 || reply[7] != 0 {
				t.Fatalf("bad reply: %x", reply)
			}
			reader := bytes.NewReader(reply[10:])
			address, err := tuic.AddressSerializer.ReadAddrPort(reader)
			if err != nil || address != target {
				t.Fatalf("wrong address: %v %v", address, err)
			}
			payload, err := io.ReadAll(reader)
			if err != nil || !bytes.Equal(payload, data) || int(binary.BigEndian.Uint16(reply[8:10])) != size {
				t.Fatalf("wrong payload: %x %v", payload, err)
			}
			break
		}
	}
	contents, err := os.ReadFile(filepath.Join(directory, "events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(contents))
	counts := map[string]int{}
	for {
		var row map[string]any
		if err := decoder.Decode(&row); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		counts[row["event"].(string)]++
	}
	if counts["native_udp_open"] != 1 || counts["native_udp_packet"] != 3 {
		t.Fatalf("association expired or empty packet dropped: %v", counts)
	}
}
