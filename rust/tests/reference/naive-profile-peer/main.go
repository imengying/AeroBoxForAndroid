// A local-only observer and the original pinned Cronet reference client.
package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/miekg/dns"
	cronet "github.com/sagernet/cronet-go"
	_ "github.com/sagernet/cronet-go/lib/linux_amd64"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

type fixtureLog struct{ logger.ContextLogger }

func (fixtureLog) DebugContext(_ context.Context, args ...any) { fmt.Fprintln(os.Stderr, args...) }
func (fixtureLog) ErrorContext(_ context.Context, args ...any) { fmt.Fprintln(os.Stderr, args...) }
func (fixtureLog) WarnContext(_ context.Context, args ...any)  { fmt.Fprintln(os.Stderr, args...) }

type recorder struct {
	net.Conn
	wire bytes.Buffer
}

func (r *recorder) Read(p []byte) (int, error) {
	n, e := r.Conn.Read(p)
	if r.wire.Len()+n < 1<<20 {
		r.wire.Write(p[:n])
	}
	return n, e
}

type frameRecord struct {
	Type     string
	Stream   uint32
	Flags    uint8
	Payload  string
	Headers  []hpack.HeaderField
	Settings [][2]uint32
	Priority *http2.PriorityParam `json:",omitempty"`
}

func report(v any) {
	if e := json.NewEncoder(os.Stdout).Encode(v); e != nil {
		panic(e)
	}
}
func check(e error) {
	if e != nil {
		panic(e)
	}
}
func serve(output string, requests int) {
	check(os.Mkdir(output, 0700))
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	check(e)
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	check(e)
	ca := filepath.Join(output, "ca.pem")
	check(os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600))
	leaf := *cert
	leaf.SerialNumber = big.NewInt(2)
	leaf.IsCA = false
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leafDER, e := x509.CreateCertificate(rand.Reader, &leaf, cert, &key.PublicKey, key)
	check(e)
	listener, e := net.Listen("tcp4", "127.0.0.1:0")
	check(e)
	defer listener.Close()
	listener.(*net.TCPListener).SetDeadline(time.Now().Add(45 * time.Second))
	report(map[string]any{"phase": "ready", "port": listener.Addr().(*net.TCPAddr).Port, "ca_pem": ca, "server_name": "localhost"})
	raw, e := listener.Accept()
	check(e)
	defer raw.Close()
	check(raw.SetDeadline(time.Now().Add(40 * time.Second)))
	rec := &recorder{Conn: raw}
	connection := tls.Server(rec, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{leafDER}, PrivateKey: key}}, MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}})
	check(connection.Handshake())
	check(os.WriteFile(filepath.Join(output, "client-tls.bin"), rec.wire.Bytes(), 0600))
	preface := make([]byte, len(http2.ClientPreface))
	_, e = io.ReadFull(connection, preface)
	check(e)
	if string(preface) != http2.ClientPreface {
		panic("invalid H2 preface")
	}
	framer := http2.NewFramer(connection, connection)
	// Keep the peer's encoder limit at the initial 4096, so the small CONNECT
	// fixture does not depend on whether SETTINGS races with its first request.
	// Dynamic table resizing is covered by the vendored h2 regression suite.
	check(framer.WriteSettings(http2.Setting{ID: http2.SettingHeaderTableSize, Val: 4096}, http2.Setting{ID: http2.SettingInitialWindowSize, Val: 8 << 20}))
	check(framer.WriteWindowUpdate(0, 16<<20))
	decoder := hpack.NewDecoder(65536, nil)
	var frames []frameRecord
	finished := 0
	closed := map[uint32]bool{}
	received := map[uint32]int{}
	for finished < requests {
		f, e := framer.ReadFrame()
		check(e)
		h := f.Header()
		entry := frameRecord{Type: h.Type.String(), Stream: h.StreamID, Flags: uint8(h.Flags)}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			f.ForeachSetting(func(s http2.Setting) error {
				entry.Settings = append(entry.Settings, [2]uint32{uint32(s.ID), s.Val})
				return nil
			})
			if !f.IsAck() {
				check(framer.WriteSettingsAck())
			}
		case *http2.WindowUpdateFrame:
			entry.Payload = fmt.Sprintf("%08x", f.Increment)
		case *http2.HeadersFrame:
			if !f.HeadersEnded() {
				panic("unexpected continuation in small fixture")
			}
			entry.Payload = hex.EncodeToString(f.HeaderBlockFragment())
			if f.HasPriority() {
				priority := f.Priority
				entry.Priority = &priority
			}
			entry.Headers, e = decoder.DecodeFull(f.HeaderBlockFragment())
			check(e)
			var buffer bytes.Buffer
			encoder := hpack.NewEncoder(&buffer)
			check(encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"}))
			check(encoder.WriteField(hpack.HeaderField{Name: "padding", Value: "reference"}))
			check(framer.WriteHeaders(http2.HeadersFrameParam{StreamID: h.StreamID, BlockFragment: buffer.Bytes(), EndHeaders: true}))
		case *http2.DataFrame:
			received[h.StreamID] += len(f.Data())
			check(framer.WriteData(h.StreamID, f.StreamEnded(), f.Data()))
			if len(f.Data()) > 0 {
				check(framer.WriteWindowUpdate(0, uint32(len(f.Data()))))
				if !f.StreamEnded() {
					check(framer.WriteWindowUpdate(h.StreamID, uint32(len(f.Data()))))
				}
			}
			if f.StreamEnded() && !closed[h.StreamID] {
				closed[h.StreamID] = true
				finished++
			}
		case *http2.PingFrame:
			if !f.IsAck() {
				check(framer.WritePing(true, f.Data))
			}
		case *http2.RSTStreamFrame:
			if f.ErrCode != http2.ErrCodeCancel || received[h.StreamID] < 65537 {
				panic(fmt.Sprintf("stream reset before payload: %v", f.ErrCode))
			}
			if !closed[h.StreamID] {
				closed[h.StreamID] = true
				finished++
			}
		}
		frames = append(frames, entry)
	}
	state := connection.ConnectionState()
	summary := map[string]any{"phase": "complete", "version": state.Version, "cipher": state.CipherSuite, "requests": finished, "frames": frames}
	encoded, e := json.MarshalIndent(summary, "", "  ")
	check(e)
	check(os.WriteFile(filepath.Join(output, "capture.json"), encoded, 0600))
	report(summary)
	connection.Close()
}
func native(port int, ca string, requests int, quic bool) {
	roots, e := os.ReadFile(ca)
	check(e)
	resolver := func(ctx context.Context, request *dns.Msg) *dns.Msg {
		reply := new(dns.Msg)
		reply.SetReply(request)
		if len(request.Question) > 0 && request.Question[0].Qtype == dns.TypeA {
			reply.Answer = []dns.RR{&dns.A{Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30}, A: net.IPv4(127, 0, 0, 1)}}
		}
		return reply
	}
	name := "localhost"
	if quic {
		name = "naive.test"
	} // Avoid the OS's IPv6 localhost shortcut.
	client, e := cronet.NewNaiveClient(cronet.NaiveClientOptions{Context: context.Background(), ServerAddress: M.ParseSocksaddrHostPort("127.0.0.1", uint16(port)), ServerName: name, Username: "user", Password: "pass", TrustedRootCertificates: string(roots), DNSResolver: resolver, TestForceUDPLoopback: true, Logger: fixtureLog{logger.NOP()}, QUIC: quic})
	check(e)
	check(client.Start())
	defer client.Close()
	for i := 0; i < requests; i++ {
		stream, e := client.DialContext(context.Background(), "tcp", M.ParseSocksaddrHostPort("capture.invalid", 443))
		check(e)
		payload := make([]byte, 65537)
		for j := range payload {
			payload[j] = byte((j*17 + 3) % 251)
		}
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); _, e := stream.Write(payload); check(e) }()
		received := make([]byte, len(payload))
		_, e = io.ReadFull(stream, received)
		check(e)
		wg.Wait()
		if !bytes.Equal(payload, received) {
			panic("echo mismatch")
		}
		check(stream.Close())
	}
	report(map[string]any{"phase": "native-complete", "requests": requests})
}
func main() {
	mode := flag.String("mode", "serve", "serve or native")
	out := flag.String("output", "", "new output directory")
	n := flag.Int("requests", 2, "tunnels")
	port := flag.Int("port", 0, "loopback peer port")
	ca := flag.String("ca", "", "test CA")
	quic := flag.Bool("quic", false, "use the original QUIC transport")
	flag.Parse()
	if *mode == "serve" {
		serve(*out, *n)
	} else if *mode == "native" {
		native(*port, *ca, *n, *quic)
	} else {
		panic("invalid mode")
	}
}
