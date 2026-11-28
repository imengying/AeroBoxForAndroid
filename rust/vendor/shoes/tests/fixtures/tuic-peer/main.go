// Independent pinned Go peer. This is test code, never a product dependency.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
	qtls "github.com/sagernet/sing-quic"
	"github.com/sagernet/sing-quic/tuic"
	"github.com/sagernet/sing/common/bufio"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	aTLS "github.com/sagernet/sing/common/tls"
	"github.com/sagernet/sing/common/uot"
)

const userID = "d9ad4eab-f118-492b-a99b-e0e27332b4b2"
const password = "test-password"

var userBytes = [16]byte{0xd9, 0xad, 0x4e, 0xab, 0xf1, 0x18, 0x49, 0x2b, 0xa9, 0x9b, 0xe0, 0xe2, 0x73, 0x32, 0xb4, 0xb2}

type events struct {
	mu   sync.Mutex
	file *os.File
}

func (e *events) record(row map[string]any) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := json.NewEncoder(e.file).Encode(row); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
	_ = e.file.Sync()
}
func (e *events) packet(kind string, target M.Socksaddr, data []byte) {
	digest := sha256.Sum256(data)
	e.record(map[string]any{"event": kind, "destination": target.String(), "bytes": len(data), "sha256": hex.EncodeToString(digest[:])})
}

type serverTLS struct {
	config      *tls.Config
	events      *events
	mode        string
	connections atomic.Uint64
}

func (s *serverTLS) ServerName() string                   { return s.config.ServerName }
func (s *serverTLS) SetServerName(name string)            { s.config.ServerName = name }
func (s *serverTLS) NextProtos() []string                 { return s.config.NextProtos }
func (s *serverTLS) SetNextProtos(value []string)         { s.config.NextProtos = value }
func (s *serverTLS) HandshakeTimeout() time.Duration      { return 5 * time.Second }
func (s *serverTLS) SetHandshakeTimeout(time.Duration)    {}
func (s *serverTLS) STDConfig() (*tls.Config, error)      { return s.config, nil }
func (s *serverTLS) Client(c net.Conn) (aTLS.Conn, error) { return tls.Client(c, s.config), nil }
func (s *serverTLS) Server(c net.Conn) (aTLS.Conn, error) { return tls.Server(c, s.config), nil }
func (s *serverTLS) Clone() aTLS.Config {
	return &serverTLS{config: s.config.Clone(), events: s.events, mode: s.mode}
}
func (s *serverTLS) Start() error    { return nil }
func (s *serverTLS) Close() error    { return nil }
func (s *serverTLS) ConfigureHTTP3() {}
func (s *serverTLS) quicConfig(base *quic.Config) *quic.Config {
	config := base.Clone()
	config.GetConfigForClient = func(_ *quic.ClientInfo) (*quic.Config, error) {
		index := s.connections.Add(1)
		// Deterministic test-only window for sending actual early STREAM bytes,
		// before a loopback server can finish TLS on another runtime worker.
		if value := os.Getenv("AEROBOX_TUIC_HANDSHAKE_DELAY_MS"); value != "" {
			milliseconds, err := strconv.Atoi(value)
			if err != nil || milliseconds < 0 || milliseconds > 1000 {
				panic("invalid handshake delay")
			}
			time.Sleep(time.Duration(milliseconds) * time.Millisecond)
		}
		selected := base.Clone()
		selected.GetConfigForClient = nil
		selected.Allow0RTT = s.mode == "accept" || (s.mode == "reject-after-first" && index == 1)
		s.events.record(map[string]any{"event": "offer", "connection": index, "allow_0rtt": selected.Allow0RTT})
		return selected, nil
	}
	return config
}
func (s *serverTLS) Listen(c net.PacketConn, config *quic.Config) (qtls.Listener, error) {
	listener, err := quic.Listen(c, s.config, s.quicConfig(config))
	if err != nil {
		return nil, err
	}
	return &observedListener{Listener: listener, events: s.events}, nil
}
func (s *serverTLS) ListenEarly(c net.PacketConn, config *quic.Config) (qtls.EarlyListener, error) {
	listener, err := quic.ListenEarly(c, s.config, s.quicConfig(config))
	if err != nil {
		return nil, err
	}
	return &observedListener{Listener: listener, events: s.events}, nil
}

type observedListener struct {
	qtls.Listener
	events *events
}

func (l *observedListener) Accept(ctx context.Context) (*quic.Conn, error) {
	conn, err := l.Listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	go func() {
		select {
		case <-conn.HandshakeComplete():
			state := conn.ConnectionState()
			l.events.record(map[string]any{"event": "handshake", "remote": conn.RemoteAddr().String(), "resumed": state.TLS.DidResume, "used_0rtt": state.Used0RTT, "name": state.TLS.ServerName})
		case <-conn.Context().Done():
			l.events.record(map[string]any{"event": "handshake_failed", "remote": conn.RemoteAddr().String()})
		}
	}()
	return conn, nil
}

type echo struct {
	events  *events
	uotOnly bool
}

func (h echo) NewConnectionEx(_ context.Context, conn net.Conn, _, target M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	if target.Fqdn == uot.MagicAddress && target.Port == 0 {
		request, err := uot.ReadRequest(conn)
		if err != nil {
			h.events.record(map[string]any{"event": "uot_error", "error": err.Error()})
			return
		}
		h.events.record(map[string]any{"event": "uot_open", "connect": request.IsConnect, "destination": request.Destination.String()})
		stream := uot.NewConn(conn, *request)
		packet := make([]byte, 65535)
		for {
			n, address, err := stream.ReadFrom(packet)
			if err != nil {
				return
			}
			h.events.packet("uot_packet", request.Destination, packet[:n])
			if _, err = stream.WriteTo(packet[:n], address); err != nil {
				return
			}
		}
	}
	h.events.record(map[string]any{"event": "tcp_open", "destination": target.String()})
	digest := sha256.New()
	count, err := io.Copy(io.MultiWriter(conn, digest), conn)
	record := map[string]any{"event": "tcp_closed", "destination": target.String(), "bytes": count, "sha256": hex.EncodeToString(digest.Sum(nil))}
	if err != nil {
		record["error"] = err.Error()
	}
	h.events.record(record)
}
func (h echo) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, target M.Socksaddr, _ N.CloseHandlerFunc) {
	defer conn.Close()
	if h.uotOnly {
		h.events.record(map[string]any{"event": "unexpected_native_udp"})
		return
	}
	waiter, ok := bufio.CreatePacketReadWaiter(conn)
	if !ok {
		panic("TUIC peer packet waiter missing")
	}
	options := N.NewReadWaitOptions(conn, conn)
	options.MTU = 65535
	waiter.InitializeReadWaiter(options)
	h.events.record(map[string]any{"event": "native_udp_open", "destination": target.String()})
	for {
		packet, destination, err := waiter.WaitReadPacket()
		if err != nil {
			h.events.record(map[string]any{"event": "native_udp_read_error", "error": err.Error()})
			return
		}
		h.events.packet("native_udp_packet", destination, packet.Bytes())
		if err = conn.WritePacket(packet, destination); err != nil {
			h.events.record(map[string]any{"event": "native_udp_write_error", "error": err.Error()})
			return
		}
	}
}

type runningPeer struct {
	service *tuic.Service[string]
	socket  net.PacketConn
	cancel  context.CancelFunc
	events  *events
	cert    []byte
}

func (p *runningPeer) close() { p.cancel(); _ = p.service.Close(); _ = p.socket.Close() }
func startPeer(directory, mode string, uotOnly bool) (*runningPeer, error) {
	if err := os.MkdirAll(directory, 0700); err != nil {
		return nil, err
	}
	caPublic, caPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "aerobox-tuic-test-ca"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caPrivate)
	if err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "aerobox-tuic-peer"}, DNSNames: []string{"localhost", "tuic.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, public, caPrivate)
	if err != nil {
		return nil, err
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	if err = os.WriteFile(filepath.Join(directory, "ca.pem"), certificate, 0600); err != nil {
		return nil, err
	}
	file, err := os.Create(filepath.Join(directory, "events.jsonl"))
	if err != nil {
		return nil, err
	}
	recorder := &events{file: file}
	config := &serverTLS{config: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der, caDER}, PrivateKey: private}}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}, events: recorder, mode: mode}
	ctx, cancel := context.WithCancel(context.Background())
	service, err := tuic.NewService[string](tuic.ServiceOptions{Context: ctx, Logger: logger.NOP(), TLSConfig: config, ZeroRTTHandshake: mode != "disabled", Heartbeat: time.Second, UDPTimeout: 30 * time.Second, Handler: echo{events: recorder, uotOnly: uotOnly}})
	if err != nil {
		cancel()
		file.Close()
		return nil, err
	}
	service.UpdateUsers([]string{"test"}, [][16]byte{userBytes}, []string{password})
	socket, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		cancel()
		file.Close()
		return nil, err
	}
	if err = service.Start(socket); err != nil {
		cancel()
		socket.Close()
		file.Close()
		return nil, err
	}
	return &runningPeer{service: service, socket: socket, cancel: cancel, events: recorder, cert: certificate}, nil
}
func main() {
	mode := "accept"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	if mode != "accept" && mode != "reject" && mode != "reject-after-first" && mode != "disabled" {
		panic("mode must be accept|reject|reject-after-first|disabled")
	}
	directory := os.Getenv("AEROBOX_PEER_CERT_DIR")
	if directory == "" {
		panic("AEROBOX_PEER_CERT_DIR is required")
	}
	uotOnly := len(os.Args) > 2 && os.Args[2] == "uot-only"
	peer, err := startPeer(directory, mode, uotOnly)
	if err != nil {
		panic(err)
	}
	defer peer.close()
	fmt.Println(peer.socket.LocalAddr().(*net.UDPAddr).Port)
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-signalCtx.Done()
}
