// Independent Go ECH reference peer. This fixture is never part of the Rust/AAR build.
package main

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/sagernet/quic-go"
)

const (
	privateName = "secret.test"
	publicName  = "public.test"
	peerALPN    = "h3"
)

type handshake struct {
	ID                int    `json:"id"`
	ServerName        string `json:"server_name"`
	ECHAccepted       bool   `json:"ech_accepted"`
	Resumed           bool   `json:"resumed"`
	TLSParametersSeen bool   `json:"tls_parameters_seen"`
	TLSVersion        uint16 `json:"tls_version"`
	ALPN              string `json:"alpn"`
}

type statistics struct {
	Transport        string      `json:"transport"`
	Mode             string      `json:"mode"`
	Attempts         int         `json:"attempts"`
	ECHAccepted      int         `json:"ech_accepted"`
	ECHRejected      int         `json:"ech_rejected"`
	Connections      int         `json:"connections"`
	EarlyConnections int         `json:"early_connections"`
	Streams          int         `json:"streams"`
	EchoedBytes      int64       `json:"echoed_bytes"`
	HandshakeErrors  int         `json:"tcp_handshake_errors"`
	Handshakes       []handshake `json:"handshakes"`
}

type observer struct {
	access sync.Mutex
	dir    string
	state  statistics
}

func newObserver(dir, transport, mode string) (*observer, error) {
	o := &observer{dir: dir, state: statistics{
		Transport: transport, Mode: mode, Handshakes: []handshake{},
	}}
	if err := os.WriteFile(filepath.Join(dir, "handshakes.jsonl"), nil, 0600); err != nil {
		return nil, err
	}
	return o, o.save()
}

// All mutations hold access. Rename makes snapshots safe for concurrent test readers.
func (o *observer) save() error {
	data, err := json.Marshal(o.state)
	if err != nil {
		return err
	}
	path := filepath.Join(o.dir, "stats.json")
	if err := os.WriteFile(path+".tmp", append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(path+".tmp", path)
}

func (o *observer) begin(name string) (int, error) {
	o.access.Lock()
	defer o.access.Unlock()
	o.state.Attempts++
	id := len(o.state.Handshakes)
	o.state.Handshakes = append(o.state.Handshakes, handshake{ID: id + 1, ServerName: name})
	return id, o.save()
}

// VerifyConnection runs even for ECH rejection before the client sends Finished.
// This observes QUIC rejections too: they never reach quic.Listener.Accept.
func (o *observer) parameters(id int, state tls.ConnectionState) error {
	o.access.Lock()
	defer o.access.Unlock()
	entry := &o.state.Handshakes[id]
	if entry.TLSParametersSeen {
		return errors.New("duplicate TLS parameters callback")
	}
	entry.ServerName, entry.ECHAccepted = state.ServerName, state.ECHAccepted
	entry.Resumed = state.DidResume
	entry.TLSParametersSeen = true
	entry.TLSVersion, entry.ALPN = state.Version, state.NegotiatedProtocol
	if state.ECHAccepted {
		o.state.ECHAccepted++
	} else {
		o.state.ECHRejected++
	}
	file, err := os.OpenFile(filepath.Join(o.dir, "handshakes.jsonl"), os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = json.NewEncoder(file).Encode(entry)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return o.save()
}

func (o *observer) update(change func(*statistics)) {
	o.access.Lock()
	defer o.access.Unlock()
	change(&o.state)
	if err := o.save(); err != nil {
		panic(err)
	}
}

type authority struct {
	certificate *x509.Certificate
	der         []byte
	key         ed25519.PrivateKey
}

func newAuthority(name string) (*authority, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{certificate, der, private}, nil
}

func (a *authority) issue(name string, serial int64) (*tls.Certificate, error) {
	var public any
	var private any
	if os.Getenv("AEROBOX_ECH_CERT_ALGORITHM") == "p256" {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		public, private = &key.PublicKey, key
	} else {
		var err error
		public, private, err = ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
		DNSNames:  []string{name},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, a.certificate, public, a.key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der, a.der}, PrivateKey: private}, nil
}

func length16(bytes []byte) []byte {
	result := binary.BigEndian.AppendUint16(nil, uint16(len(bytes)))
	return append(result, bytes...)
}

func generateECH(id byte) (tls.EncryptedClientHelloKey, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	// RFC 9849 ECHConfig with RFC 9180 X25519 / HKDF-SHA256 / AES-128-GCM.
	contents := []byte{id, 0, 0x20}
	contents = append(contents, length16(key.PublicKey().Bytes())...)
	contents = append(contents, length16([]byte{0, 1, 0, 1})...)
	contents = append(contents, 32, byte(len(publicName)))
	contents = append(contents, publicName...)
	contents = append(contents, 0, 0) // no ECHConfig extensions
	config := append([]byte{0xfe, 0x0d}, length16(contents)...)
	return tls.EncryptedClientHelloKey{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}, nil
}

func writePEM(dir, name, kind string, bytes []byte) error {
	return os.WriteFile(filepath.Join(dir, name), pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: bytes}), 0600)
}

func prepare(dir, transport, mode string) (*tls.Config, *observer, error) {
	early := os.Getenv("AEROBOX_ECH_EARLY_DATA") == "1"
	if transport != "tcp" && transport != "quic" {
		return nil, nil, fmt.Errorf("invalid transport %q", transport)
	}
	if mode != "accept" && mode != "rotate" && mode != "reject" && mode != "badpublic" {
		return nil, nil, fmt.Errorf("invalid mode %q", mode)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	trusted, err := newAuthority("AeroBox ECH fixture trusted CA")
	if err != nil {
		return nil, nil, err
	}
	privateCertificate, err := trusted.issue(privateName, 2)
	if err != nil {
		return nil, nil, err
	}
	publicAuthority := trusted
	if mode == "badpublic" {
		publicAuthority, err = newAuthority("AeroBox ECH fixture UNTRUSTED CA")
		if err != nil {
			return nil, nil, err
		}
	}
	publicCertificate, err := publicAuthority.issue(publicName, 3)
	if err != nil {
		return nil, nil, err
	}
	oldKey, err := generateECH(1)
	if err != nil {
		return nil, nil, err
	}
	current, err := generateECH(2)
	if err != nil {
		return nil, nil, err
	}
	old, active := length16(oldKey.Config), length16(current.Config)
	initial := active
	if early || mode == "rotate" || mode == "badpublic" {
		initial = old
	}
	for _, file := range []struct {
		name, kind string
		bytes      []byte
	}{
		{"ca.pem", "CERTIFICATE", trusted.der},
		{"public.pem", "CERTIFICATE", publicCertificate.Certificate[0]},
		{"secret.pem", "CERTIFICATE", privateCertificate.Certificate[0]},
		{"config-old.pem", "ECH CONFIGS", old},
		{"config.pem", "ECH CONFIGS", active},
		{"initial-config.pem", "ECH CONFIGS", initial},
	} {
		if err := writePEM(dir, file.name, file.kind, file.bytes); err != nil {
			return nil, nil, err
		}
	}
	observer, err := newObserver(dir, transport, mode)
	if err != nil {
		return nil, nil, err
	}
	config := &tls.Config{
		MinVersion: tls.VersionTLS13, NextProtos: []string{peerALPN},
		SessionTicketsDisabled: !early,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			switch hello.ServerName {
			case privateName:
				return privateCertificate, nil
			case publicName:
				return publicCertificate, nil
			default:
				return nil, fmt.Errorf("unexpected SNI %q", hello.ServerName)
			}
		},
	}
	if alpn := os.Getenv("AEROBOX_ECH_ALPN"); alpn != "" {
		config.NextProtos = []string{alpn}
	}
	if curve := os.Getenv("AEROBOX_ECH_CURVE"); curve != "" {
		group, err := strconv.ParseUint(curve, 10, 16)
		if err != nil {
			return nil, nil, err
		}
		config.CurvePreferences = []tls.CurveID{tls.CurveID(group)}
	}
	if os.Getenv("AEROBOX_ECH_TICKETS") == "1" {
		config.SessionTicketsDisabled = false
	}
	// The old private key is deliberately never installed in the server.
	if mode != "reject" {
		config.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{current}
	}
	if early {
		// A stable ticket key survives the per-connection TLS clones. Tests
		// switch the ECH key only after receiving a ticket from the old key.
		var ticketKey [32]byte
		if _, err := rand.Read(ticketKey[:]); err != nil {
			return nil, nil, err
		}
		config.SetSessionTicketKeys([][32]byte{ticketKey})
		config.GetEncryptedClientHelloKeys = func(_ *tls.ClientHelloInfo) ([]tls.EncryptedClientHelloKey, error) {
			if _, err := os.Stat(filepath.Join(dir, "switch")); err != nil || mode == "accept" {
				return []tls.EncryptedClientHelloKey{oldKey}, nil
			}
			if mode == "reject" {
				return []tls.EncryptedClientHelloKey{}, nil
			}
			return []tls.EncryptedClientHelloKey{current}, nil
		}
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if early {
			// Test-controlled barrier: let the Rust client produce real early
			// writes before the server completes TLS, without timing races.
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				if _, err := os.Stat(filepath.Join(dir, "hold-handshake")); err != nil {
					break
				}
				time.Sleep(time.Millisecond)
			}
		}
		id, err := observer.begin(hello.ServerName)
		if err != nil {
			return nil, err
		}
		connection := config.Clone()
		connection.GetConfigForClient = nil
		connection.VerifyConnection = func(state tls.ConnectionState) error {
			return observer.parameters(id, state)
		}
		return connection, nil
	}
	return config, observer, nil
}

func echo(stream io.ReadWriter, observer *observer) {
	observer.update(func(state *statistics) { state.Streams++ })
	buffer := make([]byte, 8192)
	for {
		read, readErr := stream.Read(buffer)
		if read > 0 {
			for offset := 0; offset < read; {
				written, err := stream.Write(buffer[offset:read])
				observer.update(func(state *statistics) { state.EchoedBytes += int64(written) })
				if err != nil || written == 0 {
					return
				}
				offset += written
			}
		}
		if readErr != nil {
			return
		}
	}
}

func listen(transport string, config *tls.Config, observer *observer) (net.Addr, func() error, error) {
	if transport == "tcp" {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return nil, nil, err
		}
		go func() {
			for {
				wire, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer wire.Close()
					_ = wire.SetDeadline(time.Now().Add(30 * time.Second))
					connection := tls.Server(wire, config)
					if err := connection.Handshake(); err != nil {
						observer.update(func(state *statistics) { state.HandshakeErrors++ })
						return
					}
					if !connection.ConnectionState().ECHAccepted {
						return
					}
					observer.update(func(state *statistics) { state.Connections++ })
					echo(connection, observer)
				}()
			}
		}()
		return listener.Addr(), listener.Close, nil
	}
	quicConfig := &quic.Config{
		MaxIncomingStreams: 128, MaxIncomingUniStreams: -1,
		MaxIdleTimeout: 30 * time.Second, HandshakeIdleTimeout: 5 * time.Second,
	}
	if os.Getenv("AEROBOX_ECH_EARLY_DATA") == "1" {
		quicConfig.Allow0RTT = true
		quicConfig.GetConfigForClient = func(_ *quic.ClientInfo) (*quic.Config, error) {
			selected := quicConfig.Clone()
			selected.GetConfigForClient = nil
			_, reject := os.Stat(filepath.Join(observer.dir, "reject-early"))
			selected.Allow0RTT = reject != nil
			return selected, nil
		}
	}
	listener, err := quic.ListenAddr("127.0.0.1:0", config, quicConfig)
	if err != nil {
		return nil, nil, err
	}
	go func() {
		for {
			connection, err := listener.Accept(context.Background())
			if err != nil {
				return
			}
			if !connection.ConnectionState().TLS.ECHAccepted {
				_ = connection.CloseWithError(1, "ECH required")
				continue
			}
			observer.update(func(state *statistics) {
				state.Connections++
				if connection.ConnectionState().Used0RTT {
					state.EarlyConnections++
				}
			})
			go func() {
				for {
					stream, err := connection.AcceptStream(context.Background())
					if err != nil {
						return
					}
					go func() {
						defer stream.Close()
						defer stream.CancelRead(0)
						_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
						echo(stream, observer)
					}()
				}
			}()
		}
	}()
	return listener.Addr(), listener.Close, nil
}

func run() error {
	if len(os.Args) != 3 {
		return errors.New("usage: aerobox-ech-peer tcp|quic accept|rotate|reject|badpublic")
	}
	dir := os.Getenv("AEROBOX_PEER_CERT_DIR")
	if dir == "" {
		return errors.New("set AEROBOX_PEER_CERT_DIR to an isolated test directory")
	}
	config, observer, err := prepare(dir, os.Args[1], os.Args[2])
	if err != nil {
		return err
	}
	address, closeListener, err := listen(os.Args[1], config, observer)
	if err != nil {
		return err
	}
	defer closeListener()
	switch address := address.(type) {
	case *net.TCPAddr:
		fmt.Println(address.Port)
	case *net.UDPAddr:
		fmt.Println(address.Port)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	<-ctx.Done()
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
