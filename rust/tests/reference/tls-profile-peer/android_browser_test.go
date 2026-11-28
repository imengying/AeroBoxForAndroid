package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func TestAndroidBrowserTLS13Reference(t *testing.T) {
	directory := os.Getenv("AEROBOX_TLS_FIXTURES")
	if directory == "" {
		directory = "../../../crates/aerobox-crypto/tests/fixtures"
	}
	certDER, keyDER := fixtureFiles(directory)
	root, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	clock := func() time.Time { return time.Unix(1893456000, 0) }
	clientCert, err := browserClientCertificate(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, profile := range []string{"standard", "safari", "ios"} {
		for _, group := range []uint16{29, 25} {
			for _, mutual := range []bool{false, true} {
				for _, compressed := range []bool{false, true} {
					if compressed && profile != "safari" {
						continue
					}
					t.Run(fmt.Sprintf("%s/group%d/mutual%t/zlib%t", profile, group, mutual, compressed), func(t *testing.T) {
						options := peerOptions{Group: group, Mutual: mutual, Compress: compressed,
							CompressionAlgorithm: 1, BrowserExchange: true, ClientCertificate: clientCert}
						if profile != "standard" {
							options.ExpectedShares = []uint16{29}
						}
						left, right := net.Pipe()
						defer left.Close()
						defer right.Close()
						_ = left.SetDeadline(time.Now().Add(45 * time.Second))
						type completion struct {
							result peerResult
							err    error
						}
						finished := make(chan completion, 1)
						go func() {
							result, err := serveWire(right, certDER, keyDER, options)
							finished <- completion{result, err}
						}()
						var client tlsClient
						var export func() ([]byte, error)
						if profile == "standard" {
							config := &tls.Config{ServerName: "localhost", RootCAs: roots, Time: clock,
								MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
								CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP521}, NextProtos: []string{"h2"}}
							if mutual {
								config.Certificates = []tls.Certificate{{Certificate: [][]byte{clientCert}, PrivateKey: private}}
							}
							conn := tls.Client(left, config)
							client = conn
							export = func() ([]byte, error) {
								state := conn.ConnectionState()
								if state.Version != tls.VersionTLS13 || state.CipherSuite != tls.TLS_AES_128_GCM_SHA256 || len(state.VerifiedChains) == 0 {
									return nil, fmt.Errorf("unexpected standard TLS state")
								}
								return state.ExportKeyingMaterial(browserExporterLabel, browserExporterContext, 32)
							}
						} else {
							config := &utls.Config{ServerName: "localhost", RootCAs: roots, Time: clock}
							if mutual {
								config.Certificates = []utls.Certificate{{Certificate: [][]byte{clientCert}, PrivateKey: private}}
							}
							id := utls.HelloSafari_16_0
							if profile == "ios" {
								id = utls.HelloIOS_14
							}
							conn := utls.UClient(left, config, id)
							client = conn
							export = func() ([]byte, error) {
								state := conn.ConnectionState()
								if state.Version != utls.VersionTLS13 || state.CipherSuite != utls.TLS_AES_128_GCM_SHA256 || len(state.VerifiedChains) == 0 {
									return nil, fmt.Errorf("unexpected browser TLS state")
								}
								// uTLS blocks all exporters when the fingerprint enables
								// legacy renegotiation, even after negotiating TLS 1.3.
								// Only adjust this test-only API policy after verifying
								// TLS 1.3; no handshake bytes or peer verification change.
								config.Renegotiation = utls.RenegotiateNever
								state = conn.ConnectionState()
								return state.ExportKeyingMaterial(browserExporterLabel, browserExporterContext, 32)
							}
						}
						if err = client.Handshake(); err != nil {
							_ = left.Close()
							result := <-finished
							t.Fatalf("handshake: %v; peer: %v", err, result.err)
						}
						exporter, err := export()
						if err != nil {
							t.Fatal(err)
						}
						if err = writeAll(client, browserPattern(false)); err != nil {
							t.Fatal(err)
						}
						got := make([]byte, 36+browserPayloadBytes)
						if _, err = io.ReadFull(client, got); err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(got[:4], []byte("AB13")) || !bytes.Equal(got[4:36], exporter) || !bytes.Equal(got[36:], browserPattern(true)) {
							t.Fatal("exporter or application bytes differ")
						}
						if err = client.CloseWrite(); err != nil {
							t.Fatal(err)
						}
						if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
							t.Fatalf("server close_notify: %d %v", n, err)
						}
						outcome := <-finished
						if outcome.err != nil {
							t.Fatal(outcome.err)
						}
						if outcome.result.Group != group || outcome.result.HelloRetry != (group == 25) ||
							outcome.result.Exporter != hex.EncodeToString(exporter) || !outcome.result.CloseNotify ||
							outcome.result.ClientVerifiedChain != mutual || outcome.result.Compressed != compressed {
							t.Fatalf("unexpected result: %+v", outcome.result)
						}
					})
				}
			}
		}
	}
}

func TestP521ExchangeRejectsInvalidPointsAndMatchesGoECDH(t *testing.T) {
	client, err := ecdh.P521().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	server, secret, err := exchange(25, client.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	public, err := ecdh.P521().NewPublicKey(server)
	if err != nil {
		t.Fatal(err)
	}
	want, err := client.ECDH(public)
	if err != nil || len(secret) != 66 || !bytes.Equal(secret, want) {
		t.Fatalf("P521 shared secret mismatch: %v", err)
	}
	for _, invalid := range [][]byte{nil, {0}, bytes.Repeat([]byte{0}, 133), append([]byte{4}, bytes.Repeat([]byte{255}, 132)...)} {
		if _, _, err = exchange(25, invalid); err == nil {
			t.Fatalf("accepted invalid P521 point: %x", invalid)
		}
	}
}
