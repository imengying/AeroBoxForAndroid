package main

import (
	"bytes"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	tls "github.com/metacubex/utls"
)

// Both endpoints use the independent Go implementation. Restricting signatures
// does not replace transcript hashing, ECDSA verification or x509 validation.
func TestThreeServerCurvesAndFourClientIdentities(t *testing.T) {
	tls.AeroBoxForceECDSASHA1Fixture()
	fixtures, _, err := loadFixtures(os.Getenv("AEROBOX_ANDROID_BROWSER_SHA1_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := roots(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, server := range []string{"P-256", "P-384", "P-521"} {
		for _, client := range []string{"none", "P-256", "P-384", "P-521"} {
			t.Run(fmt.Sprintf("%s/%s", server, client), func(t *testing.T) {
				config, err := configuration(fixtures, server, client, false)
				if err != nil {
					t.Fatal(err)
				}
				clientConfig := &tls.Config{RootCAs: pool, ServerName: "localhost",
					MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
					CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
					Time:         func() time.Time { return fixtureTime }}
				if client != "none" {
					cert, err := certificate(fixtures, client, false)
					if err != nil {
						t.Fatal(err)
					}
					clientConfig.Certificates = []tls.Certificate{cert}
				}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				if err = b.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
					t.Fatal(err)
				}
				type result struct {
					report map[string]any
					err    error
				}
				done := make(chan result, 1)
				go func() {
					report, err := serve(a, config, server, client, 65537)
					done <- result{report, err}
				}()
				conn := tls.Client(b, clientConfig)
				if err = conn.Handshake(); err != nil {
					t.Fatal(err)
				}
				state := conn.ConnectionState()
				if len(state.VerifiedChains) == 0 || state.Version != tls.VersionTLS12 ||
					state.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 {
					t.Fatalf("unexpected authenticated state: %+v", state)
				}
				exporter, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = io.Copy(conn, bytes.NewReader(pattern(65537, false))); err != nil {
					t.Fatal(err)
				}
				data := make([]byte, 36+65537)
				if _, err = io.ReadFull(conn, data); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(data[:4], []byte("ABS1")) || !bytes.Equal(data[4:36], exporter) ||
					!bytes.Equal(data[36:], pattern(65537, true)) {
					t.Fatal("exporter or application data mismatch")
				}
				if err = conn.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				var extra [1]byte
				if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
					t.Fatalf("expected server close_notify: %d %v", n, err)
				}
				finished := <-done
				if finished.err != nil {
					t.Fatal(finished.err)
				}
				if finished.report["phase"] != "complete" || finished.report["exporter"] != hex.EncodeToString(exporter) {
					t.Fatalf("unexpected report: %+v", finished.report)
				}
			})
		}
	}
}

func handshakeRecord(kind byte, body []byte) []byte {
	message := []byte{kind, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	message = append(message, body...)
	return append([]byte{22, 3, 3, byte(len(message) >> 8), byte(len(message))}, message...)
}

func TestObserverHandlesFragmentsAndRejectsMalformedSignatures(t *testing.T) {
	// ECDHE params + 0203 + a nonempty synthetic signature; this exercises only
	// the observer's framing, while the 12 live cases exercise real signatures.
	record := handshakeRecord(12, []byte{3, 0, 29, 1, 9, 2, 3, 0, 1, 7})
	var observer handshakeObserver
	for _, b := range record {
		observer.observe([]byte{b}, true)
	}
	if observer.err != nil || observer.serverKeys != 1 || observer.serverSignature != 0x0203 {
		t.Fatalf("fragmented ServerKeyExchange: %+v", observer)
	}
	for _, body := range [][]byte{
		{}, {3, 0, 29, 255, 0, 0, 0, 0}, {3, 0, 29, 0, 2, 3, 0, 9, 1},
	} {
		var invalid handshakeObserver
		invalid.observe(handshakeRecord(12, body), true)
		if invalid.err == nil {
			t.Fatalf("accepted malformed ServerKeyExchange: %x", body)
		}
	}
}

func TestSHA1SignedLeafRemainsUntrustedUnderTheCorrectRoot(t *testing.T) {
	fixtures, _, err := loadFixtures(os.Getenv("AEROBOX_ANDROID_BROWSER_SHA1_FIXTURES"))
	if err != nil {
		t.Fatal(err)
	}
	pool, err := roots(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		cert, err := certificate(fixtures, curve, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost",
			CurrentTime: fixtureTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
			t.Fatalf("trusted SHA1-signed %s leaf", curve)
		}
	}
}
