package main

import (
	"bytes"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	tls "github.com/metacubex/utls"
)

// Sequential and bounded: one TCP connection and at most 64 KiB application
// payload per endpoint. The CLI flags are fixture process state, never parallel.
func TestFixed360DefaultRealSuites(t *testing.T) {
	*fixtures = os.Getenv("AEROBOX_TLS_FIXTURES")
	if *fixtures == "" {
		t.Fatal("AEROBOX_TLS_FIXTURES is required")
	}
	*ocspFlag, *sha1Flag, *bytesFlag = true, false, 4097
	for _, version := range []string{"1.0", "1.1", "1.2"} {
		for _, suite := range []uint{0xc00a, 0xc014, 0x0035, 0xc007, 0xc009, 0xc023, 0xc011, 0xc013, 0xc027, 0x0005, 0x002f, 0x003c, 0x000a} {
			if version != "1.2" && (suite == 0xc023 || suite == 0xc027 || suite == 0x003c) {
				continue
			}
			for _, mutual := range []string{"none", "rsa", "ecdsa"} {
				t.Run(fmt.Sprintf("%s/%04x/%s", version, suite, mutual), func(t *testing.T) {
					*versionFlag, *suiteFlag, *mutualFlag = version, suite, mutual
					clientCertificateDER = nil
					config, err := configuration()
					if err != nil {
						t.Fatal(err)
					}
					roots := x509.NewCertPool()
					roots.AddCert(config.Certificates[0].Leaf)
					cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", Time: func() time.Time { return fixtureTime }}
					if mutual != "none" {
						cert, err := certificate(mutual)
						if err != nil {
							t.Fatal(err)
						}
						cert.Certificate = [][]byte{append([]byte(nil), clientCertificateDER...)}
						cert.Leaf, err = x509.ParseCertificate(clientCertificateDER)
						if err != nil {
							t.Fatal(err)
						}
						cfg.Certificates = []tls.Certificate{cert}
					}
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					type outcome struct {
						report map[string]any
						err    error
					}
					done := make(chan outcome, 1)
					go func() {
						conn, err := listener.Accept()
						if err != nil {
							done <- outcome{nil, err}
							return
						}
						result, err := serve(conn, config)
						done <- outcome{result, err}
					}()
					raw, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					completed := false
					defer func() {
						_ = raw.Close()
						if !completed {
							select {
							case <-done:
							case <-time.After(30 * time.Second):
								t.Error("peer did not terminate after closing transport")
							}
						}
					}()
					if err = raw.SetDeadline(time.Now().Add(25 * time.Second)); err != nil {
						t.Fatal(err)
					}
					client := tls.UClient(&observedConn{Conn: raw}, cfg, tls.Hello360_7_5)
					if err = client.Handshake(); err != nil {
						t.Fatal(err)
					}
					state := client.ConnectionState()
					if state.CipherSuite != uint16(suite) || state.Version != config.MinVersion || state.DidResume || len(state.VerifiedChains) == 0 || state.NegotiatedProtocol != "http/1.1" {
						t.Fatalf("unexpected authenticated state: %+v", state)
					}
					if !bytes.Equal(state.OCSPResponse, staple) {
						t.Fatal("missing OCSP transport evidence")
					}
					// Change only the test export policy after authentication;
					// this cannot alter the already transmitted 360 hello. The
					// remaining exporter refusal must come from absent EMS.
					cfg.Renegotiation = tls.RenegotiateNever
					state = client.ConnectionState()
					if _, err = state.ExportKeyingMaterial(exporterLabel, nil, 32); err == nil {
						t.Fatal("non-EMS exporter succeeded")
					}
					if _, err = client.Write(pattern(*bytesFlag, false)); err != nil {
						t.Fatal(err)
					}
					reply := make([]byte, 4+*bytesFlag)
					if _, err = io.ReadFull(client, reply); err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(reply[:4], []byte("B360")) || !bytes.Equal(reply[4:], pattern(*bytesFlag, true)) {
						t.Fatal("server data mismatch")
					}
					if err = client.CloseWrite(); err != nil {
						t.Fatal(err)
					}
					var extra [1]byte
					if n, err := client.Read(extra[:]); n != 0 || err != io.EOF {
						t.Fatalf("server close: %d %v", n, err)
					}
					result := <-done
					completed = true
					if result.err != nil {
						t.Fatal(result.err)
					}
					if result.report["ems"] != false || result.report["exporter_rejected"] != true || result.report["close_notify_received"] != true {
						t.Fatalf("report %+v", result.report)
					}
					_ = client.Close()
				})
			}
		}
	}
}

func TestAdvertisedOnlySuitesAndInvalidVersionsNeverListen(t *testing.T) {
	*versionFlag, *mutualFlag, *bytesFlag = "1.2", "none", 4097
	for _, suite := range []uint{0x0039, 0x006b, 0x003d, 0x0033, 0x0067, 0x0032, 0x0004, 0x1301, 65536} {
		*suiteFlag = suite
		if _, err := configuration(); err == nil {
			t.Fatalf("unsupported suite accepted: %x", suite)
		}
	}
	for _, version := range []string{"1.0", "1.1"} {
		for _, suite := range []uint{0xc023, 0xc027, 0x003c} {
			*versionFlag, *suiteFlag = version, suite
			if _, err := configuration(); err == nil {
				t.Fatalf("SHA2-CBC accepted on %s/%x", version, suite)
			}
		}
	}
}
