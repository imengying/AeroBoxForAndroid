package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

type dynamicOutcome struct {
	result peerResult
	err    error
}

func dynamicTestServer(t *testing.T, options peerOptions) (net.Conn, <-chan dynamicOutcome) {
	t.Helper()
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	done := make(chan dynamicOutcome, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- dynamicOutcome{err: err}
			return
		}
		r, e := serveDynamicReality(conn, cert, key, options)
		done <- dynamicOutcome{r, e}
	}()
	conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	return conn, done
}
func dynamicTestExchange(t *testing.T, client tlsClient, exporter []byte, done <-chan dynamicOutcome, options peerOptions) {
	t.Helper()
	written := make(chan error, 1)
	go func() { written <- writeAll(client, browserPattern(false)) }()
	response := make([]byte, 36+browserPayloadBytes)
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response[:4], []byte("RR13")) || !bytes.Equal(response[4:36], exporter) || !bytes.Equal(response[36:], browserPattern(true)) {
		t.Fatal("dynamic exporter or server payload mismatch")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if err := client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("close notify: %d %v", n, err)
	}
	server := <-done
	if server.err != nil || server.result.Suite != options.RealitySuite || server.result.Bytes != browserPayloadBytes || !server.result.CloseNotify || server.result.ALPS != options.ALPS {
		t.Fatalf("dynamic server: %+v", server)
	}
	if options.Reality != "" && !server.result.RealityAuthenticated {
		t.Fatal("missing REALITY metadata authentication")
	}
}

func TestDynamicStandardGoChecksAllThreeSuitesHashesRetryExporterAndClose(t *testing.T) {
	cert, _ := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	issuer, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	for _, suite := range []uint16{0x1301, 0x1302, 0x1303} {
		for _, group := range []uint16{29, 24} {
			for _, noALPN := range []bool{false, true} {
				t.Run(fmt.Sprintf("suite%x_group%d_noalpn%v", suite, group, noALPN), func(t *testing.T) {
					options := peerOptions{RealitySuite: suite, RealityExchange: true, Group: group, AllowNoALPN: noALPN, OmitALPN: noALPN}
					socket, done := dynamicTestServer(t, options)
					cfg := &tls.Config{ServerName: "localhost", RootCAs: roots, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP384}, Time: func() time.Time { return time.Unix(1893456000, 0) }}
					if !noALPN {
						cfg.NextProtos = []string{"h2"}
					}
					client := tls.Client(socket, cfg)
					if err := client.Handshake(); err != nil {
						_ = socket.Close()
						t.Fatalf("client=%v server=%+v", err, <-done)
					}
					state := client.ConnectionState()
					if state.Version != tls.VersionTLS13 || state.CipherSuite != suite || len(state.VerifiedChains) == 0 {
						t.Fatal("incorrect verified TLS state")
					}
					exporter, err := state.ExportKeyingMaterial(realityExporterLabel, realityExporterContext, 32)
					if err != nil {
						t.Fatal(err)
					}
					dynamicTestExchange(t, client, exporter, done, options)
				})
			}
		}
	}
}

func TestDynamicSuiteSelectionDoesNotRequireAES128(t *testing.T) {
	for _, id := range []uint16{0x1302, 0x1303} {
		offer := binary.BigEndian.AppendUint16(nil, id)
		offer = append(offer, 0xc0, 0x2f)
		suite, err := selectDynamicSuite(offer, 0)
		if err != nil || suite.id != id {
			t.Fatalf("suite %x: %v", id, err)
		}
		if _, err := selectDynamicSuite(offer, 0x1301); err == nil {
			t.Fatal("unoffered explicit suite accepted")
		}
	}
	for _, id := range []uint16{0, 0x1301, 0x1302, 0x1303, 0xffff} {
		if _, err := selectDynamicSuite([]byte{0xc0, 0x2f}, id); err == nil {
			t.Fatal("missing TLS13 offer accepted")
		}
	}
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		s, err := getDynamicSuite(id)
		if err != nil {
			t.Fatal(err)
		}
		want := 32
		if id == 0x1302 {
			want = 48
		}
		if len(s.digest(nil)) != want || len(s.finished(make([]byte, want), nil)) != want {
			t.Fatal("wrong suite hash length")
		}
		a, err := s.protect(bytes.Repeat([]byte{7}, want))
		if err != nil {
			t.Fatal(err)
		}
		b, err := s.protect(bytes.Repeat([]byte{7}, want))
		if err != nil {
			t.Fatal(err)
		}
		var wire bytes.Buffer
		if err = a.write(&wire, 23, []byte("authenticated record")); err != nil {
			t.Fatal(err)
		}
		tampered := append([]byte(nil), wire.Bytes()...)
		tampered[len(tampered)-1] ^= 1
		if _, _, err = b.read(bytes.NewReader(tampered)); err == nil {
			t.Fatal("AEAD tag corruption accepted")
		}
	}
}

func TestUnsolicitedALPNFaultRequiresAbsentOfferAndPreservesDefault(t *testing.T) {
	absent := clientHello{extensions: map[uint16][]byte{}}
	offered := clientHello{extensions: map[uint16][]byte{16: []byte{0, 3, 2, 'h', '2'}}}
	if checkPeerALPN(absent, peerOptions{UnsolicitedALPN: true}) != nil {
		t.Fatal("explicit malicious mode rejected")
	}
	if checkPeerALPN(offered, peerOptions{UnsolicitedALPN: true}) == nil {
		t.Fatal("malicious mode accepted an actual offer")
	}
	for _, o := range []peerOptions{{UnsolicitedALPN: true, AllowNoALPN: true}, {UnsolicitedALPN: true, OmitALPN: true}, {UnsolicitedALPN: true, ALPS: 17513}, {UnsolicitedALPN: true, SelectedALPN: "http/1.1"}} {
		if checkPeerALPN(absent, o) == nil {
			t.Fatal("ambiguous ALPN fault accepted")
		}
	}
	if checkPeerALPN(absent, peerOptions{}) == nil {
		t.Fatal("default h2 check changed")
	}
}

func TestDynamicRandomizedRealityAllSuitesAndNoAES128Plan(t *testing.T) {
	witnesses := append([]struct {
		name, seed string
		alpn, alps bool
	}{}, randomizedRealityWitnesses...)
	witnesses = append(witnesses, struct {
		name, seed string
		alpn, alps bool
	}{"no-aes128", "52750ada4d78dca017937cf13dfb96cecbd47f810e80750fdf22e3d08fedc4b4", false, false})
	suitesCovered := map[uint16]bool{}
	for _, witness := range witnesses {
		for _, suite := range []uint16{0x1301, 0x1302, 0x1303} {
			// The independent pinned generator, rather than this peer, determines the
			// fixed witness capability. Unknown or mismatched requested suites fail.
			profile := randomizedRealityProfile(t, witness.seed)
			spec, err := utls.UTLSIdToSpec(profile)
			if err != nil {
				t.Fatal(err)
			}
			offered := false
			for _, id := range spec.CipherSuites {
				offered = offered || id == suite
			}
			if !offered {
				continue
			}
			for _, group := range []uint16{29, 24} {
				t.Run(fmt.Sprintf("%s_suite%x_group%d", witness.name, suite, group), func(t *testing.T) {
					options := peerOptions{Reality: "valid", RealityBrowser: true, RealityProfile: "randomized", RealitySuite: suite, RealityExchange: true, Group: group}
					if witness.alps {
						options.ALPS = 17513
					}
					if !witness.alpn {
						options.AllowNoALPN, options.OmitALPN = true, true
					}
					socket, done := dynamicTestServer(t, options)
					cfg := &utls.Config{ServerName: "cover.test", InsecureSkipVerify: true, SessionTicketsDisabled: true}
					client, err := realityClientWithProfileAndConfig(socket, true, profile, cfg)
					if err != nil {
						t.Fatal(err)
					}
					if err = client.Handshake(); err != nil {
						_ = socket.Close()
						t.Fatalf("client=%v server=%+v", err, <-done)
					}
					state := client.ConnectionState()
					if state.Version != tls.VersionTLS13 || state.CipherSuite != suite {
						t.Fatal("unexpected authenticated REALITY TLS state")
					}
					// Pinned uTLS disables its exporter API for any renegotiation setting,
					// even after authenticated TLS1.3. Only change that test API policy after
					// this completed TLS1.3 handshake; wire bytes and verifier stay untouched.
					cfg.Renegotiation = utls.RenegotiateNever
					state = client.ConnectionState()
					exporter, err := state.ExportKeyingMaterial(realityExporterLabel, realityExporterContext, 32)
					if err != nil {
						t.Fatal(err)
					}
					dynamicTestExchange(t, client, exporter, done, options)
					suitesCovered[suite] = true
				})
			}
		}
	}
	if len(suitesCovered) != 3 {
		t.Fatalf("missing suite coverage: %v", suitesCovered)
	}
}
