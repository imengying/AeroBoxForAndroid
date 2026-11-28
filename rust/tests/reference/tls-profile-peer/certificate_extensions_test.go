package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

func TestCertificateExtensionFixturesRequireActualOffer(t *testing.T) {
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	parsed, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	private := parsed.(*rsa.PrivateKey)
	hello := clientHello{extensions: map[uint16][]byte{}}
	for _, o := range []peerOptions{{SCT: "valid"}, {OCSP: true}} {
		if _, err := certificateExtensionFixture(hello, o, cert, private); err == nil {
			t.Fatal("normal extension accepted without offer")
		}
	}
	for _, o := range []peerOptions{{UnsolicitedSCT: true}, {UnsolicitedOCSP: true}} {
		data, err := certificateExtensionFixture(hello, o, cert, private)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := extensions(vector16(data))
		if err != nil || len(decoded) != 1 {
			t.Fatalf("invalid extension framing: %v", err)
		}
	}
	hello.extensions[18] = nil
	hello.extensions[5] = []byte{1, 0, 0, 0, 0}
	for _, o := range []peerOptions{{UnsolicitedSCT: true}, {UnsolicitedOCSP: true}} {
		if _, err := certificateExtensionFixture(hello, o, cert, private); err == nil {
			t.Fatal("unsolicited fixture accepted an actual client offer")
		}
	}
	data, err := certificateExtensionFixture(hello, peerOptions{SCT: "valid", OCSP: true}, cert, private)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := extensions(vector16(data))
	if err != nil || len(decoded) != 2 {
		t.Fatalf("combined certificate extensions lost: %v", err)
	}
	response := reader{p: decoded[5]}
	if response.uint(1) != 1 {
		t.Fatal("wrong OCSP status type")
	}
	der := response.vector(3)
	if response.done() != nil {
		t.Fatal("OCSP framing")
	}
	issuer, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	status, err := ocsp.ParseResponse(der, issuer)
	if err != nil || status.Status != ocsp.Good || status.SerialNumber.Cmp(issuer.SerialNumber) != 0 {
		t.Fatalf("OCSP not authenticated: %v", err)
	}
	for _, o := range []peerOptions{{SCT: "valid", UnsolicitedSCT: true}, {OCSP: true, UnsolicitedOCSP: true}, {UnsolicitedSCT: true, Reality: "valid"}, {OCSP: true, Tickets: &ticketStore{}}} {
		if o.validateCertificateExtensionOptions() == nil {
			t.Fatal("accepted ambiguous extension fixture")
		}
	}
}

func TestReferenceNormalOCSPAndSCTCompleteAuthenticatedTLS(t *testing.T) {
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	issuer, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(issuer)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	type outcome struct {
		result peerResult
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		socket, err := listener.Accept()
		if err != nil {
			done <- outcome{err: err}
			return
		}
		r, e := serveWire(socket, cert, key, peerOptions{SCT: "valid", OCSP: true})
		done <- outcome{r, e}
	}()
	socket, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
	client := tls.Client(socket, &tls.Config{RootCAs: roots, ServerName: "localhost", Time: func() time.Time { return time.Unix(1893456000, 0) }, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
	if err = client.Handshake(); err != nil {
		_ = socket.Close()
		t.Fatalf("client: %v; server: %+v", err, <-done)
	}
	state := client.ConnectionState()
	status, err := ocsp.ParseResponse(state.OCSPResponse, issuer)
	if err != nil || status.Status != ocsp.Good || len(state.SignedCertificateTimestamps) != 2 || len(state.VerifiedChains) == 0 {
		t.Fatalf("authenticated certificate extension evidence lost: %v", err)
	}
	payload := bytes.Repeat([]byte{0x63}, 4097)
	if err = writeAll(client, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err = io.ReadFull(client, got); err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("echo: %v", err)
	}
	if err = client.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("close notify: %d %v", n, err)
	}
	_ = socket.Close()
	server := <-done
	if server.err != nil || server.result.Bytes != len(payload) {
		t.Fatalf("server: %+v", server)
	}
}

func TestNoALPNModeCannotSilentlyDiscardAnOffer(t *testing.T) {
	absent := clientHello{extensions: map[uint16][]byte{}}
	offered := clientHello{extensions: map[uint16][]byte{16: []byte{0, 3, 2, 'h', '2'}}}
	if checkPeerALPN(absent, peerOptions{AllowNoALPN: true, OmitALPN: true}) != nil {
		t.Fatal("valid absent ALPN rejected")
	}
	if checkPeerALPN(offered, peerOptions{}) != nil {
		t.Fatal("existing h2 mode changed")
	}
	if checkPeerALPN(absent, peerOptions{}) == nil {
		t.Fatal("default peer accepted absent ALPN")
	}
	for _, hello := range []clientHello{absent, offered} {
		for _, o := range []peerOptions{{AllowNoALPN: true}, {AllowNoALPN: true, OmitALPN: true, ALPS: 17513}} {
			if checkPeerALPN(hello, o) == nil {
				t.Fatal("missing explicit no-ALPN policy error")
			}
		}
	}
	if checkPeerALPN(offered, peerOptions{AllowNoALPN: true, OmitALPN: true}) == nil {
		t.Fatal("no-ALPN mode silently discarded a real offer")
	}
}
