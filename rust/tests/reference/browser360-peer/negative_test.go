package main

import (
	"crypto/x509"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	tls "github.com/metacubex/utls"
)

// Force a properly authenticated EMS handshake to show that this fixture will
// not relabel a different handshake as 360/non-EMS or emit application markers.
func TestEMSCannotBeReportedAs360NonEMS(t *testing.T) {
	*fixtures = os.Getenv("AEROBOX_TLS_FIXTURES")
	*versionFlag, *suiteFlag, *mutualFlag, *bytesFlag, *ocspFlag, *sha1Flag = "1.2", 0xc013, "none", 4097, true, false
	config, err := configuration()
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(config.Certificates[0].Leaf)
	cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", Time: func() time.Time { return fixtureTime }}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		_, err = serve(conn, config)
		done <- err
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
				t.Error("peer cleanup timeout")
			}
		}
	}()
	if err = raw.SetDeadline(time.Now().Add(25 * time.Second)); err != nil {
		t.Fatal(err)
	}
	spec, err := tls.UTLSIdToSpec(tls.Hello360_7_5)
	if err != nil {
		t.Fatal(err)
	}
	spec.Extensions = append(spec.Extensions, &tls.ExtendedMasterSecretExtension{})
	client := tls.UClient(&observedConn{Conn: raw}, cfg, tls.HelloCustom)
	if err = client.ApplyPreset(&spec); err != nil {
		t.Fatal(err)
	}
	if err = client.Handshake(); err != nil {
		t.Fatal(err)
	}
	state := client.ConnectionState()
	if !state.HandshakeComplete || len(state.VerifiedChains) == 0 || state.CipherSuite != 0xc013 {
		t.Fatal("missing real authentication")
	}
	var marker [4]byte
	n, readErr := io.ReadFull(client, marker[:])
	if n != 0 || readErr == nil {
		t.Fatalf("wrong-policy application bytes: %d %v", n, readErr)
	}
	if timeout, ok := readErr.(net.Error); ok && timeout.Timeout() {
		t.Fatalf("timeout is not rejection: %v", readErr)
	}
	err = <-done
	completed = true
	if err == nil || !strings.Contains(err.Error(), "unexpectedly negotiated EMS") {
		t.Fatalf("wrong rejection: %v", err)
	}
}

func TestObservationDoesNotConfuseRawEOFWithCloseNotify(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			err = conn.Close()
		}
		closed <- err
	}()
	raw, err := net.DialTimeout("tcp4", listener.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err = raw.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	conn := &observedConn{Conn: raw}
	n, err := conn.Read(make([]byte, 1))
	if n != 0 || err == nil || err == io.EOF || !strings.Contains(err.Error(), "without authenticated TLS close_notify") {
		t.Fatalf("raw EOF: %d %v", n, err)
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
}
