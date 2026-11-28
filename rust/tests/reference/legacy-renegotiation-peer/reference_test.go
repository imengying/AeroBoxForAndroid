package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tls "github.com/metacubex/utls"
)

type fixtureClient interface {
	io.Reader
	io.Writer
	Close() error
	CloseWrite() error
	Handshake() error
	ConnectionState() tls.ConnectionState
	AeroBoxFixtureExportKeyingMaterial() ([]byte, error)
}

type exchangeResult struct {
	server serverResult
	err    error
}

func exercise(t *testing.T, version, suite uint16, profile, mode string, mutual bool) (serverResult, error) {
	t.Helper()
	fixtures := os.Getenv("AEROBOX_TLS_FIXTURES")
	if fixtures == "" {
		t.Fatal("AEROBOX_TLS_FIXTURES must name the public certificate fixtures")
	}
	cfg, err := configuration(fixtures, suite, version)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	finished := make(chan exchangeResult, 1)
	hellosPath := filepath.Join(t.TempDir(), "hellos.json")
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			finished <- exchangeResult{err: err}
			return
		}
		result, err := serve(raw, cfg, mode, mutual, hellosPath)
		finished <- exchangeResult{server: result, err: err}
	}()
	raw, err := net.Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		t.Fatal(err)
	}
	clientConfig := cfg.Clone()
	clientConfig.NextProtos = []string{"h2", "http/1.1"}
	var c fixtureClient
	switch profile {
	case "go":
		c = tls.Client(raw, clientConfig)
	case "edge":
		c = tls.UClient(raw, clientConfig, tls.HelloEdge_85)
	case "qq":
		c = tls.UClient(raw, clientConfig, tls.HelloQQ_11_1)
	default:
		t.Fatalf("unknown fixture profile %q", profile)
	}
	run := func() error {
		if err := c.Handshake(); err != nil {
			return err
		}
		if state := c.ConnectionState(); state.Version != version || state.CipherSuite != suite || state.NegotiatedProtocol != "h2" {
			return fmt.Errorf("unexpected initial parameters: %#v", state)
		}
		old, err := checkMarker(c, "initial")
		if err != nil {
			return err
		}
		if _, err := c.Write([]byte("ack")); err != nil {
			return err
		}
		if mode == "inflight" || mode == "inflight-fragment" {
			oldData := make([]byte, 8)
			if _, err := io.ReadFull(c, oldData); err != nil {
				return err
			}
			if !bytes.Equal(oldData, []byte("old-data")) {
				return errors.New("incorrect old epoch application data")
			}
		}
		renewed, err := checkMarker(c, "renewed")
		if err != nil {
			return err
		}
		if bytes.Equal(old, renewed) {
			return errors.New("unchanged exporter after renegotiation")
		}
		if mode == "repeat" {
			var b [1]byte
			_, err := c.Read(b[:])
			return err
		}
		expectedALPN := "h2"
		if mode == "changed-alpn" {
			expectedALPN = "http/1.1"
		}
		if state := c.ConnectionState(); state.Version != version || state.CipherSuite != suite || state.NegotiatedProtocol != expectedALPN {
			return fmt.Errorf("unexpected renewed parameters: %#v", state)
		}
		data := bytes.Repeat([]byte{42}, 65537)
		if _, err := io.Copy(c, bytes.NewReader(data)); err != nil {
			return err
		}
		out := make([]byte, len(data))
		if _, err := io.ReadFull(c, out); err != nil {
			return err
		}
		if !bytes.Equal(data, out) {
			return errors.New("echo mismatch")
		}
		if err := c.CloseWrite(); err != nil {
			return err
		}
		var extra [1]byte
		n, err := c.Read(extra[:])
		if n != 0 || err != io.EOF {
			return fmt.Errorf("expected close_notify, read=%d error=%v", n, err)
		}
		return nil
	}
	err = run()
	_ = c.Close()
	var server exchangeResult
	select {
	case server = <-finished:
	case <-time.After(22 * time.Second):
		t.Fatal("reference server did not terminate")
	}
	if err == nil {
		if server.err != nil {
			t.Fatalf("client succeeded but server failed: %v; trace=%v", server.err, server.server.Trace)
		}
		if server.server.Handshakes != 2 || server.server.EchoedBytes != 65537 || mutual && server.server.ClientCertificates != 1 {
			t.Fatalf("incomplete successful exchange: %+v", server.server)
		}
		rawHellos, readErr := os.ReadFile(hellosPath)
		var hellos []string
		if readErr != nil || json.Unmarshal(rawHellos, &hellos) != nil || len(hellos) != 2 {
			t.Fatalf("expected initial and renegotiated hello: %s; %v", rawHellos, readErr)
		}
	}
	t.Logf("client_error=%v server=%+v", err, server.server)
	return server.server, err
}

func requireTLSFailure(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		t.Fatal("malformed handshake accepted")
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		t.Fatalf("timeout is not a verified protocol rejection: %v", err)
	}
	if !strings.Contains(err.Error(), "tls:") {
		t.Fatalf("expected a TLS protocol failure, got %v", err)
	}
}

func TestValidVersionsCiphersAndClientAuthentication(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		suites := []uint16{0xc013, 0xc014, 0x002f, 0x0035}
		if version == tls.VersionTLS12 {
			suites = append(suites, 0xc02f, 0xc030, 0x009c, 0x009d, 0xcca8)
		}
		for _, profile := range []string{"go", "edge", "qq"} {
			for _, mutual := range []bool{false, true} {
				for _, suite := range suites {
					t.Run(fmt.Sprintf("%04x/%s/%04x/mtls=%t", version, profile, suite, mutual), func(t *testing.T) {
						_, err := exercise(t, version, suite, profile, "valid", mutual)
						if err != nil {
							t.Fatal(err)
						}
					})
				}
			}
		}
	}
}

func TestFaultsAndSecondRequest(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, profile := range []string{"go", "edge", "qq"} {
			for _, mode := range []string{"bad-binding", "bad-server-binding", "short-binding", "omit-binding", "initial-nonempty", "changed-certificate", "changed-version", "bad-finished", "early-data", "repeat"} {
				t.Run(fmt.Sprintf("%04x/%s/%s", version, profile, mode), func(t *testing.T) {
					_, err := exercise(t, version, 0xc013, profile, mode, true)
					requireTLSFailure(t, err)
				})
			}
		}
	}
}

func TestFragmentationAndConsistentNoEMS(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, profile := range []string{"go", "edge", "qq"} {
			for _, mode := range []string{"fragment", "no-ems"} {
				t.Run(fmt.Sprintf("%04x/%s/%s", version, profile, mode), func(t *testing.T) {
					_, err := exercise(t, version, 0xc013, profile, mode, true)
					if err != nil {
						t.Fatal(err)
					}
				})
			}
		}
	}
}

// These source-visible upstream policies are deliberately characterized, not
// presented as safe Rust behavior. Rust must reject changes to ALPN/EMS and
// renegotiation following an initial handshake without a secure binding.
func TestReferencePermissivePolicyLimits(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, profile := range []string{"go", "edge", "qq"} {
			for _, mode := range []string{"changed-alpn", "ems-downgrade", "initial-no-binding"} {
				t.Run(fmt.Sprintf("%04x/%s/%s", version, profile, mode), func(t *testing.T) {
					_, err := exercise(t, version, 0xc013, profile, mode, true)
					if err != nil {
						t.Fatalf("upstream limitation changed; review the reference assumptions: %v", err)
					}
				})
			}
		}
	}
}

// Go's old client rejects application data while its handshake flag is false,
// even before the incoming ChangeCipherSpec. The fixture must still prove
// which outgoing epoch carried the injected bytes; Rust tests require success.
func TestReferenceOldEpochReceiveLimit(t *testing.T) {
	for _, version := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		for _, mode := range []string{"inflight", "inflight-fragment"} {
			t.Run(fmt.Sprintf("%04x/%s", version, mode), func(t *testing.T) {
				result, err := exercise(t, version, 0xc013, "go", mode, true)
				requireTLSFailure(t, err)
				for i, event := range result.Trace {
					if event == "old-epoch-application-data" && i+1 < len(result.Trace) && result.Trace[i+1] == "server-change-cipher-spec" {
						return
					}
				}
				t.Fatalf("old-epoch injection was not before CCS: %v", result.Trace)
			})
		}
	}
}

func TestInvalidVersionAndSuite(t *testing.T) {
	for _, text := range []string{"", "1.3", "SSL3", "0x0301"} {
		if _, err := parseVersion(text); err == nil {
			t.Fatalf("invalid version accepted: %q", text)
		}
	}
	if _, err := configuration("unused", 0xc02f, tls.VersionTLS10); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("AEAD for TLS1.0 not rejected before fixture reads: %v", err)
	}
}
