// Independent, test-only TLS 1.0/1.1/1.2 renegotiation driver. Never a product dependency.
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	tls "github.com/metacubex/utls"
)

var fixtureDir = flag.String("fixtures", "../../../crates/aerobox-crypto/tests/fixtures", "public disposable certificate fixtures")
var recordFirst = flag.Int("record-first", -2, "initial receive limit; -2 disables fixture, -1 omits extension")
var recordSecond = flag.Int("record-second", -1, "renegotiated receive limit; -1 omits extension")
var recordAdvertised = flag.Uint("record-advertised", 16385, "required client record_size_limit")

var modeFlag = flag.String("mode", "valid", "fixture behavior; see README")
var versionFlag = flag.String("version", "1.2", "initial and valid renegotiation version: 1.0, 1.1 or 1.2")
var suiteFlag = flag.Uint("suite", 0, "cipher suite decimal or 0x hex; default c013 for old versions, c02f for 1.2")
var mutualFlag = flag.Bool("mutual", false, "require possession of the pinned RSA client key during renegotiation")
var helloFile = flag.String("hellos", "", "write captured plaintext ClientHellos as a JSON hex array")
var fixtureNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

const exporterLabel = "aerobox-renegotiation"
const maxEchoBytes = 1 << 20

func parseVersion(text string) (uint16, error) {
	switch text {
	case "1.0":
		return tls.VersionTLS10, nil
	case "1.1":
		return tls.VersionTLS11, nil
	case "1.2":
		return tls.VersionTLS12, nil
	default:
		return 0, fmt.Errorf("unsupported --version %q", text)
	}
}

func validMode(mode string) bool {
	switch mode {
	case "valid", "fragment", "inflight", "inflight-fragment", "no-ems", "ems-downgrade",
		"bad-binding", "bad-server-binding", "short-binding", "omit-binding", "initial-no-binding",
		"initial-nonempty", "changed-certificate", "changed-alpn", "changed-version", "bad-finished",
		"early-data", "repeat":
		return true
	default:
		return false
	}
}

func configuration(fixtures string, suite, version uint16) (*tls.Config, error) {
	if version < tls.VersionTLS10 || version > tls.VersionTLS12 {
		return nil, errors.New("fixture requires TLS 1.0, 1.1 or 1.2")
	}
	// Keep this fixture focused on the RSA-authenticated Edge/QQ cipher set.
	// No synthetic cipher advertisement and no AES-GCM on old versions.
	old := suite == 0xc013 || suite == 0xc014 || suite == 0x002f || suite == 0x0035
	modern := suite == 0xc02f || suite == 0xc030 || suite == 0x009c || suite == 0x009d || suite == 0xcca8
	if !old && !(version == tls.VersionTLS12 && modern) {
		return nil, fmt.Errorf("suite %#04x is unavailable for version %#04x in this fixture", suite, version)
	}
	certDER, err := os.ReadFile(filepath.Join(fixtures, "rsa-cert.der"))
	if err != nil {
		return nil, err
	}
	keyDER, err := os.ReadFile(filepath.Join(fixtures, "rsa-key.der"))
	if err != nil {
		return nil, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: cert}},
		RootCAs:      roots, ClientCAs: roots, ServerName: "localhost",
		MinVersion: version, MaxVersion: version, CipherSuites: []uint16{suite},
		NextProtos: []string{"h2"}, Time: func() time.Time { return fixtureNow },
		SessionTicketsDisabled: true, Renegotiation: tls.RenegotiateOnceAsClient,
	}, nil
}

func marker(c *tls.Conn, name string) error {
	key, err := c.AeroBoxFixtureExportKeyingMaterial()
	if err != nil {
		return err
	}
	_, err = c.Write(append([]byte(name), key...))
	return err
}

type serverResult struct {
	RecordCounts       [3]int   `json:"record_counts"`
	RecordMaximum      [3]int   `json:"record_maximum"`
	Phase              string   `json:"phase"`
	Mode               string   `json:"mode"`
	Version            uint16   `json:"version"`
	Cipher             uint16   `json:"cipher"`
	ALPN               string   `json:"alpn"`
	Handshakes         int      `json:"completed_handshakes"`
	ClientCertificates int      `json:"client_certificates"`
	EchoedBytes        int64    `json:"echoed_bytes"`
	Trace              []string `json:"trace"`
	Error              string   `json:"error,omitempty"`
}

func serve(raw net.Conn, config *tls.Config, mode string, mutual bool, helloPath string) (result serverResult, resultErr error) {
	result.Mode = mode
	result.Phase = "complete"
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		return result, err
	}
	c := tls.Server(raw, config)
	if *recordFirst >= -1 {
		if *recordFirst > 65535 || *recordSecond > 65535 || *recordSecond < -1 || *recordAdvertised > 65535 {
			return result, errors.New("invalid record limit fixture arguments")
		}
		c.AeroBoxFixtureRecordSize(*recordFirst, *recordSecond, uint16(*recordAdvertised))
	}
	if mode == "initial-no-binding" || mode == "initial-nonempty" || mode == "no-ems" || mode == "fragment" || mode == "inflight-fragment" {
		c.AeroBoxFixtureMode(mode)
	}
	defer func() {
		result.RecordCounts, result.RecordMaximum = c.AeroBoxFixtureRecordSizes()
		state := c.ConnectionState()
		result.Version, result.Cipher, result.ALPN = state.Version, state.CipherSuite, state.NegotiatedProtocol
		result.Handshakes = c.AeroBoxFixtureHandshakes()
		result.ClientCertificates = len(state.PeerCertificates)
		result.Trace = c.AeroBoxFixtureTrace()
		if helloPath != "" {
			hellos := []string{}
			for _, hello := range c.AeroBoxFixtureHellos() {
				hellos = append(hellos, hex.EncodeToString(hello))
			}
			out, err := json.Marshal(hellos)
			if err == nil {
				err = os.WriteFile(helloPath, out, 0600)
			}
			if resultErr == nil {
				resultErr = err
			}
		}
		if resultErr != nil {
			result.Phase, result.Error = "error", resultErr.Error()
		}
	}()
	if err := c.Handshake(); err != nil {
		return result, err
	}
	state := c.ConnectionState()
	if state.Version != config.MinVersion || state.CipherSuite != config.CipherSuites[0] || state.DidResume {
		return result, errors.New("unexpected initial version, cipher or resumption")
	}
	if err := marker(c, "initial"); err != nil {
		return result, err
	}
	ack := make([]byte, 3)
	if _, err := io.ReadFull(c, ack); err != nil {
		return result, err
	}
	if !bytes.Equal(ack, []byte("ack")) {
		return result, errors.New("missing phase acknowledgement")
	}
	next := config.Clone()
	if mutual {
		// Existing public fixtures have serverAuth EKU. Pin this disposable
		// leaf explicitly; CertificateVerify still proves possession of its key.
		next.ClientAuth = tls.RequireAnyClientCert
		next.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) != 1 || !bytes.Equal(raw[0], config.Certificates[0].Certificate[0]) {
				return errors.New("untrusted client fixture")
			}
			return nil
		}
	}
	if mode == "changed-certificate" {
		leaf := *next.Certificates[0].Leaf
		leaf.SerialNumber = new(big.Int).Add(leaf.SerialNumber, big.NewInt(1))
		der, err := x509.CreateCertificate(rand.Reader, &leaf, next.Certificates[0].Leaf, leaf.PublicKey, next.Certificates[0].PrivateKey)
		if err != nil {
			return result, err
		}
		next.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: next.Certificates[0].PrivateKey}}
	}
	if mode == "changed-alpn" {
		next.NextProtos = []string{"http/1.1"}
	}
	if err := c.AeroBoxFixtureRenegotiate(next, mode); err != nil {
		return result, err
	}
	if mutual && len(c.ConnectionState().PeerCertificates) == 0 {
		return result, errors.New("missing renegotiated client certificate")
	}
	if err := marker(c, "renewed"); err != nil {
		return result, err
	}
	if mode == "repeat" {
		return result, c.AeroBoxFixtureRenegotiate(next, mode)
	}
	// Bounded stream echo; callers normally send 65537 bytes and close_notify.
	count, err := io.CopyBuffer(c, io.LimitReader(c, maxEchoBytes+1), make([]byte, 16*1024))
	result.EchoedBytes = count
	if err != nil {
		return result, err
	}
	if count > maxEchoBytes {
		return result, errors.New("fixture echo limit exceeded")
	}
	return result, c.Close()
}

func run() error {
	flag.Parse()
	version, err := parseVersion(*versionFlag)
	if err != nil {
		return err
	}
	if !validMode(*modeFlag) || *suiteFlag > 65535 {
		return errors.New("unknown mode or cipher suite outside uint16")
	}
	suite := uint16(*suiteFlag)
	if suite == 0 {
		suite = 0xc013
		if version == tls.VersionTLS12 {
			suite = 0xc02f
		}
	}
	cfg, err := configuration(*fixtureDir, suite, version)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return err
	}
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(map[string]any{"phase": "ready", "port": number, "version": version, "cipher": suite, "mode": *modeFlag, "exporter_label": exporterLabel, "max_echo_bytes": maxEchoBytes}); err != nil {
		return err
	}
	raw, err := listener.Accept()
	if err != nil {
		return err
	}
	result, _ := serve(raw, cfg, *modeFlag, *mutualFlag, *helloFile)
	// Injected protocol faults are reported in terminal JSON, not hidden by a
	// nonzero exit status or presented as successful handshakes.
	return encoder.Encode(result)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func checkMarker(c interface {
	io.Reader
	AeroBoxFixtureExportKeyingMaterial() ([]byte, error)
}, name string) ([]byte, error) {
	buffer := make([]byte, len(name)+32)
	if _, err := io.ReadFull(c, buffer); err != nil {
		return nil, err
	}
	key, err := c.AeroBoxFixtureExportKeyingMaterial()
	if err != nil {
		return nil, err
	}
	if string(buffer[:len(name)]) != name || !bytes.Equal(buffer[len(name):], key) {
		return nil, errors.New("exporter/marker mismatch")
	}
	return key, nil
}
