// Independent non-EMS server for the 13 real default 360 7.5 cipher suites.
// Pinned uTLS v1.8.7, without EnableWeakCiphers or any algorithm registration shim.
package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	tls "github.com/metacubex/utls"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

var fixtures = flag.String("fixtures", "crates/aerobox-crypto/tests/fixtures", "existing public certificate/key fixture directory")
var versionFlag = flag.String("version", "1.0", "exact TLS version: 1.0, 1.1 or 1.2")
var suiteFlag = flag.Uint("suite", 0xc013, "one exact cipher suite, decimal or 0x-prefixed")
var mutualFlag = flag.String("mutual", "none", "required client certificate: none, rsa or ecdsa")
var bytesFlag = flag.Int("bytes", 65537, "application bytes in each direction, 1..1048576")
var ocspFlag = flag.Bool("ocsp", true, "send and assert an opaque test-only OCSP staple")
var sha1Flag = flag.Bool("rsa-sha1", false, "force TLS1.2 ECDHE_RSA ServerKeyExchange to use RSA/SHA1")

var fixtureTime = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
var staple = []byte("AeroBox Android11 opaque OCSP transport fixture")
var clientCertificateDER []byte

const exporterLabel = "aerobox 360 non-EMS exporter forbidden"

var exporterContext = []byte{0, 'a', 'n', 'd', 'r', 'o', 'i', 'd', '1', '1', 0}

func certificate(kind string) (tls.Certificate, error) {
	der, err := os.ReadFile(filepath.Join(*fixtures, kind+"-cert.der"))
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := os.ReadFile(filepath.Join(*fixtures, kind+"-key.der"))
	if err != nil {
		return tls.Certificate{}, err
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, nil
}

func clientCertificate(kind string) (tls.Certificate, error) {
	// The existing RSA/P-256 fixtures have serverAuth only. Reuse their public
	// test keys but issue an explicit clientAuth certificate, so Go performs
	// normal chain/purpose/proof-of-possession checks for mutual authentication.
	keyPair, err := certificate(kind)
	if err != nil {
		return tls.Certificate{}, err
	}
	signer, ok := keyPair.PrivateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, errors.New("fixture key cannot sign a client certificate")
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(202611231),
		Subject:               pkix.Name{CommonName: "aerobox-android11-" + kind + "-client"},
		NotBefore:             time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:              time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: signer, Leaf: leaf}, nil
}

func configuration() (*tls.Config, error) {
	versions := map[string]uint16{"1.0": tls.VersionTLS10, "1.1": tls.VersionTLS11, "1.2": tls.VersionTLS12}
	version, ok := versions[*versionFlag]
	if !ok {
		return nil, errors.New("unsupported --version")
	}
	if *suiteFlag > 65535 {
		return nil, errors.New("cipher suite exceeds u16")
	}
	suite := uint16(*suiteFlag)
	var kind string
	switch suite {
	case 0xc00a, 0xc007, 0xc009, 0xc023:
		kind = "ecdsa"
	case 0xc014, 0x0035, 0xc011, 0xc013, 0xc027, 0x0005, 0x002f, 0x003c, 0x000a:
		kind = "rsa"
	default:
		return nil, errors.New("suite is outside the 13 default real 360 implementations")
	}
	if version < tls.VersionTLS12 {
		switch suite {
		case 0xc00a, 0xc014, 0x0035, 0xc007, 0xc009, 0xc011, 0xc013, 0x0005, 0x002f, 0x000a:
		default:
			return nil, errors.New("SHA2-CBC suites require TLS1.2")
		}
	}
	if *bytesFlag < 1 || *bytesFlag > 1048576 {
		return nil, errors.New("--bytes out of bounds")
	}
	cert, err := certificate(kind)
	if err != nil {
		return nil, err
	}
	if *ocspFlag {
		cert.OCSPStaple = staple
	}
	if *sha1Flag {
		if version != tls.VersionTLS12 || (suite != 0xc013 && suite != 0xc014 && suite != 0xc011 && suite != 0xc027) {
			return nil, errors.New("--rsa-sha1 requires a TLS1.2 ECDHE_RSA suite")
		}
		cert.SupportedSignatureAlgorithms = []tls.SignatureScheme{tls.PKCS1WithSHA1}
	}
	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: version, MaxVersion: version,
		CipherSuites: []uint16{suite}, SessionTicketsDisabled: true,
		CurvePreferences: []tls.CurveID{tls.CurveP256, tls.CurveP384, tls.CurveP521},
		NextProtos:       []string{"http/1.1"},
		Time:             func() time.Time { return fixtureTime },
	}
	switch *mutualFlag {
	case "none":
	case "rsa", "ecdsa":
		client, err := clientCertificate(*mutualFlag)
		if err != nil {
			return nil, err
		}
		config.ClientCAs = x509.NewCertPool()
		config.ClientCAs.AddCert(client.Leaf)
		clientCertificateDER = client.Certificate[0]
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 || len(state.VerifiedChains) == 0 || !bytes.Equal(state.PeerCertificates[0].Raw, client.Certificate[0]) {
				return errors.New("missing or unexpected authenticated client certificate")
			}
			return nil
		}
	default:
		return nil, errors.New("unsupported --mutual")
	}
	return config, nil
}

func pattern(size int, server bool) []byte {
	out := make([]byte, size)
	for i := range out {
		if server {
			out[i] = byte((i*29 + 7) % 251)
		} else {
			out[i] = byte((i*17 + 3) % 251)
		}
	}
	return out
}

func serve(raw net.Conn, config *tls.Config) (map[string]any, error) {
	defer raw.Close()
	if err := raw.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		return nil, err
	}
	observed := &observedConn{Conn: raw}
	conn := tls.Server(observed, config)
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if state.Version != config.MinVersion || state.CipherSuite != config.CipherSuites[0] || state.DidResume || state.NegotiatedProtocol != "http/1.1" {
		return nil, errors.New("unexpected negotiated TLS parameters")
	}
	if !observed.serverHelloSeen {
		return nil, errors.New("missing independent ServerHello observation")
	}
	if observed.err != nil {
		return nil, observed.err
	}
	if observed.extendedMasterSecret {
		return nil, errors.New("360 unexpectedly negotiated EMS")
	}
	if *ocspFlag && (!observed.ocspNegotiated || !bytes.Equal(observed.ocspResponse, staple)) {
		return nil, errors.New("client did not request or server did not transmit the OCSP fixture")
	}
	_, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
	if err == nil {
		return nil, errors.New("non-EMS exporter unexpectedly succeeded")
	}
	// Concurrent output means each endpoint can stream independently; memory is
	// bounded by the configured payload size and normal TLS/TCP buffers.
	written := make(chan error, 1)
	serverData := pattern(*bytesFlag, true)
	go func() {
		_, err := io.Copy(conn, bytes.NewReader([]byte("B360")))
		if err == nil {
			_, err = io.Copy(conn, bytes.NewReader(serverData))
		}
		written <- err
	}()
	clientData := make([]byte, *bytesFlag)
	if _, err = io.ReadFull(conn, clientData); err != nil {
		return nil, err
	}
	if !bytes.Equal(clientData, pattern(*bytesFlag, false)) {
		return nil, errors.New("client payload mismatch")
	}
	if err = <-written; err != nil {
		return nil, err
	}
	// Require authenticated close_notify, not a silent TCP truncation. The
	// client sends close_notify after reading the known B360/data size.
	var extra [1]byte
	n, err := conn.Read(extra[:])
	if n != 0 || err != io.EOF {
		return nil, fmt.Errorf("expected client close_notify, read=%d err=%v", n, err)
	}
	if err = conn.Close(); err != nil {
		return nil, err
	}
	clientHash, serverHash := sha256.Sum256(clientData), sha256.Sum256(serverData)
	return map[string]any{
		"phase": "complete", "version": state.Version, "cipher": state.CipherSuite,
		"client_certificates":    len(state.PeerCertificates),
		"verified_client_chains": len(state.VerifiedChains), "mutual": *mutualFlag,
		"bytes_each_direction": *bytesFlag, "client_sha256": hex.EncodeToString(clientHash[:]),
		"server_sha256": hex.EncodeToString(serverHash[:]), "exporter_rejected": true, "alpn": state.NegotiatedProtocol,
		"ems": observed.extendedMasterSecret, "ocsp": *ocspFlag, "server_hello_observed": observed.serverHelloSeen,
		"rsa_sha1": *sha1Flag, "close_notify_received": true, "resumed": false,
	}, nil
}

func run() error {
	flag.Parse()
	config, err := configuration()
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		return err
	}
	ready := map[string]any{"phase": "ready", "port": listener.Addr().(*net.TCPAddr).Port}
	if len(clientCertificateDER) != 0 {
		ready["client_certificate_der_hex"] = hex.EncodeToString(clientCertificateDER)
	}
	if err = json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		return err
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	result, err := serve(conn, config)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "error", "error": err.Error()})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
