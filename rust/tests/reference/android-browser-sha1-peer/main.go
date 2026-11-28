// Independent test-only TLS1.2 ECDSA-SHA1 peer for Android browser fingerprints.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	tls "github.com/metacubex/utls"
)

var fixturePath = flag.String("fixtures", "crates/aerobox-crypto/src/android_browser/sha1-fixtures.json", "public OpenSSL test fixture JSON")
var serverCurve = flag.String("server-curve", "P-256", "P-256, P-384 or P-521")
var clientCurve = flag.String("client-curve", "none", "none, P-256, P-384 or P-521")
var weakCertificate = flag.Bool("weak-certificate", false, "send SHA1-signed leaf for rejection tests")
var payloadBytes = flag.Int("bytes", 65537, "application bytes in each direction, 1..1048576")

var fixtureTime = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
var staple = []byte("AeroBox Android browser opaque OCSP transport fixture")

const exporterLabel = "aerobox android browser sha1 exporter"

var exporterContext = []byte{0, 'a', 'n', 'd', 'r', 'o', 'i', 'd', 0, 's', 'h', 'a', '1', 0}

type curveFixture struct {
	Curve      string `json:"curve"`
	Key        string `json:"key_der"`
	PublicSPKI string `json:"public_spki"`
	StrongCert string `json:"sha256_cert_der"`
	WeakCert   string `json:"sha1_cert_der"`
}

type fixtureSet struct {
	CA     string         `json:"ca_der"`
	Curves []curveFixture `json:"curves"`
}

func decodeHex(value string) ([]byte, error) {
	if len(value) == 0 || len(value) > 65536 {
		return nil, errors.New("fixture hex length")
	}
	return hex.DecodeString(value)
}

func loadFixtures(path string) (fixtureSet, string, error) {
	var fixtures fixtureSet
	file, err := os.Open(path)
	if err != nil {
		return fixtures, "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 131073))
	if err != nil {
		return fixtures, "", err
	}
	if len(data) > 131072 {
		return fixtures, "", errors.New("fixture file size limit")
	}
	if err = json.Unmarshal(data, &fixtures); err != nil {
		return fixtures, "", err
	}
	if len(fixtures.Curves) != 3 {
		return fixtures, "", errors.New("expected three curve fixtures")
	}
	sum := sha256.Sum256(data)
	return fixtures, hex.EncodeToString(sum[:]), nil
}

func certificate(fixtures fixtureSet, curve string, weak bool) (tls.Certificate, error) {
	if curve != "P-256" && curve != "P-384" && curve != "P-521" {
		return tls.Certificate{}, errors.New("unknown certificate curve")
	}
	for _, fixture := range fixtures.Curves {
		if fixture.Curve != curve {
			continue
		}
		encoded := fixture.StrongCert
		if weak {
			encoded = fixture.WeakCert
		}
		der, err := decodeHex(encoded)
		if err != nil {
			return tls.Certificate{}, err
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			return tls.Certificate{}, err
		}
		keyDER, err := decodeHex(fixture.Key)
		if err != nil {
			return tls.Certificate{}, err
		}
		private, err := x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			return tls.Certificate{}, err
		}
		key, ok := private.(*ecdsa.PrivateKey)
		if !ok || key.Curve.Params().Name != curve {
			return tls.Certificate{}, errors.New("wrong fixture private-key curve")
		}
		spki, err := x509.MarshalPKIXPublicKey(key.Public())
		if err != nil {
			return tls.Certificate{}, err
		}
		if !bytes.Equal(spki, leaf.RawSubjectPublicKeyInfo) || hex.EncodeToString(spki) != fixture.PublicSPKI {
			return tls.Certificate{}, errors.New("fixture key does not match leaf/SPKI")
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf,
			SupportedSignatureAlgorithms: []tls.SignatureScheme{tls.ECDSAWithSHA1}}, nil
	}
	return tls.Certificate{}, errors.New("missing certificate fixture")
}

func roots(fixtures fixtureSet) (*x509.CertPool, error) {
	der, err := decodeHex(fixtures.CA)
	if err != nil {
		return nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return pool, nil
}

func configuration(fixtures fixtureSet, server, client string, weak bool) (*tls.Config, error) {
	cert, err := certificate(fixtures, server, weak)
	if err != nil {
		return nil, err
	}
	pool, err := roots(fixtures)
	if err != nil {
		return nil, err
	}
	if !weak {
		if _, err = cert.Leaf.Verify(x509.VerifyOptions{Roots: pool, DNSName: "localhost",
			CurrentTime: fixtureTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return nil, fmt.Errorf("strong server fixture: %w", err)
		}
	}
	cert.OCSPStaple = staple
	config := &tls.Config{
		Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256}, SessionTicketsDisabled: true,
		CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256, tls.CurveP384, tls.CurveP521},
		Time:             func() time.Time { return fixtureTime },
	}
	if client != "none" {
		clientCert, err := certificate(fixtures, client, false)
		if err != nil {
			return nil, err
		}
		if _, err = clientCert.Leaf.Verify(x509.VerifyOptions{Roots: pool,
			CurrentTime: fixtureTime, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
			return nil, fmt.Errorf("strong client fixture: %w", err)
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 || len(state.VerifiedChains) == 0 ||
				!bytes.Equal(state.PeerCertificates[0].Raw, clientCert.Certificate[0]) {
				return errors.New("missing or unexpected authenticated client identity")
			}
			return nil
		}
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

func serve(raw net.Conn, config *tls.Config, server, client string, size int) (map[string]any, error) {
	defer raw.Close()
	if size < 1 || size > 1048576 {
		return nil, errors.New("payload size limit")
	}
	if err := raw.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		return nil, err
	}
	observed := &observedConn{Conn: raw}
	conn := tls.Server(observed, config)
	if err := conn.Handshake(); err != nil {
		return observed.report(), err
	}
	result := observed.report()
	if err := observed.validate(client != "none"); err != nil {
		return result, err
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS12 || state.CipherSuite != tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ||
		state.DidResume || state.NegotiatedProtocol != "" {
		return result, errors.New("unexpected negotiated TLS state")
	}
	exporter, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
	if err != nil {
		return result, fmt.Errorf("EMS exporter: %w", err)
	}
	written := make(chan error, 1)
	serverData := pattern(size, true)
	go func() {
		_, err := io.Copy(conn, bytes.NewReader(append([]byte("ABS1"), exporter...)))
		if err == nil {
			_, err = io.Copy(conn, bytes.NewReader(serverData))
		}
		written <- err
	}()
	clientData := make([]byte, size)
	if _, err = io.ReadFull(conn, clientData); err != nil {
		return result, err
	}
	if !bytes.Equal(clientData, pattern(size, false)) {
		return result, errors.New("client payload mismatch")
	}
	if err = <-written; err != nil {
		return result, err
	}
	var extra [1]byte
	if n, err := conn.Read(extra[:]); n != 0 || err != io.EOF {
		return result, fmt.Errorf("expected client close_notify, read=%d err=%v", n, err)
	}
	if err = conn.Close(); err != nil {
		return result, err
	}
	clientHash, serverHash := sha256.Sum256(clientData), sha256.Sum256(serverData)
	result["phase"], result["version"], result["cipher"] = "complete", state.Version, state.CipherSuite
	result["server_curve"], result["client_curve"] = server, client
	result["client_certificates"], result["verified_client_chains"] = len(state.PeerCertificates), len(state.VerifiedChains)
	result["bytes_each_direction"], result["exporter"] = size, hex.EncodeToString(exporter)
	result["client_sha256"], result["server_sha256"] = hex.EncodeToString(clientHash[:]), hex.EncodeToString(serverHash[:])
	result["close_notify_received"], result["resumed"] = true, false
	return result, nil
}

func run() (map[string]any, error) {
	flag.Parse()
	tls.AeroBoxForceECDSASHA1Fixture()
	fixtures, fixtureHash, err := loadFixtures(*fixturePath)
	if err != nil {
		return nil, err
	}
	config, err := configuration(fixtures, *serverCurve, *clientCurve, *weakCertificate)
	if err != nil {
		return nil, err
	}
	if *payloadBytes < 1 || *payloadBytes > 1048576 {
		return nil, errors.New("--bytes out of bounds")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
		return nil, err
	}
	ready := map[string]any{"phase": "ready", "port": listener.Addr().(*net.TCPAddr).Port,
		"fixture_sha256": fixtureHash, "server_curve": *serverCurve, "client_curve": *clientCurve,
		"weak_certificate": *weakCertificate}
	if err = json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		return nil, err
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		return nil, err
	}
	return serve(conn, config, *serverCurve, *clientCurve, *payloadBytes)
}

func main() {
	result, err := run()
	if result == nil {
		result = make(map[string]any)
	}
	if err != nil {
		result["phase"], result["error"] = "error", err.Error()
	}
	if encodeErr := json.NewEncoder(os.Stdout).Encode(result); encodeErr != nil {
		fmt.Fprintln(os.Stderr, encodeErr)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
