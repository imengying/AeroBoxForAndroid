// Independent, test-only TLS 1.2 renegotiation driver for the pinned uTLS fork.
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
	tls "github.com/metacubex/utls"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

var fixtureDir = flag.String("fixtures", "../../../crates/aerobox-crypto/tests/fixtures", "public certificate fixtures")
var modeFlag = flag.String("mode", "valid", "fixture behavior")
var suiteFlag = flag.Uint("suite", 0xc02f, "TLS 1.2 cipher suite")
var mutualFlag = flag.Bool("mutual", false, "request a client certificate during renegotiation")
var resumeFirst = flag.Bool("resume-first", false, "seed a ticket on the first of two connections")
var helloFile = flag.String("hellos", "", "write captured ClientHellos")
var fixtureNow = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)

func configuration(fixtures string, suite uint16) (*tls.Config, error) {
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
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key, Leaf: cert}}, RootCAs: roots, ClientCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite}, NextProtos: []string{"h2"}, Time: func() time.Time { return fixtureNow }, SessionTicketsDisabled: true, Renegotiation: tls.RenegotiateOnceAsClient}, nil
}
func marker(c *tls.Conn, name string) error {
	key, err := c.AeroBoxFixtureExportKeyingMaterial()
	if err != nil {
		return err
	}
	_, err = c.Write(append([]byte(name), key...))
	return err
}
func serve(raw net.Conn, config *tls.Config, mode string, mutual bool, helloPath string) error {
	defer raw.Close()
	_ = raw.SetDeadline(time.Now().Add(15 * time.Second))
	c := tls.Server(raw, config)
	if mode == "initial-no-binding" || mode == "initial-nonempty" || mode == "no-ems" || mode == "fragment" {
		c.AeroBoxFixtureMode(mode)
	}
	defer func() {
		if helloPath != "" {
			out := []string{}
			for _, h := range c.AeroBoxFixtureHellos() {
				out = append(out, hex.EncodeToString(h))
			}
			b, _ := json.Marshal(out)
			_ = os.WriteFile(helloPath, b, 0600)
		}
	}()
	if err := c.Handshake(); err != nil {
		return err
	}
	if mode == "resumed" && !c.ConnectionState().DidResume {
		return errors.New("expected initial resumed connection")
	}
	if err := marker(c, "initial"); err != nil {
		return err
	}
	ack := make([]byte, 3)
	if _, err := io.ReadFull(c, ack); err != nil {
		return err
	}
	if string(ack) != "ack" {
		return errors.New("missing phase acknowledgement")
	}
	if mode == "seed" {
		_, err := io.Copy(c, c)
		if err == nil {
			err = c.Close()
		}
		return err
	}
	next := config.Clone()
	if mutual {
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
			return err
		}
		next.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: next.Certificates[0].PrivateKey}}
	}
	if mode == "changed-alpn" {
		next.NextProtos = []string{"http/1.1"}
	}
	if err := c.AeroBoxFixtureRenegotiate(next, mode); err != nil {
		return err
	}
	if mutual && len(c.ConnectionState().PeerCertificates) == 0 {
		return errors.New("missing renegotiated client certificate")
	}
	if err := marker(c, "renewed"); err != nil {
		return err
	}
	if mode == "repeat" {
		return c.AeroBoxFixtureRenegotiate(next, mode)
	}
	_, err := io.Copy(c, c)
	if err == nil {
		err = c.Close()
	}
	return err
}
func main() {
	flag.Parse()
	cfg, err := configuration(*fixtureDir, uint16(*suiteFlag))
	if err != nil {
		panic(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	number, _ := strconv.Atoi(port)
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"port": number})
	if *resumeFirst {
		cfg.SessionTicketsDisabled = false
		conn, err := listener.Accept()
		if err == nil {
			err = serve(conn, cfg, "seed", false, "")
		}
		if err != nil {
			panic(err)
		}
	}
	conn, err := listener.Accept()
	if err == nil {
		err = serve(conn, cfg, *modeFlag, *mutualFlag, *helloFile)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		fmt.Fprintln(os.Stderr, err)
	}
}
func checkMarker(c interface {
	Read([]byte) (int, error)
	AeroBoxFixtureExportKeyingMaterial() ([]byte, error)
}, name string) ([]byte, error) {
	b := make([]byte, len(name)+32)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	key, err := c.AeroBoxFixtureExportKeyingMaterial()
	if err != nil {
		return nil, err
	}
	if string(b[:len(name)]) != name || !bytes.Equal(b[len(name):], key) {
		return nil, errors.New("exporter/marker mismatch")
	}
	return key, nil
}
