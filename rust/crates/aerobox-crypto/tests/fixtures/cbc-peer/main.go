// Independent CBC-only Go TLS 1.2 server. Test tool, never a product dependency.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

func main() {
	if len(os.Args) != 3 {
		panic("usage: cbc-peer DIRECTORY CIPHER_ID")
	}
	directory := os.Args[1]
	number, err := strconv.ParseUint(os.Args[2], 10, 16)
	if err != nil {
		panic(err)
	}
	var credentials tls.Certificate
	var root []byte
	if fixtureDir := os.Getenv("AEROBOX_RSA_CERT_DIR"); fixtureDir != "" {
		credentials, err = tls.LoadX509KeyPair(filepath.Join(fixtureDir, "leaf.pem"), filepath.Join(fixtureDir, "key.pem"))
		if err != nil {
			panic(err)
		}
		root, err = os.ReadFile(filepath.Join(fixtureDir, "ca.der"))
		if err != nil {
			panic(err)
		}
	} else {
		var key crypto.Signer
		switch uint16(number) {
		case tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA, tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_256_GCM_SHA384:
			key, err = rsa.GenerateKey(rand.Reader, 2048)
		case tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		default:
			panic("unsupported fixture cipher")
		}
		if err != nil {
			panic(err)
		}
		certificate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "cbc.aerobox.test"}, DNSNames: []string{"cbc.aerobox.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
		staticRSA := uint16(number) == tls.TLS_RSA_WITH_AES_128_CBC_SHA || uint16(number) == tls.TLS_RSA_WITH_AES_256_CBC_SHA || uint16(number) == tls.TLS_RSA_WITH_AES_128_GCM_SHA256 || uint16(number) == tls.TLS_RSA_WITH_AES_256_GCM_SHA384
		if staticRSA && os.Getenv("AEROBOX_RSA_BAD_USAGE") == "" {
			// Key transport needs keyEncipherment, not digitalSignature.
			certificate.KeyUsage = x509.KeyUsageKeyEncipherment
		}
		der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, key.Public(), key)
		if err != nil {
			panic(err)
		}
		credentials = tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
		root = der
	}
	if err = os.WriteFile(filepath.Join(directory, "root.der"), root, 0600); err != nil {
		panic(err)
	}
	if err = os.WriteFile(filepath.Join(directory, "certificate.der"), credentials.Certificate[0], 0600); err != nil {
		panic(err)
	}
	if os.Getenv("AEROBOX_TLS_STAPLE") == "1" {
		credentials.OCSPStaple = []byte{1, 2, 3, 4}
	}
	credentials.SignedCertificateTimestamps = [][]byte{[]byte("opaque test timestamp")}
	config := &tls.Config{Certificates: []tls.Certificate{credentials}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{uint16(number)}}
	config.DynamicRecordSizingDisabled = true
	if os.Getenv("AEROBOX_TLS_MUTUAL") == "1" {
		config.ClientAuth = tls.RequireAnyClientCert
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		panic(err)
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"port": listener.Addr().(*net.TCPAddr).Port}); err != nil {
		panic(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			c := conn.(*tls.Conn)
			if err := c.Handshake(); err != nil {
				return
			}
			state := c.ConnectionState()
			// Echoing a typed header confirms the independently negotiated
			// cipher and resumption state without polling a statistics file.
			resumed := byte(0)
			if state.DidResume {
				resumed = 1
			}
			if _, err := c.Write([]byte{byte(state.CipherSuite >> 8), byte(state.CipherSuite), resumed}); err != nil {
				return
			}
			_, _ = io.Copy(c, c)
		}()
	}
}
