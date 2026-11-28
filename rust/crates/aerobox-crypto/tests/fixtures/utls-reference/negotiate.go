package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	utls "github.com/metacubex/utls"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

func fixture(rsa bool) (tls.Certificate, utls.Certificate, []byte) {
	name := "ecdsa"
	if rsa {
		name = "rsa"
	}
	root := os.Getenv("AEROBOX_CRYPTO_FIXTURES")
	if root == "" {
		root = ".."
	}
	cert, err := os.ReadFile(filepath.Join(root, name+"-cert.der"))
	if err != nil {
		panic(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, name+"-key.der"))
	if err != nil {
		panic(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(raw)
	if err != nil {
		panic(err)
	}
	return tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}, utls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}, cert
}
func negotiate() {
	rsaServer, clientCert, rsaDER := fixture(true)
	ecdsaServer, _, ecdsaDER := fixture(false)
	roots := x509.NewCertPool()
	for _, der := range [][]byte{rsaDER, ecdsaDER} {
		c, e := x509.ParseCertificate(der)
		if e != nil {
			panic(e)
		}
		roots.AddCert(c)
	}
	clock := func() time.Time { return time.Unix(1893456000, 0) }
	type testCase struct {
		name                 string
		version, cipher      uint16
		ecdsa, mutual, cache bool
		modify               func(*utls.Config)
	}
	cases := []testCase{
		{name: "tls10", version: tls.VersionTLS10, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{name: "tls11", version: tls.VersionTLS11, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA},
		{name: "tls12", version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
		{name: "tls10_despite_min13", version: tls.VersionTLS10, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, modify: func(c *utls.Config) { c.MinVersion = utls.VersionTLS13; c.MaxVersion = utls.VersionTLS13 }},
		{name: "cipher_override_ignored", version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, ecdsa: true, modify: func(c *utls.Config) { c.CipherSuites = []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} }},
		{name: "group_override_ignored", version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, modify: func(c *utls.Config) { c.CurvePreferences = []utls.CurveID{utls.CurveP521} }},
		{name: "client_auth", version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, mutual: true},
		{name: "resumption_with_explicit_cache", version: tls.VersionTLS12, cipher: tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, cache: true},
	}
	var results []map[string]any
	for _, tc := range cases {
		cert := rsaServer
		if tc.ecdsa {
			cert = ecdsaServer
		}
		serverConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tc.version, MaxVersion: tc.version, CipherSuites: []uint16{tc.cipher}, CurvePreferences: []tls.CurveID{tls.X25519}, Time: clock}
		if tc.mutual {
			serverConfig.ClientAuth = tls.RequireAnyClientCert
		}
		clientConfig := &utls.Config{ServerName: "localhost", RootCAs: roots, Time: clock}
		if tc.cache {
			clientConfig.ClientSessionCache = utls.NewLRUClientSessionCache(4)
		}
		if tc.mutual {
			clientConfig.Certificates = []utls.Certificate{clientCert}
		}
		if tc.modify != nil {
			tc.modify(clientConfig)
		}
		for iteration := 0; iteration < 2; iteration++ {
			left, right := net.Pipe()
			_ = left.SetDeadline(time.Now().Add(3 * time.Second))
			_ = right.SetDeadline(time.Now().Add(3 * time.Second))
			server := tls.Server(right, serverConfig)
			serverDone := make(chan map[string]any, 1)
			go func() {
				defer right.Close()
				err := server.Handshake()
				result := map[string]any{"server_error": errString(err)}
				if err == nil {
					state := server.ConnectionState()
					result["version"] = state.Version
					result["suite"] = state.CipherSuite
					result["resumed"] = state.DidResume
					result["client_certificates"] = len(state.PeerCertificates)
					var bytes [4]byte
					if _, err = io.ReadFull(server, bytes[:]); err == nil {
						_, err = server.Write(bytes[:])
					}
					result["server_transfer_error"] = errString(err)
				}
				serverDone <- result
			}()
			client := utls.UClient(left, clientConfig.Clone(), utls.HelloAndroid_11_OkHttp)
			err := client.Handshake()
			result := map[string]any{"case": tc.name, "iteration": iteration, "client_error": errString(err)}
			if err == nil {
				_, err = client.Write([]byte("echo"))
				var data [4]byte
				if err == nil {
					_, err = io.ReadFull(client, data[:])
				}
				result["client_transfer_error"] = errString(err)
				result["echo"] = string(data[:])
			}
			_ = left.Close()
			for k, v := range <-serverDone {
				result[k] = v
			}
			results = append(results, result)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		panic(err)
	}
}
