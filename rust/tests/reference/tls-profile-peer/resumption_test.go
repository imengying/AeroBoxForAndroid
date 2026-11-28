package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

func TestReferenceResumption(t *testing.T) {
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	root, err := x509.ParseCertificate(cert)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	private, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	clock := func() time.Time { return time.Unix(1893456000, 0) }
	for _, group := range []uint16{29, 24} {
		for _, browser := range []bool{false, true} {
			name := "standard_go"
			if browser {
				name = "chrome133_custom_psk"
			}
			t.Run(fmt.Sprintf("%s_group_%d", name, group), func(t *testing.T) {
				options := peerOptions{Tickets: &ticketStore{}, Mutual: true, Group: group}
				if browser {
					options.ALPS = 17613
					options.Compress = true
					options.ServerSettings = []byte("server settings")
				}
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				goConfig := &tls.Config{ServerName: "localhost", RootCAs: roots, Time: clock, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}, ClientSessionCache: tls.NewLRUClientSessionCache(4)}
				uConfig := &utls.Config{ServerName: "localhost", RootCAs: roots, Time: clock, ClientSessionCache: utls.NewLRUClientSessionCache(4), OmitEmptyPsk: true}
				goConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: private}}
				uConfig.Certificates = []utls.Certificate{{Certificate: [][]byte{cert}, PrivateKey: private}}
				for iteration := 0; iteration < 3; iteration++ {
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
						result, err := serveWire(socket, cert, key, options)
						done <- outcome{result, err}
					}()
					socket, err := net.Dial("tcp", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
					var client tlsClient
					var resumed func() bool
					if browser {
						uc := utls.UClient(socket, uConfig, utls.HelloCustom)
						spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
						if err != nil {
							t.Fatal(err)
						}
						spec.Extensions = append(spec.Extensions, &utls.UtlsPreSharedKeyExtension{})
						if err = uc.ApplyPreset(&spec); err != nil {
							t.Fatal(err)
						}
						client = uc
						resumed = func() bool { return uc.ConnectionState().DidResume }
					} else {
						standard := tls.Client(socket, goConfig)
						client = standard
						resumed = func() bool { return standard.ConnectionState().DidResume }
					}
					if err = client.Handshake(); err != nil {
						socket.Close()
						server := <-done
						if browser && group == 24 && iteration == 1 && server.err != nil &&
							strings.Contains(err.Error(), "uTLS does not support reprocessing of PSK key triggered by HelloRetryRequest") {
							t.Log("confirmed pinned uTLS limitation: PSK + HelloRetryRequest is unsupported")
							return
						}
						t.Fatalf("iteration %d handshake: %v; server %v", iteration, err, server.err)
					}
					if browser && group == 24 && iteration == 1 {
						client.Close()
						t.Fatal("pinned uTLS PSK + HRR behavior changed; reassess this expected limitation")
					}
					payload := bytes.Repeat([]byte{31}, 65537)
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
						t.Fatalf("close: %v", err)
					}
					socket.Close()
					server := <-done
					if server.err != nil || resumed() != (iteration > 0) || server.result.Resumed != (iteration > 0) {
						t.Fatalf("iteration %d: resume=%v server=%+v", iteration, resumed(), server)
					}
				}
			})
		}
	}
}
