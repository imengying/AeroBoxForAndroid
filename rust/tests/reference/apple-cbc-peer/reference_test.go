package main

import (
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	tls "github.com/metacubex/utls"
)

// Exercise actual independent handshakes and application records for every
// added registry entry. Sequential: the CLI fixture's flags are process state.
func TestNineCBCSuitesWithIndependentGoClient(t *testing.T) {
	tls.AeroBoxEnableAppleCipherFixtures()
	*fixtures = os.Getenv("AEROBOX_TLS_FIXTURES")
	*ocspFlag = false
	*mutualFlag = "none"
	for _, version := range []string{"1.0", "1.1", "1.2"} {
		for _, suite := range []uint16{0xc023, 0xc024, 0xc027, 0xc028, 0x003c, 0x003d, 0xc008, 0xc012, 0x000a} {
			if version != "1.2" && suite != 0xc008 && suite != 0xc012 && suite != 0x000a {
				continue
			}
			t.Run(fmt.Sprintf("%s/%04x", version, suite), func(t *testing.T) {
				*versionFlag = version
				*suiteFlag = uint(suite)
				config, err := configuration()
				if err != nil {
					t.Fatal(err)
				}
				roots := x509.NewCertPool()
				roots.AddCert(config.Certificates[0].Leaf)
				clientConfig := &tls.Config{RootCAs: roots, ServerName: "localhost",
					MinVersion: config.MinVersion, MaxVersion: config.MaxVersion,
					CipherSuites: []uint16{suite}, Time: func() time.Time { return fixtureTime }}
				a, b := net.Pipe()
				defer a.Close()
				defer b.Close()
				a.SetDeadline(time.Now().Add(15 * time.Second))
				b.SetDeadline(time.Now().Add(15 * time.Second))
				result := make(chan error, 1)
				go func() {
					server := tls.Server(a, config)
					if err := server.Handshake(); err != nil {
						result <- err
						return
					}
					data := make([]byte, 4097)
					if _, err := io.ReadFull(server, data); err != nil {
						result <- err
						return
					}
					_, err := server.Write(data)
					result <- err
				}()
				client := tls.Client(b, clientConfig)
				if err := client.Handshake(); err != nil {
					t.Fatal(err)
				}
				if state := client.ConnectionState(); state.CipherSuite != suite || state.Version != config.MinVersion || len(state.VerifiedChains) == 0 {
					t.Fatalf("unexpected authenticated state: %+v", state)
				}
				data := pattern(4097, false)
				if _, err := client.Write(data); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(data))
				if _, err := io.ReadFull(client, got); err != nil {
					t.Fatal(err)
				}
				for i := range data {
					if data[i] != got[i] {
						t.Fatalf("payload byte %d", i)
					}
				}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestSHA2CipherVersionsAreRejectedBeforeListening(t *testing.T) {
	for _, version := range []string{"1.0", "1.1"} {
		for _, suite := range []uint{0xc023, 0xc024, 0xc027, 0xc028, 0x003c, 0x003d} {
			*versionFlag = version
			*suiteFlag = suite
			if _, err := configuration(); err == nil {
				t.Fatalf("accepted %s/%04x", version, suite)
			}
		}
	}
}
