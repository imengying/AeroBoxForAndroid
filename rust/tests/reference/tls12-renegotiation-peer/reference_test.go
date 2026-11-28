package main

import (
	"bytes"
	tls "github.com/metacubex/utls"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPinnedReference(t *testing.T) {
	fixtures := os.Getenv("AEROBOX_TLS_FIXTURES")
	if fixtures == "" {
		t.Fatal("AEROBOX_TLS_FIXTURES")
	}
	for _, chrome := range []bool{false, true} {
		for _, mode := range []string{"valid", "bad-binding", "short-binding", "omit-binding", "initial-nonempty", "changed-certificate", "fragment", "bad-finished", "early-data"} {
			for _, suite := range []uint16{0xc02f, 0xc013, 0x009c, 0x002f, 0xcca8} {
				name := tls.CipherSuiteName(suite) + "/" + mode
				if chrome {
					name = "chrome/" + name
				} else {
					name = "go/" + name
				}
				t.Run(name, func(t *testing.T) {
					cfg, err := configuration(fixtures, suite)
					if err != nil {
						t.Fatal(err)
					}
					listener, err := net.Listen("tcp4", "127.0.0.1:0")
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					finished := make(chan error, 1)
					hellos := filepath.Join(t.TempDir(), "hello.json")
					go func() {
						raw, err := listener.Accept()
						if err == nil {
							err = serve(raw, cfg, mode, true, hellos)
						}
						finished <- err
					}()
					raw, err := net.Dial("tcp4", listener.Addr().String())
					if err != nil {
						t.Fatal(err)
					}
					defer raw.Close()
					_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
					clientCfg := cfg.Clone()
					clientCfg.NextProtos = []string{"h2", "http/1.1"}
					var c interface {
						io.Reader
						io.Writer
						Close() error
						Handshake() error
						AeroBoxFixtureExportKeyingMaterial() ([]byte, error)
					}
					if chrome {
						c = tls.UClient(raw, clientCfg, tls.HelloChrome_133)
					} else {
						c = tls.Client(raw, clientCfg)
					}
					run := func() error {
						if err := c.Handshake(); err != nil {
							return err
						}
						old, err := checkMarker(c, "initial")
						if err != nil {
							return err
						}
						if _, err := c.Write([]byte("ack")); err != nil {
							return err
						}
						renewed, err := checkMarker(c, "renewed")
						if err != nil {
							return err
						}
						if bytes.Equal(old, renewed) {
							t.Fatal("unchanged exporter after renegotiation")
						}
						data := bytes.Repeat([]byte{42}, 65537)
						if _, err := c.Write(data); err != nil {
							return err
						}
						out := make([]byte, len(data))
						if _, err := io.ReadFull(c, out); err != nil {
							return err
						}
						if !bytes.Equal(data, out) {
							t.Fatal("echo mismatch")
						}
						return nil
					}
					err = run()
					_ = c.Close()
					serverErr := <-finished
					if mode == "valid" || mode == "fragment" {
						if err != nil || serverErr != nil {
							t.Fatalf("client=%v server=%v", err, serverErr)
						}
						b, _ := os.ReadFile(hellos)
						t.Logf("hellos=%s", b)
					} else if err == nil {
						t.Fatal("invalid handshake accepted")
					}
				})
			}
		}
	}
}
