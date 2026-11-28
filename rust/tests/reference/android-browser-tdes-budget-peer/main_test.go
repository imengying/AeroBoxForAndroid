package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestActualGoBudgetWitness(t *testing.T) {
	fixtures := os.Getenv("AEROBOX_TLS_FIXTURES")
	if fixtures == "" {
		t.Fatal("AEROBOX_TLS_FIXTURES must name the public test fixture directory")
	}
	for _, mode := range []string{"partial", "exact"} {
		t.Run(mode, func(t *testing.T) {
			config, err := configuration(fixtures)
			if err != nil {
				t.Fatal(err)
			}
			serverRaw, clientRaw := net.Pipe()
			defer clientRaw.Close()
			roots := x509.NewCertPool()
			roots.AddCert(config.Certificates[0].Leaf)
			client := tls.Client(clientRaw, &tls.Config{
				RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
				CipherSuites:                []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
				DynamicRecordSizingDisabled: true, Time: func() time.Time { return fixtureTime },
			})
			type outcome struct {
				result map[string]any
				err    error
			}
			done := make(chan outcome, 1)
			go func() { result, err := serve(serverRaw, config, mode); done <- outcome{result, err} }()
			if err := client.Handshake(); err != nil {
				t.Fatal(err)
			}
			state := client.ConnectionState()
			if len(state.VerifiedChains) != 1 || !bytes.Equal(state.PeerCertificates[0].Raw, config.Certificates[0].Certificate[0]) {
				t.Fatal("normal hostname/chain validation did not authenticate exact fixture")
			}
			exporter, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
			if err != nil {
				t.Fatal(err)
			}
			var banner [36]byte
			if _, err := io.ReadFull(client, banner[:]); err != nil {
				t.Fatal(err)
			}
			if string(banner[:4]) != "ABBD" || !bytes.Equal(banner[4:], exporter) {
				t.Fatal("exporter mismatch")
			}
			var data [fullPlain]byte
			count := 0
			h := sha256.New()
			write := func(n int) {
				for i := range data[:n] {
					data[i] = pattern(count + i)
				}
				written, err := client.Write(data[:n])
				if err != nil || written != n {
					t.Fatalf("write=%d error=%v", written, err)
				}
				h.Write(data[:n])
				count += n
			}
			for i := 0; i < fullRecords; i++ {
				write(fullPlain)
			}
			if mode == "exact" {
				write(tailPlain)
			}
			// Model a failed local encrypter: no TLS close_notify can be generated.
			if err := clientRaw.Close(); err != nil {
				t.Fatal(err)
			}
			got := <-done
			if got.err != nil {
				t.Fatal(got.err)
			}
			if got.result["plaintext_bytes"] != count || got.result["sha256"] != hex.EncodeToString(h.Sum(nil)) {
				t.Fatalf("invalid complete witness: %v", got.result)
			}
		})
	}
}

func TestFragmentedRecordWitnessAndInvalidShapes(t *testing.T) {
	ccs := []byte{20, 3, 3, 0, 1, 1}
	finished := append([]byte{22, 3, 3, 0, 48}, make([]byte, 48)...)
	var witness recordWitness
	for _, b := range append(ccs, finished...) {
		if err := witness.feed([]byte{b}); err != nil {
			t.Fatal(err)
		}
	}
	if witness.blocks != 5 || !witness.encrypted || len(witness.buffer) != 0 {
		t.Fatal("fragmented witness mismatch")
	}
	for _, record := range [][]byte{
		{23, 3, 3, 0xff, 0xff},
		append([]byte{23, 3, 2, 0, 32}, make([]byte, 32)...),
		append([]byte{23, 3, 3, 0, 33}, make([]byte, 33)...),
	} {
		w := recordWitness{encrypted: true}
		if w.feed(record) == nil {
			t.Fatalf("accepted invalid TLS CBC shape %x", record[:5])
		}
	}
}
