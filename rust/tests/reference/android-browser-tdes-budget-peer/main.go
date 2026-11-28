// Independent bounded-memory 3DES budget witness, using only Go's standard library.
package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

const maximumBlocks = 1 << 20
const fullPlain = 16384
const fullBlocks = 2051
const finishedBlocks = 5
const fullRecords = (maximumBlocks - finishedBlocks) / fullBlocks          // 511
const tailBlocks = maximumBlocks - finishedBlocks - fullRecords*fullBlocks // 510
const tailPlain = tailBlocks*8 - 21                                        // maximum plaintext with a one-byte padding
const exporterLabel = "aerobox 3des budget exporter"

var exporterContext = []byte{0, 'b', 'u', 'd', 'g', 'e', 't', 0}
var fixtureTime = time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
var transportTruncated = errors.New("fixture transport EOF without authenticated close_notify")

// Count actual encrypted CBC blocks, excluding the TLS header and explicit IV.
// Only one incomplete TLS record is retained; no stream-sized allocation occurs.
type recordWitness struct {
	buffer               []byte
	encrypted            bool
	blocks, applications uint64
}

func (w *recordWitness) feed(p []byte) error {
	if len(w.buffer)+len(p) > 65536 {
		return errors.New("witness buffer exceeded")
	}
	w.buffer = append(w.buffer, p...)
	for len(w.buffer) >= 5 {
		n := int(binary.BigEndian.Uint16(w.buffer[3:5]))
		if n > 18432 {
			return errors.New("oversized TLS record")
		}
		if len(w.buffer) < n+5 {
			break
		}
		kind := w.buffer[0]
		if w.encrypted {
			if w.buffer[1] != 3 || w.buffer[2] != 3 || n < 32 || (n-8)%8 != 0 {
				return errors.New("invalid encrypted TLS1.2 CBC record shape")
			}
			w.blocks += uint64((n - 8) / 8)
			if kind == 23 {
				w.applications++
			}
		} else if kind == 20 {
			if n != 1 || w.buffer[5] != 1 {
				return errors.New("invalid ChangeCipherSpec")
			}
			w.encrypted = true
		}
		w.buffer = w.buffer[n+5:]
	}
	return nil
}

type witnessedConn struct {
	net.Conn
	read recordWitness
}

func (c *witnessedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		if witnessErr := c.read.feed(p[:n]); witnessErr != nil {
			return 0, witnessErr
		}
	}
	if err == io.EOF {
		err = transportTruncated
	}
	return n, err
}

func configuration(fixtures string) (*tls.Config, error) {
	der, err := os.ReadFile(filepath.Join(fixtures, "rsa-cert.der"))
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
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}},
		MinVersion:   tls.VersionTLS12, MaxVersion: tls.VersionTLS12,
		CipherSuites:     []uint16{tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA},
		CurvePreferences: []tls.CurveID{tls.X25519}, SessionTicketsDisabled: true,
		Time: func() time.Time { return fixtureTime },
	}, nil
}

func pattern(offset int) byte { return byte((offset*17 + 3) % 251) }

func serve(raw net.Conn, config *tls.Config, mode string) (map[string]any, error) {
	defer raw.Close()
	// Unoptimized pure-Rust 3DES can take longer than a normal handshake. Bound
	// both transport activity and memory; the parent additionally bounds the process.
	if err := raw.SetDeadline(time.Now().Add(10 * time.Minute)); err != nil {
		return nil, err
	}
	witness := &witnessedConn{Conn: raw}
	conn := tls.Server(witness, config)
	if err := conn.Handshake(); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if state.Version != tls.VersionTLS12 || state.CipherSuite != tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA || state.DidResume {
		return nil, errors.New("unexpected negotiated TLS state")
	}
	// Go refuses this exporter for TLS1.2 without Extended Master Secret.
	exporter, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append([]byte("ABBD"), exporter...)); err != nil {
		return nil, err
	}
	expected := fullRecords * fullPlain
	expectedBlocks := uint64(finishedBlocks + fullRecords*fullBlocks)
	expectedRecords := uint64(fullRecords)
	if mode == "exact" {
		expected += tailPlain
		expectedBlocks = maximumBlocks
		expectedRecords++
	} else if mode != "partial" {
		return nil, errors.New("invalid mode")
	}
	h := sha256.New()
	var buffer [16384]byte
	count := 0
	for {
		n, readErr := conn.Read(buffer[:])
		if count+n > expected {
			return nil, errors.New("accepted plaintext exceeds announced exact budget boundary")
		}
		for i, b := range buffer[:n] {
			if b != pattern(count+i) {
				return nil, fmt.Errorf("plaintext mismatch at %d", count+i)
			}
		}
		h.Write(buffer[:n])
		count += n
		if readErr != nil {
			if !errors.Is(readErr, transportTruncated) {
				return nil, fmt.Errorf("expected explicit transport truncation: %w", readErr)
			}
			break
		}
	}
	if count != expected || witness.read.blocks != expectedBlocks || witness.read.applications != expectedRecords || len(witness.read.buffer) != 0 {
		return nil, fmt.Errorf("unexpected budget witness: plaintext=%d blocks=%d records=%d residual=%d", count, witness.read.blocks, witness.read.applications, len(witness.read.buffer))
	}
	return map[string]any{
		"phase": "complete", "mode": mode, "plaintext_bytes": count,
		"encrypted_blocks": witness.read.blocks, "application_records": witness.read.applications,
		"sha256": hex.EncodeToString(h.Sum(nil)), "exporter": hex.EncodeToString(exporter),
		"version": state.Version, "cipher": state.CipherSuite, "ems": true,
		"transport_truncation": true, "close_notify_received": false,
	}, nil
}

func run() error {
	fixtures := flag.String("fixtures", "crates/aerobox-crypto/tests/fixtures", "public test certificate/key directory")
	mode := flag.String("mode", "partial", "partial or exact block-budget boundary")
	flag.Parse()
	if *mode != "partial" && *mode != "exact" {
		return errors.New("invalid mode")
	}
	config, err := configuration(*fixtures)
	if err != nil {
		return err
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err = listener.SetDeadline(time.Now().Add(time.Minute)); err != nil {
		return err
	}
	if err = json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "ready", "port": listener.Addr().(*net.TCPAddr).Port}); err != nil {
		return err
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	report, err := serve(conn, config, *mode)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(report)
}

func main() {
	if err := run(); err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"phase": "error", "error": err.Error()})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
