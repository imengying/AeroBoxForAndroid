// Independent HTTP/2 and HTTP/3 peer, only used by interoperability tests.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/qlog"
	"github.com/sagernet/quic-go/qlogwriter"
	"golang.org/x/net/http2"
)

// Record only transport parameters received from the Rust client. This sees
// the actual TLS extension decoded by an independent QUIC implementation.
type parameterTrace struct{ path string }

func (p *parameterTrace) SupportsSchemas(string) bool      { return true }
func (p *parameterTrace) AddProducer() qlogwriter.Recorder { return p }
func (p *parameterTrace) Close() error                     { return nil }
func (p *parameterTrace) RecordEvent(event qlogwriter.Event) {
	value, ok := event.(qlog.ParametersSet)
	if !ok || value.Restore || value.Initiator != qlog.InitiatorRemote {
		return
	}
	data, err := json.Marshal(map[string]any{
		"connection":       value.InitialMaxData,
		"bidi_local":       value.InitialMaxStreamDataBidiLocal,
		"bidi_remote":      value.InitialMaxStreamDataBidiRemote,
		"uni":              value.InitialMaxStreamDataUni,
		"bidi_streams":     value.InitialMaxStreamsBidi,
		"uni_streams":      value.InitialMaxStreamsUni,
		"source_cid_bytes": value.InitialSourceConnectionID.Len(),
		"active_cid_limit": value.ActiveConnectionIDLimit,
	})
	if err != nil {
		panic(err)
	}
	file, err := os.OpenFile(p.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0600)
	if err != nil {
		panic(err)
	}
	defer file.Close()
	if _, err = file.Write(append(data, '\n')); err != nil {
		panic(err)
	}
}

func tunnel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
		w.WriteHeader(407)
		return
	}
	padded := r.Header.Get("Padding") != ""
	if padded {
		w.Header().Set("Padding", "reply")
		w.Header().Set("Padding-Type-Reply", "1")
	}
	w.WriteHeader(200)
	flush := w.(http.Flusher)
	flush.Flush()
	outputFrames := 0
	echo := func(data []byte) error {
		for len(data) > 0 {
			size := len(data)
			if size > 65535 {
				size = 65535
			}
			if padded && outputFrames < 8 {
				header := []byte{byte(size >> 8), byte(size), 0}
				if _, err := w.Write(header); err != nil {
					return err
				}
				outputFrames++
			}
			if _, err := w.Write(data[:size]); err != nil {
				return err
			}
			flush.Flush()
			data = data[size:]
		}
		return nil
	}
	if padded {
		for i := 0; i < 8; i++ {
			var header [3]byte
			if _, err := io.ReadFull(r.Body, header[:]); err != nil {
				return
			}
			length := int(binary.BigEndian.Uint16(header[:2]))
			data := make([]byte, length+int(header[2]))
			if _, err := io.ReadFull(r.Body, data); err != nil {
				return
			}
			if err := echo(data[:length]); err != nil {
				return
			}
		}
	}
	buffer := make([]byte, 16384)
	for {
		n, err := r.Body.Read(buffer)
		if n > 0 {
			if echo(buffer[:n]) != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"}, DNSNames: []string{"localhost", "naive.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	credentials := tls.Certificate{Certificate: [][]byte{cert}, PrivateKey: key}
	if capture := os.Getenv("AEROBOX_NAIVE_CAPTURE"); capture != "" {
		captureQUIC(capture, credentials)
		return
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(tunnel), TLSConfig: &tls.Config{Certificates: []tls.Certificate{credentials}, NextProtos: []string{"h2"}, MinVersion: tls.VersionTLS12}}
	if err := http2.ConfigureServer(server, &http2.Server{}); err != nil {
		panic(err)
	}
	go server.Serve(tls.NewListener(listener, server.TLSConfig))
	h3 := &http3.Server{Handler: http.HandlerFunc(tunnel), TLSConfig: &tls.Config{Certificates: []tls.Certificate{credentials}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}}
	if path := os.Getenv("AEROBOX_NAIVE_PARAMETERS"); path != "" {
		h3.QUICConfig = &quic.Config{Tracer: func(context.Context, bool, quic.ConnectionID) qlogwriter.Trace {
			return &parameterTrace{path: path}
		}}
	}
	go h3.Serve(udp)
	json.NewEncoder(os.Stdout).Encode(map[string]any{"h2": listener.Addr().(*net.TCPAddr).Port, "h3": udp.LocalAddr().(*net.UDPAddr).Port, "certificate": base64.StdEncoding.EncodeToString(cert)})
	select {}
}
