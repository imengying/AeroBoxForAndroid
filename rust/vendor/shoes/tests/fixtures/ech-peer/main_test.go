package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sagernet/quic-go"
)

func readBlock(t *testing.T, dir, file string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, file))
	if err != nil {
		t.Fatal(err)
	}
	block, trailing := pem.Decode(raw)
	if block == nil || len(trailing) != 0 {
		t.Fatalf("invalid PEM %s", file)
	}
	return block.Bytes
}

func connect(t *testing.T, transport, address string, config *tls.Config) (io.ReadWriter, func(), error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if transport == "tcp" {
		connection, err := tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", address, config)
		if err != nil {
			return nil, nil, err
		}
		if !connection.ConnectionState().ECHAccepted || connection.ConnectionState().ServerName != privateName {
			t.Fatal("TLS client did not authenticate inner handshake")
		}
		_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
		return connection, func() { _ = connection.Close() }, nil
	}
	connection, err := quic.DialAddr(ctx, address, config, &quic.Config{})
	if err != nil {
		return nil, nil, err
	}
	if !connection.ConnectionState().TLS.ECHAccepted || connection.ConnectionState().TLS.ServerName != privateName {
		t.Fatal("QUIC client did not authenticate inner handshake")
	}
	stream, err := connection.OpenStreamSync(ctx)
	if err != nil {
		_ = connection.CloseWithError(0, "test cleanup")
		return nil, nil, err
	}
	_ = stream.SetDeadline(time.Now().Add(5 * time.Second))
	return stream, func() {
		_ = stream.Close()
		stream.CancelRead(0)
		_ = connection.CloseWithError(0, "test cleanup")
	}, nil
}

func TestECHReferenceModes(t *testing.T) {
	for _, transport := range []string{"tcp", "quic"} {
		for _, mode := range []string{"accept", "rotate", "reject", "badpublic"} {
			t.Run(transport+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				server, observer, err := prepare(dir, transport, mode)
				if err != nil {
					t.Fatal(err)
				}
				address, closeListener, err := listen(transport, server, observer)
				if err != nil {
					t.Fatal(err)
				}
				defer closeListener()
				roots := x509.NewCertPool()
				root, err := x509.ParseCertificate(readBlock(t, dir, "ca.pem"))
				if err != nil {
					t.Fatal(err)
				}
				roots.AddCert(root)
				client := &tls.Config{
					MinVersion: tls.VersionTLS13, ServerName: privateName,
					RootCAs: roots, NextProtos: []string{peerALPN},
					EncryptedClientHelloConfigList: readBlock(t, dir, "initial-config.pem"),
				}
				stream, closeStream, err := connect(t, transport, address.String(), client)
				switch mode {
				case "accept":
					if err != nil {
						t.Fatal(err)
					}
				case "rotate", "reject":
					var rejected *tls.ECHRejectionError
					if !errors.As(err, &rejected) {
						t.Fatalf("expected authenticated ECH rejection, got %v", err)
					}
					if mode == "reject" {
						if len(rejected.RetryConfigList) != 0 {
							t.Fatal("reject mode advertised retry config")
						}
						return
					}
					if !bytes.Equal(rejected.RetryConfigList, readBlock(t, dir, "config.pem")) {
						t.Fatal("retry config differs from config.pem")
					}
					client.EncryptedClientHelloConfigList = rejected.RetryConfigList
					stream, closeStream, err = connect(t, transport, address.String(), client)
					if err != nil {
						t.Fatal(err)
					}
				case "badpublic":
					var authority x509.UnknownAuthorityError
					if !errors.As(err, &authority) {
						t.Fatalf("expected untrusted outer certificate, got %v", err)
					}
					// A trusted inner certificate still works when ECH decrypts.
					client.EncryptedClientHelloConfigList = readBlock(t, dir, "config.pem")
					stream, closeStream, err = connect(t, transport, address.String(), client)
					if err != nil {
						t.Fatalf("trusted inner positive control: %v", err)
					}
				}
				defer closeStream()
				payload := bytes.Repeat([]byte{42}, 65537)
				written := make(chan error, 1)
				go func() {
					_, err := io.Copy(stream, bytes.NewReader(payload))
					written <- err
				}()
				received := make([]byte, len(payload))
				if _, err := io.ReadFull(stream, received); err != nil {
					t.Fatal(err)
				}
				if err := <-written; err != nil || !bytes.Equal(received, payload) {
					t.Fatalf("echo: %v, matches=%v", err, bytes.Equal(received, payload))
				}
				observer.access.Lock()
				defer observer.access.Unlock()
				if observer.state.ECHAccepted != 1 || observer.state.Connections != 1 {
					t.Fatalf("unexpected accepted connection counts: %+v", observer.state)
				}
				if mode == "rotate" || mode == "badpublic" {
					if observer.state.Attempts != 2 || observer.state.ECHRejected != 1 {
						t.Fatalf("unexpected rejected attempt counts: %+v", observer.state)
					}
					if observer.state.Handshakes[0].ServerName != publicName || observer.state.Handshakes[1].ServerName != privateName {
						t.Fatalf("unexpected handshake identities: %+v", observer.state.Handshakes)
					}
				}
			})
		}
	}
}
