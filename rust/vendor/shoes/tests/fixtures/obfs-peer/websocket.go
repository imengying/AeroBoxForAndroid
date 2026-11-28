package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	ss "github.com/sagernet/sing-shadowsocks"
	vmess "github.com/sagernet/sing-vmess"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type wsStream struct {
	*websocket.Conn
	reader      io.Reader
	writeAccess sync.Mutex
}

func (c *wsStream) Read(p []byte) (int, error) {
	for {
		if c.reader == nil {
			kind, reader, err := c.NextReader()
			if err != nil {
				return 0, err
			}
			if kind != websocket.BinaryMessage {
				return 0, fmt.Errorf("non-binary WS payload")
			}
			c.reader = reader
		}
		n, err := c.reader.Read(p)
		if err == io.EOF {
			c.reader = nil
			if n == 0 {
				continue
			}
			err = nil
		}
		return n, err
	}
}
func (c *wsStream) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	err := c.WriteMessage(websocket.BinaryMessage, p)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}
func (c *wsStream) SetDeadline(t time.Time) error { return c.UnderlyingConn().SetDeadline(t) }

type muxHandler struct{ service ss.Service }

func (h muxHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source, dest M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer conn.Close()
	if dest.Fqdn != "v1.mux.cool" || dest.Port != 666 {
		panic("incorrect plugin mux destination")
	}
	serveSS(h.service, conn)
}
func (muxHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	conn.Close()
}
func serveSS(service ss.Service, conn net.Conn) {
	var err error
	if service == nil {
		err = echo(conn)
	} else {
		err = service.NewConnection(context.Background(), conn, M.Metadata{})
	}
	if err != nil && !strings.Contains(err.Error(), "EOF") && !strings.Contains(err.Error(), "close 1000") {
		fmt.Fprintln(os.Stderr, err)
	}
}

func serveWebsocket(listener net.Listener, mode string, service ss.Service) {
	if os.Getenv("AEROBOX_PEER_TLS") != "" {
		listener = tls.NewListener(listener, peerTLSConfig([]string{"http/1.1"}))
	}
	fmt.Println(listener.Addr().(*net.TCPAddr).Port)
	upgrade := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	server := &http.Server{ReadHeaderTimeout: 10 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tunnel" || r.Host != "localhost" {
			http.Error(w, "invalid host or path", 400)
			return
		}
		wire, err := upgrade.Upgrade(w, r, nil)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return
		}
		defer wire.Close()
		conn := &wsStream{Conn: wire}
		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if mode == "wsmux" {
			vmess.HandleMuxConnection(context.Background(), conn, M.Socksaddr{}, muxHandler{service})
		} else {
			serveSS(service, conn)
		}
	})}
	if err := server.Serve(listener); err != nil {
		panic(err)
	}
}

func peerTLSConfig(protocols []string) *tls.Config {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(42), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true,
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		panic(err)
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})
	if err := os.WriteFile(filepath.Join(os.Getenv("AEROBOX_PEER_CERT_DIR"), "ca.pem"), pemData, 0600); err != nil {
		panic(err)
	}
	leaf := *template
	leaf.SerialNumber = big.NewInt(43)
	leaf.IsCA = false
	leaf.KeyUsage = x509.KeyUsageDigitalSignature
	leafCert, err := x509.CreateCertificate(rand.Reader, &leaf, template, public, private)
	if err != nil {
		panic(err)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: protocols, Certificates: []tls.Certificate{{Certificate: [][]byte{leafCert, cert}, PrivateKey: private}}}
}
