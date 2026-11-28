package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
	"golang.org/x/crypto/hkdf"
)

// Follow the pinned sing-box constructor's session-ID authentication, including
// removing MLKEM for its browser path. Retaining MLKEM exercises the independent
// share API separately; it is not claimed as the pinned Android wire layout.
func realityClient(socket net.Conn, stripHybrid bool) (*utls.UConn, error) {
	return realityClientWithProfile(socket, stripHybrid, utls.HelloChrome_133)
}

func realityClientWithProfile(socket net.Conn, stripHybrid bool, profile utls.ClientHelloID) (*utls.UConn, error) {
	cfg := &utls.Config{ServerName: "cover.test", InsecureSkipVerify: true, SessionTicketsDisabled: true}
	return realityClientWithProfileAndConfig(socket, stripHybrid, profile, cfg)
}
func realityClientWithProfileAndConfig(socket net.Conn, stripHybrid bool, profile utls.ClientHelloID, cfg *utls.Config) (*utls.UConn, error) {
	var auth []byte
	cfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
		if len(raw) != 1 {
			return errors.New("unexpected REALITY certificate chain")
		}
		cert, err := x509.ParseCertificate(raw[0])
		if err != nil {
			return err
		}
		public, ok := cert.PublicKey.(ed25519.PublicKey)
		if !ok {
			return errors.New("REALITY requires Ed25519")
		}
		mac := hmac.New(sha512.New, auth)
		_, _ = mac.Write(public)
		if !hmac.Equal(cert.Signature, mac.Sum(nil)) {
			return errors.New("REALITY HMAC rejected")
		}
		return nil
	}
	client := utls.UClient(socket, cfg, profile)
	if err := client.BuildHandshakeState(); err != nil {
		return nil, err
	}
	if stripHybrid {
		for _, ext := range client.Extensions {
			switch ext := ext.(type) {
			case *utls.SupportedCurvesExtension:
				var curves []utls.CurveID
				for _, curve := range ext.Curves {
					if curve != utls.X25519MLKEM768 {
						curves = append(curves, curve)
					}
				}
				ext.Curves = curves
			case *utls.KeyShareExtension:
				var shares []utls.KeyShare
				for _, share := range ext.KeyShares {
					if share.Group != utls.X25519MLKEM768 {
						shares = append(shares, share)
					}
				}
				ext.KeyShares = shares
			}
		}
		if err := client.BuildHandshakeState(); err != nil {
			return nil, err
		}
	}
	serverPrivate, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		return nil, err
	}
	shared, err := client.HandshakeState.State13.KeyShareKeys.Ecdhe.ECDH(serverPrivate.PublicKey())
	if err != nil {
		return nil, err
	}
	hello := client.HandshakeState.Hello
	auth = make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, hello.Random[:20], []byte("REALITY")), auth); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(auth)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hello.SessionId = make([]byte, 32)
	clear(hello.Raw[39:71])
	plain := make([]byte, 16)
	copy(plain, []byte{1, 8, 1, 0})
	binary.BigEndian.PutUint32(plain[4:8], uint32(time.Now().Unix()))
	copy(plain[8:], bytes.Repeat([]byte{1}, 8))
	copy(hello.SessionId, aead.Seal(nil, hello.Random[20:], plain, hello.Raw))
	copy(hello.Raw[39:71], hello.SessionId)
	return client, nil
}

func TestReferenceReality(t *testing.T) {
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	for _, tc := range []struct {
		mode    string
		group   uint16
		strip   bool
		profile string
	}{
		{"valid", 29, true, "chrome"}, {"valid", 29, false, "chrome"}, {"valid", 4588, false, "chrome"},
		{"bad-hmac", 29, true, "chrome"}, {"bad-signature", 29, true, "chrome"}, {"bad-short-id", 29, true, "chrome"},
		{"valid", 29, true, "safari"}, {"bad-hmac", 29, true, "safari"}, {"bad-signature", 29, true, "safari"}, {"bad-short-id", 29, true, "safari"},
		{"valid", 29, true, "ios"}, {"bad-hmac", 29, true, "ios"}, {"bad-signature", 29, true, "ios"}, {"bad-short-id", 29, true, "ios"},
		{"valid", 29, true, "firefox"}, {"bad-hmac", 29, true, "firefox"}, {"bad-signature", 29, true, "firefox"}, {"bad-short-id", 29, true, "firefox"},
	} {
		t.Run(fmt.Sprintf("%s_%s_group%d_strip%v", tc.profile, tc.mode, tc.group, tc.strip), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
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
				options := peerOptions{Reality: tc.mode, RealityBrowser: tc.strip, RealityProfile: tc.profile, Group: tc.group, Compress: true, ALPS: 17613}
				if tc.profile != "chrome" {
					options.Compress, options.ALPS = false, 0
				}
				r, e := serveWire(socket, cert, key, options)
				done <- outcome{r, e}
			}()
			socket, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer socket.Close()
			_ = socket.SetDeadline(time.Now().Add(10 * time.Second))
			profile := utls.HelloChrome_133
			if tc.profile == "safari" {
				profile = utls.HelloSafari_16_0
			} else if tc.profile == "ios" {
				profile = utls.HelloIOS_14
			} else if tc.profile == "firefox" {
				profile = utls.HelloFirefox_120
			}
			client, err := realityClientWithProfile(socket, tc.strip, profile)
			if err != nil {
				t.Fatal(err)
			}
			err = client.Handshake()
			if tc.mode != "valid" {
				_ = socket.Close()
				server := <-done
				if err == nil || server.err == nil {
					t.Fatalf("malformed REALITY accepted: client=%v server=%+v", err, server)
				}
				return
			}
			if err != nil {
				_ = socket.Close()
				t.Fatalf("handshake %v; server %+v", err, <-done)
			}
			payload := bytes.Repeat([]byte{67}, 65537)
			if err = writeAll(client, payload); err != nil {
				t.Fatal(err)
			}
			got := make([]byte, len(payload))
			if _, err = io.ReadFull(client, got); err != nil || !bytes.Equal(payload, got) {
				t.Fatalf("echo %v", err)
			}
			if err = client.CloseWrite(); err != nil {
				t.Fatal(err)
			}
			if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
				t.Fatalf("close n=%d err=%v", n, err)
			}
			_ = socket.Close()
			server := <-done
			if server.err != nil || !server.result.RealityAuthenticated || server.result.Bytes != len(payload) {
				t.Fatalf("server %+v", server)
			}
		})
	}
}

func TestRealityBrowserLayoutRejectsWrongProfileAndMutations(t *testing.T) {
	for _, tc := range []struct {
		name string
		id   utls.ClientHelloID
	}{
		{"chrome", utls.HelloChrome_133}, {"safari", utls.HelloSafari_16_0}, {"ios", utls.HelloIOS_14}, {"firefox", utls.HelloFirefox_120},
	} {
		t.Run(tc.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			client, err := realityClientWithProfile(left, true, tc.id)
			if err != nil {
				t.Fatal(err)
			}
			fresh := func() clientHello {
				hello, err := parseHello(append([]byte(nil), client.HandshakeState.Hello.Raw...))
				if err != nil {
					t.Fatal(err)
				}
				return hello
			}
			if err := checkRealityBrowserLayout(fresh(), tc.name); err != nil {
				t.Fatal(err)
			}
			wrong := "chrome"
			if tc.name == "chrome" {
				wrong = "safari"
			}
			if checkRealityBrowserLayout(fresh(), wrong) == nil {
				t.Fatal("accepted another profile's group layout")
			}
			if checkRealityBrowserLayout(fresh(), "unknown") == nil {
				t.Fatal("accepted unknown profile")
			}
			for name, mutate := range map[string]func(*clientHello){
				"group-order": func(h *clientHello) {
					h.extensions[10][5], h.extensions[10][7] = h.extensions[10][7], h.extensions[10][5]
				},
				"non-grease":         func(h *clientHello) { h.extensions[10][2], h.extensions[10][3] = 0, 1 },
				"group-trailing":     func(h *clientHello) { h.extensions[10] = append(h.extensions[10], 0) },
				"missing-share":      func(h *clientHello) { h.shareOrder = h.shareOrder[:1] },
				"wrong-grease-share": func(h *clientHello) { h.shares[h.shareOrder[0]] = []byte{1} },
				"short-x25519":       func(h *clientHello) { h.shares[29] = h.shares[29][:31] },
				"unexpected-hybrid":  func(h *clientHello) { h.shares[4588] = make([]byte, 1216) },
			} {
				t.Run(name, func(t *testing.T) {
					hello := fresh()
					mutate(&hello)
					if checkRealityBrowserLayout(hello, tc.name) == nil {
						t.Fatal("accepted mutated browser layout")
					}
				})
			}
		})
	}
}
