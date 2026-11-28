package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	utls "github.com/metacubex/utls"
)

// Published fixed witnesses from the already captured v1.8.7 reference corpus.
// They contain 1301 because this baseline reference server implements AES128GCM.
// This selection is test corpus design, never a production seed retry policy.
var randomizedRealityWitnesses = []struct {
	name, seed string
	alpn, alps bool
}{
	{"alps-p256", "a444b8de32c1a2669ab2a8d0611676c9dd2b0e5c3271476ebd4be4dce157ede2", true, true},
	{"alpn-p521", "66be7ef5a1326ecb60b940e83e5d5362d7dda01891bdb837b300eeb369ef274c", true, false},
	{"no-alpn", "2e93a5dc34325729b38aa13ca38072164cc8b74297766a8d72c1a9cfeeb531b4", false, false},
}

func randomizedRealityProfile(t *testing.T, seedHex string) utls.ClientHelloID {
	t.Helper()
	raw, err := hex.DecodeString(seedHex)
	if err != nil || len(raw) != 32 {
		t.Fatal("invalid fixed seed")
	}
	var seed utls.PRNGSeed
	copy(seed[:], raw)
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	profile := utls.HelloRandomized
	profile.Seed, profile.Weights = &seed, &weights
	return profile
}

func TestRandomizedRealityLayoutUsesFixedPoolAndRejectsMutations(t *testing.T) {
	for _, witness := range randomizedRealityWitnesses {
		t.Run(witness.name, func(t *testing.T) {
			left, right := net.Pipe()
			defer left.Close()
			defer right.Close()
			client, err := realityClientWithProfile(left, true, randomizedRealityProfile(t, witness.seed))
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
			if err := checkRealityBrowserLayout(fresh(), "randomized"); err != nil {
				t.Fatal(err)
			}
			for name, mutate := range map[string]func(*clientHello){
				"grease-cipher":    func(h *clientHello) { h.ciphers[0], h.ciphers[1] = 0x0a, 0x0a },
				"duplicate-cipher": func(h *clientHello) { h.ciphers = append(h.ciphers, h.ciphers[:2]...) },
				"fake-cipher":      func(h *clientHello) { h.ciphers[0], h.ciphers[1] = 0, 4 },
				"missing-pss": func(h *clientHello) {
					h.extensions[13] = bytes.ReplaceAll(h.extensions[13], []byte{8, 4}, []byte{8, 7})
				},
				"wrong-group-order":  func(h *clientHello) { h.extensions[10] = vector16([]byte{0, 23, 0, 29, 0, 24}) },
				"hybrid-group":       func(h *clientHello) { h.extensions[10] = vector16([]byte{0x11, 0xec, 0, 29, 0, 23, 0, 24}) },
				"missing-share":      func(h *clientHello) { delete(h.shares, 29) },
				"hybrid-share":       func(h *clientHello) { h.shares[4588] = make([]byte, 1216) },
				"short-x25519":       func(h *clientHello) { h.shares[29] = h.shares[29][:31] },
				"ech":                func(h *clientHello) { h.extensions[65037] = nil },
				"unknown-extension":  func(h *clientHello) { h.extensions[34] = nil },
				"renegotiation-body": func(h *clientHello) { h.extensions[65281] = []byte{1} },
				"psk-mode":           func(h *clientHello) { h.extensions[45] = []byte{1, 0} },
				"version":            func(h *clientHello) { h.extensions[43] = []byte{2, 3, 4} },
				"alps-object":        func(h *clientHello) { h.extensions[17513] = []byte{0, 3, 2, 'h', '3'} },
				"nonzero-padding":    func(h *clientHello) { h.extensions[21] = []byte{1} },
			} {
				t.Run(name, func(t *testing.T) {
					hello := fresh()
					mutate(&hello)
					if checkRealityBrowserLayout(hello, "randomized") == nil {
						t.Fatal("accepted mutated randomized REALITY layout")
					}
				})
			}
		})
	}
}

func TestReferenceRandomizedRealityAuthenticationAndOptionalALPN(t *testing.T) {
	cert, key := fixtureFiles("../../../crates/aerobox-crypto/tests/fixtures")
	for _, witness := range randomizedRealityWitnesses {
		for _, mode := range []string{"valid", "bad-hmac", "bad-signature", "bad-short-id"} {
			t.Run(fmt.Sprintf("%s-%s", witness.name, mode), func(t *testing.T) {
				listener, err := net.Listen("tcp4", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				type outcome struct {
					result peerResult
					err    error
				}
				done := make(chan outcome, 1)
				options := peerOptions{Reality: mode, RealityBrowser: true, RealityProfile: "randomized", Group: 29}
				if witness.alps {
					options.ALPS = 17513
				}
				if !witness.alpn {
					options.AllowNoALPN, options.OmitALPN = true, true
				}
				go func() {
					socket, err := listener.Accept()
					if err != nil {
						done <- outcome{err: err}
						return
					}
					r, e := serveWire(socket, cert, key, options)
					done <- outcome{r, e}
				}()
				socket, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
				if err != nil {
					t.Fatal(err)
				}
				defer socket.Close()
				_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
				client, err := realityClientWithProfile(socket, true, randomizedRealityProfile(t, witness.seed))
				if err != nil {
					t.Fatal(err)
				}
				err = client.Handshake()
				if mode != "valid" {
					_ = socket.Close()
					server := <-done
					if err == nil || server.err == nil {
						t.Fatalf("unauthenticated REALITY accepted: client=%v server=%+v", err, server)
					}
					return
				}
				if err != nil {
					_ = socket.Close()
					t.Fatalf("client=%v server=%+v", err, <-done)
				}
				wantedALPN := ""
				if witness.alpn {
					wantedALPN = "h2"
				}
				if client.ConnectionState().NegotiatedProtocol != wantedALPN {
					t.Fatal("ALPN changed")
				}
				payload := make([]byte, 65537)
				for i := range payload {
					payload[i] = byte(i % 251)
				}
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
					t.Fatalf("close notify: %d %v", n, err)
				}
				_ = socket.Close()
				server := <-done
				if server.err != nil || !server.result.RealityAuthenticated || server.result.Bytes != len(payload) || server.result.ALPS != options.ALPS {
					t.Fatalf("server=%+v", server)
				}
			})
		}
	}
}
