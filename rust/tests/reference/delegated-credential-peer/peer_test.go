package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func testFixtures(t *testing.T) *fixtures {
	t.Helper()
	path := os.Getenv("AEROBOX_DC_FIXTURES")
	if path == "" {
		path = "../../../crates/aerobox-crypto/src/delegated_credentials/fixtures.json"
	}
	f, err := loadFixtures(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func verifySignature(public any, scheme uint16, message, sig []byte) error {
	var h crypto.Hash
	var digest []byte
	switch scheme {
	case 0x0201, 0x0203:
		h = crypto.SHA1
		v := sha1.Sum(message)
		digest = v[:]
	case 0x0401, 0x0403, 0x0804:
		h = crypto.SHA256
		v := sha256.Sum256(message)
		digest = v[:]
	case 0x0501, 0x0503, 0x0805:
		h = crypto.SHA384
		v := sha512.Sum384(message)
		digest = v[:]
	case 0x0601, 0x0603, 0x0806:
		h = crypto.SHA512
		v := sha512.Sum512(message)
		digest = v[:]
	case 0x0807:
		if key, ok := public.(ed25519.PublicKey); ok && ed25519.Verify(key, message, sig) {
			return nil
		}
		return fmt.Errorf("invalid Ed25519 signature")
	default:
		return fmt.Errorf("unknown signature %04x", scheme)
	}
	switch key := public.(type) {
	case *ecdsa.PublicKey:
		if scheme&255 == 3 && ecdsa.VerifyASN1(key, digest, sig) {
			return nil
		}
	case *rsa.PublicKey:
		if scheme >= 0x0804 && scheme <= 0x0806 {
			return rsa.VerifyPSS(key, h, digest, sig, &rsa.PSSOptions{SaltLength: h.Size(), Hash: h})
		}
		if scheme&255 == 1 {
			return rsa.VerifyPKCS1v15(key, h, digest, sig)
		}
	}
	return fmt.Errorf("signature did not verify")
}
func TestIndependentOpenSSLDelegationSignaturesAndContext(t *testing.T) {
	f := testFixtures(t)
	for _, item := range f.IssuerCases {
		t.Run(item.Name, func(t *testing.T) {
			raw, err := decode(item.Credential)
			if err != nil {
				t.Fatal(err)
			}
			der, err := decode(item.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.verifyCertificate(der, false); err != nil {
				t.Fatal(err)
			}
			r := reader{p: raw}
			r.uint(4)
			r.uint(2)
			r.vector(3)
			prefix := len(raw) - len(r.p)
			issuer := uint16(r.uint(2))
			sig := r.vector(2)
			if err = r.done(); err != nil {
				t.Fatal(err)
			}
			input := delegationInput(der, raw[:prefix], issuer, "server")
			if err = verifySignature(leaf.PublicKey, issuer, input, sig); err != nil {
				t.Fatal(err)
			}
			input[len(input)-1] ^= 1
			if err = verifySignature(leaf.PublicKey, issuer, input, sig); err == nil {
				t.Fatal("issuer accepted mutation")
			}
		})
	}
}
func TestNewCredentialsHaveRealIssuerSignaturesAcrossFourDelegatedKeys(t *testing.T) {
	f := testFixtures(t)
	for _, curve := range []string{"P-256", "P-384", "P-521", "Ed25519"} {
		dc, err := credential(f, options{Curve: curve, Mode: "valid"})
		if err != nil {
			t.Fatal(err)
		}
		r := reader{p: dc.wire}
		r.uint(4)
		expected := uint16(r.uint(2))
		spki := r.vector(3)
		prefix := len(dc.wire) - len(r.p)
		issuer := uint16(r.uint(2))
		sig := r.vector(2)
		if r.done() != nil || expected != dc.scheme || issuer != dc.issuer {
			t.Fatal("bad credential wire")
		}
		leaf, err := x509.ParseCertificate(dc.certificate)
		if err != nil {
			t.Fatal(err)
		}
		if err = verifySignature(leaf.PublicKey, issuer, delegationInput(dc.certificate, dc.wire[:prefix], issuer, "server"), sig); err != nil {
			t.Fatal(err)
		}
		key, err := x509.ParsePKIXPublicKey(spki)
		if err != nil {
			t.Fatal(err)
		}
		message := []byte("independent live CertificateVerify check")
		proof, err := signature(dc.private, expected, message)
		if err != nil {
			t.Fatal(err)
		}
		if err = verifySignature(key, expected, message, proof); err != nil {
			t.Fatal(err)
		}
	}
}
func TestStandardGoTLS13ValidatesAllSuitesRetryMutualExporterAndClose(t *testing.T) {
	f := testFixtures(t)
	roots, err := f.roots()
	if err != nil {
		t.Fatal(err)
	}
	der, err := decode(f.Certificates["valid"])
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := decode(f.IssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		t.Fatal(err)
	}
	for _, cipher := range []uint16{0x1301, 0x1302, 0x1303} {
		for _, mutual := range []bool{false, true} {
			t.Run(fmt.Sprintf("%04x-mutual-%t", cipher, mutual), func(t *testing.T) {
				group := uint16(29)
				if mutual {
					group = 23
				}
				left, right := net.Pipe()
				defer left.Close()
				_ = left.SetDeadline(time.Now().Add(20 * time.Second))
				type outcome struct {
					result result
					err    error
				}
				done := make(chan outcome, 1)
				go func() {
					r, e := serve(right, f, options{Curve: "P-256", Mode: "omit", Cipher: cipher, Group: group, Mutual: mutual})
					done <- outcome{r, e}
				}()
				cfg := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Time: func() time.Time { return time.Unix(f.Now, 0) }, NextProtos: []string{"h2"}, CurvePreferences: []tls.CurveID{tls.X25519, tls.CurveP256}}
				if mutual {
					cfg.Certificates = []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}
				}
				client := tls.Client(left, cfg)
				if err := client.Handshake(); err != nil {
					left.Close()
					remote := <-done
					t.Fatalf("handshake: %v; peer: %v", err, remote.err)
				}
				state := client.ConnectionState()
				if state.Version != tls.VersionTLS13 || state.CipherSuite != cipher || len(state.VerifiedChains) == 0 || state.DidResume {
					t.Fatalf("unexpected state %#v", state)
				}
				writeDone := make(chan error, 1)
				go func() { _, e := client.Write(pattern(false)); writeDone <- e }()
				response := make([]byte, 36+payloadBytes)
				if _, err := io.ReadFull(client, response); err != nil {
					t.Fatal(err)
				}
				if err := <-writeDone; err != nil {
					t.Fatal(err)
				}
				exporter, err := state.ExportKeyingMaterial(exporterLabel, exporterContext, 32)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(response[:4], []byte("ABDC")) || !bytes.Equal(response[4:36], exporter) || !bytes.Equal(response[36:], pattern(true)) {
					t.Fatal("application/exporter mismatch")
				}
				if err = client.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if n, err := client.Read(make([]byte, 1)); n != 0 || err != io.EOF {
					t.Fatalf("close: %d %v", n, err)
				}
				remote := <-done
				if remote.err != nil {
					t.Fatal(remote.err)
				}
				if !remote.result.ClientFinished || !remote.result.CloseNotify || remote.result.ClientVerified != mutual || remote.result.Cipher != cipher || remote.result.Delegated || remote.result.Exporter != hex.EncodeToString(exporter) {
					t.Fatalf("bad evidence %+v", remote.result)
				}
			})
		}
	}
}
func TestAEADAuthenticationAndSuiteHashLengths(t *testing.T) {
	for _, id := range []uint16{0x1301, 0x1302, 0x1303} {
		s, err := getSuite(id)
		if err != nil {
			t.Fatal(err)
		}
		secret := bytes.Repeat([]byte{7}, s.size)
		var wire bytes.Buffer
		if err = s.protect(secret).write(&wire, 22, []byte("authenticated transcript")); err != nil {
			t.Fatal(err)
		}
		ciphertext := append([]byte(nil), wire.Bytes()...)
		typ, body, err := s.protect(secret).read(bytes.NewReader(ciphertext))
		if err != nil || typ != 22 || !bytes.Equal(body, []byte("authenticated transcript")) {
			t.Fatalf("suite %x %v", id, err)
		}
		ciphertext[len(ciphertext)-1] ^= 1
		if _, _, err = s.protect(secret).read(bytes.NewReader(ciphertext)); err == nil {
			t.Fatal("corrupt AEAD accepted")
		}
		if len(s.derive(secret, "c hs traffic", nil)) != s.size || len(s.finished(secret, nil)) != s.size {
			t.Fatal("incorrect transcript/HKDF hash length")
		}
	}
}

func TestFaultFixturesRemainConstructibleAndDoNotUseBrokenSignatureAccidentally(t *testing.T) {
	f := testFixtures(t)
	for _, mode := range []string{"valid", "omit", "expired", "too-long", "seven-days", "now-expiry", "cert-expiry", "short-inside", "bad-issuer", "bad-cv", "wrong-role", "wrong-expected", "bad-key", "rsa-key", "sha1-cv", "sha1-issuer", "pkcs1-issuer", "duplicate", "nonleaf", "serverhello", "encryptedextensions", "hrr", "unadvertised-delegated", "bad-finished", "truncated", "trailing", "empty-spki", "empty-signature", "unadvertised", "bad-delegated-scheme", "certificate-context", "missing_usage", "critical_usage", "malformed_usage", "duplicate_usage", "missing_key_usage", "wrong_key_usage"} {
		t.Run(mode, func(t *testing.T) {
			dc, err := credential(f, options{Curve: "P-256", Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			if len(dc.certificate) == 0 || len(dc.wire) == 0 {
				t.Fatal("missing malicious fixture")
			}
		})
	}
}
