// Independent REALITY authentication fixture using Go's crypto primitives.
// The fixed private key/short ID below are public test data, never credentials.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"time"

	"golang.org/x/crypto/hkdf"
)

func realityCredential(ch []byte, hello clientHello, mode string, browser bool, profile string) ([]byte, ed25519.PrivateKey, error) {
	switch mode {
	case "valid", "bad-hmac", "bad-signature", "bad-short-id":
	default:
		return nil, nil, errors.New("invalid REALITY fixture mode")
	}
	x, hybrid := hello.shares[29], hello.shares[4588]
	if len(x) != 32 || (len(hybrid) != 0 && (len(hybrid) != 1216 || bytes.Equal(x, hybrid[1184:]))) || len(hello.session) != 32 || len(ch) < 71 || ch[38] != 32 {
		return nil, nil, errors.New("REALITY requires X25519, optional independent hybrid share and 32-byte session ID")
	}
	if browser {
		if err := checkRealityBrowserLayout(hello, profile); err != nil {
			return nil, nil, err
		}
	}
	private, err := ecdh.X25519().NewPrivateKey(bytes.Repeat([]byte{42}, 32))
	if err != nil {
		return nil, nil, err
	}
	public, err := ecdh.X25519().NewPublicKey(x)
	if err != nil {
		return nil, nil, err
	}
	shared, err := private.ECDH(public)
	if err != nil {
		return nil, nil, err
	}
	auth := make([]byte, 32)
	if _, err = io.ReadFull(hkdf.New(sha256.New, shared, hello.random[:20], []byte("REALITY")), auth); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(auth)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	aad := append([]byte(nil), ch...)
	clear(aad[39:71])
	plain, err := aead.Open(nil, hello.random[20:], hello.session, aad)
	if err != nil {
		return nil, nil, err
	}
	short := byte(1)
	if mode == "bad-short-id" {
		short = 2
	}
	if len(plain) != 16 || !bytes.Equal(plain[:4], []byte{1, 8, 1, 0}) || !bytes.Equal(plain[8:], bytes.Repeat([]byte{short}, 8)) {
		return nil, nil, errors.New("invalid authenticated REALITY metadata")
	}
	age := time.Now().Unix() - int64(binary.BigEndian.Uint32(plain[4:8]))
	if age < -60 || age > 60 {
		return nil, nil, errors.New("REALITY timestamp out of range")
	}
	signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"cover.test"}, KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signingPublic, signingPrivate)
	if err != nil {
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil || len(certificate.Signature) != 64 || !bytes.Equal(der[len(der)-64:], certificate.Signature) {
		return nil, nil, errors.New("unexpected generated certificate signature framing")
	}
	mac := hmac.New(sha512.New, auth)
	_, _ = mac.Write(signingPublic)
	copy(der[len(der)-64:], mac.Sum(nil))
	if mode == "bad-hmac" {
		der[len(der)-1] ^= 1
	}
	return der, signingPrivate, nil
}

// Keep the pre-existing Chrome/Edge/QQ check strict. Android's Safari and iOS
// fingerprints additionally advertise P-521; select that layout explicitly.
func checkRealityBrowserLayout(hello clientHello, profile string) error {
	if profile == "randomized" {
		return checkRandomizedRealityLayout(hello)
	}
	if profile == "firefox" {
		return checkFirefoxRealityLayout(hello)
	}
	want := []uint16{29, 23, 24}
	switch profile {
	case "", "chrome", "edge", "qq":
	case "safari", "ios":
		want = append(want, 25)
	default:
		return errors.New("unknown REALITY browser profile")
	}
	isGrease := func(x uint16) bool { return x&0x0f0f == 0x0a0a && x>>8 == x&255 }
	groupsReader := reader{p: hello.extensions[10]}
	groups := reader{p: groupsReader.vector(2)}
	grease := uint16(groups.uint(2))
	if !isGrease(grease) {
		return errors.New("REALITY browser requires leading GREASE group")
	}
	for _, group := range want {
		if groups.uint(2) != int(group) {
			return errors.New("wrong REALITY browser supported group order")
		}
	}
	if groups.done() != nil || groupsReader.done() != nil || len(hello.shareOrder) != 2 || hello.shareOrder[0] != grease || hello.shareOrder[1] != 29 || !bytes.Equal(hello.shares[grease], []byte{0}) || len(hello.shares[29]) != 32 || len(hello.shares[4588]) != 0 {
		return errors.New("wrong REALITY browser groups or shares")
	}
	return nil
}

// This leaf is fully CA-authenticated. Only its chosen handshake signature is
// malformed for a Chrome offer; ordinary TLS advertising Ed25519 can use it.
func unadvertisedCertificate(issuer []byte, key *rsa.PrivateKey) ([]byte, ed25519.PrivateKey, error) {
	parent, err := x509.ParseCertificate(issuer)
	if err != nil {
		return nil, nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: time.Unix(1577836800, 0), NotAfter: time.Unix(2208988800, 0), DNSNames: []string{"localhost"}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, public, key)
	return der, private, err
}
