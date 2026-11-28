package main

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

type keyFixture struct {
	Name              string `json:"name"`
	Scheme            uint16 `json:"scheme"`
	SPKI              string `json:"spki"`
	Key               string `json:"key"`
	Credential        string `json:"credential"`
	CertificateVerify string `json:"certificate_verify"`
}
type issuerFixture struct {
	Name        string `json:"name"`
	Certificate string `json:"certificate"`
	Credential  string `json:"credential"`
	Accepted    bool   `json:"accepted"`
}
type fixtures struct {
	Now          int64             `json:"now"`
	NotBefore    int64             `json:"not_before"`
	CA           string            `json:"ca"`
	IssuerKey    string            `json:"issuer_key"`
	Certificates map[string]string `json:"certificates"`
	Curves       []keyFixture      `json:"curves"`
	Ed25519      keyFixture        `json:"ed25519"`
	IssuerCases  []issuerFixture   `json:"issuer_cases"`
}

func decode(text string) ([]byte, error) {
	if len(text) == 0 || len(text) > 131072 || len(text)%2 != 0 {
		return nil, errors.New("invalid bounded fixture hex")
	}
	return hex.DecodeString(text)
}
func loadFixtures(path string) (*fixtures, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 262144 {
		return nil, errors.New("fixture file limit")
	}
	var f fixtures
	if err = json.Unmarshal(data, &f); err != nil {
		return nil, err
	}
	if f.Now != 1893456000 || f.NotBefore != 1577836800 || len(f.Curves) != 3 {
		return nil, errors.New("unexpected fixture metadata")
	}
	f.Ed25519.Name = "Ed25519"
	f.Ed25519.Scheme = 0x0807
	return &f, nil
}
func (f *fixtures) selected(name string) (keyFixture, error) {
	for _, item := range append(append([]keyFixture(nil), f.Curves...), f.Ed25519) {
		if item.Name == name {
			return item, nil
		}
	}
	return keyFixture{}, fmt.Errorf("unknown delegated curve %s", name)
}
func (f *fixtures) roots() (*x509.CertPool, error) {
	der, err := decode(f.CA)
	if err != nil {
		return nil, err
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	return roots, nil
}
func (f *fixtures) verifyCertificate(der []byte, client bool) error {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	roots, err := f.roots()
	if err != nil {
		return err
	}
	options := x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(f.Now, 0), DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if client {
		options.DNSName = ""
		options.KeyUsages = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	_, err = leaf.Verify(options)
	return err
}
func signature(key any, scheme uint16, message []byte) ([]byte, error) {
	var hash crypto.Hash
	var sum []byte
	switch scheme {
	case 0x0201, 0x0203:
		hash = crypto.SHA1
		out := sha1.Sum(message)
		sum = out[:]
	case 0x0401, 0x0403, 0x0804:
		hash = crypto.SHA256
		out := sha256.Sum256(message)
		sum = out[:]
	case 0x0501, 0x0503, 0x0805:
		hash = crypto.SHA384
		out := sha512.Sum384(message)
		sum = out[:]
	case 0x0601, 0x0603, 0x0806:
		hash = crypto.SHA512
		out := sha512.Sum512(message)
		sum = out[:]
	case 0x0807:
		private, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("Ed25519 key required")
		}
		return ed25519.Sign(private, message), nil
	default:
		return nil, errors.New("unsupported test signature scheme")
	}
	switch private := key.(type) {
	case *ecdsa.PrivateKey:
		if scheme&255 != 3 {
			return nil, errors.New("ECDSA scheme mismatch")
		}
		return ecdsa.SignASN1(rand.Reader, private, sum)
	case *rsa.PrivateKey:
		if scheme >= 0x0804 && scheme <= 0x0806 {
			return rsa.SignPSS(rand.Reader, private, hash, sum, &rsa.PSSOptions{SaltLength: hash.Size(), Hash: hash})
		}
		if scheme&255 != 1 {
			return nil, errors.New("RSA scheme mismatch")
		}
		return rsa.SignPKCS1v15(rand.Reader, private, hash, sum)
	default:
		return nil, errors.New("unsupported private key")
	}
}
func delegationInput(certificate, credential []byte, scheme uint16, role string) []byte {
	input := append(bytes.Repeat([]byte{32}, 64), []byte("TLS, "+role+" delegated credentials\x00")...)
	input = append(input, certificate...)
	input = append(input, credential...)
	return binary.BigEndian.AppendUint16(input, scheme)
}

type delegated struct {
	certificate, wire []byte
	private           any
	scheme, issuer    uint16
	expiry            int64
}

func credential(f *fixtures, options options) (delegated, error) {
	var result delegated
	selected, err := f.selected(options.Curve)
	if err != nil {
		return result, err
	}
	if options.Mode == "unadvertised-delegated" {
		selected = f.Ed25519
	}
	keyDER, err := decode(selected.Key)
	if err != nil {
		return result, err
	}
	result.private, err = x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return result, err
	}
	result.scheme = selected.Scheme
	result.issuer = 0x0804
	result.expiry = f.Now + 86400
	leafName := "valid"
	switch options.Mode {
	case "valid", "omit", "bad-issuer", "bad-cv", "wrong-role", "wrong-expected", "bad-key", "rsa-key", "sha1-cv", "sha1-issuer", "pkcs1-issuer", "duplicate", "nonleaf", "serverhello", "encryptedextensions", "hrr", "unadvertised-delegated", "bad-finished", "truncated", "trailing", "empty-spki", "empty-signature", "unadvertised", "bad-delegated-scheme", "certificate-context":
	case "expired":
		result.expiry = f.Now - 1
	case "seven-days":
		result.expiry = f.Now + 604800
	case "too-long":
		result.expiry = f.Now + 604801
	case "now-expiry":
		result.expiry = f.Now
	case "cert-expiry":
		leafName = "short"
	case "short-inside":
		leafName = "short"
		result.expiry--
	case "missing_usage", "critical_usage", "malformed_usage", "duplicate_usage", "missing_key_usage", "wrong_key_usage":
		leafName = options.Mode
	default:
		if options.IssuerCase == "" {
			return result, errors.New("unknown DC fault")
		}
	}
	result.certificate, err = decode(f.Certificates[leafName])
	if err != nil {
		return result, err
	}
	if options.IssuerCase != "" {
		if options.Curve != "P-256" || options.Mode != "valid" {
			return result, errors.New("issuer fixture requires P-256 and valid mode")
		}
		for _, item := range f.IssuerCases {
			if item.Name == options.IssuerCase {
				result.certificate, err = decode(item.Certificate)
				if err != nil {
					return result, err
				}
				result.wire, err = decode(item.Credential)
				if err != nil {
					return result, err
				}
				r := reader{p: result.wire}
				r.uint(4)
				r.uint(2)
				r.vector(3)
				result.issuer = uint16(r.uint(2))
				return result, nil
			}
		}
		return result, errors.New("unknown issuer fixture")
	}
	if options.Mode != "critical_usage" && options.Mode != "duplicate_usage" {
		if err = f.verifyCertificate(result.certificate, false); err != nil {
			return result, fmt.Errorf("fixture certificate: %w", err)
		}
	}
	spki, err := decode(selected.SPKI)
	if err != nil {
		return result, err
	}
	if options.Mode == "bad-key" {
		spki, err = decode(f.Curves[1].SPKI)
	}
	if options.Mode == "rsa-key" || options.Mode == "bad-delegated-scheme" {
		parsed, e := x509.ParseCertificate(result.certificate)
		if e != nil {
			return result, e
		}
		spki = parsed.RawSubjectPublicKeyInfo
	}
	if err != nil {
		return result, err
	}
	expected := result.scheme
	if options.Mode == "wrong-expected" {
		expected = 0x0503
	}
	if options.Mode == "bad-delegated-scheme" {
		expected = 0x0804
		result.scheme = expected
	}
	if options.Mode == "sha1-cv" {
		expected = 0x0203
		result.scheme = expected
	}
	cred := binary.BigEndian.AppendUint32(nil, uint32(result.expiry-f.NotBefore))
	cred = binary.BigEndian.AppendUint16(cred, expected)
	cred = append(cred, vector24(spki)...)
	if options.Mode == "sha1-issuer" {
		result.issuer = 0x0201
	}
	if options.Mode == "pkcs1-issuer" {
		result.issuer = 0x0401
	}
	issuerDER, err := decode(f.IssuerKey)
	if err != nil {
		return result, err
	}
	issuer, err := x509.ParsePKCS8PrivateKey(issuerDER)
	if err != nil {
		return result, err
	}
	role := "server"
	if options.Mode == "wrong-role" {
		role = "client"
	}
	sig, err := signature(issuer, result.issuer, delegationInput(result.certificate, cred, result.issuer, role))
	if err != nil {
		return result, err
	}
	if options.Mode == "bad-issuer" {
		sig[len(sig)-1] ^= 1
	}
	result.wire = append(binary.BigEndian.AppendUint16(cred, result.issuer), vector16(sig)...)
	switch options.Mode {
	case "truncated":
		result.wire = result.wire[:len(result.wire)-1]
	case "trailing":
		result.wire = append(result.wire, 0)
	case "empty-spki":
		result.wire[6], result.wire[7], result.wire[8] = 0, 0, 0
	case "empty-signature":
		at := len(cred) + 2
		result.wire[at], result.wire[at+1] = 0, 0
	case "certificate-context":
		result.certificate, err = decode(f.Certificates["alternate"])
	}
	return result, err
}
