// Independent test material only; no Go code is linked into AeroBox.
package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

func main() {
	directory := os.Args[1]
	if err := os.MkdirAll(directory, 0755); err != nil {
		panic(err)
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 8192)
	if err != nil {
		panic(err)
	}
	before := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)
	after := time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	ca := &x509.Certificate{SerialNumber: big.NewInt(8192001), Subject: pkix.Name{CommonName: "AeroBox independent RSA-2048 test CA"}, NotBefore: before, NotAfter: after, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(8192002), Subject: pkix.Name{CommonName: "rsa8192.aerobox.test"}, DNSNames: []string{"rsa8192.aerobox.test"}, NotBefore: before, NotAfter: after, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		panic(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		panic(err)
	}
	files := map[string][]byte{"ca.der": caDER, "leaf.der": leafDER, "key.der": keyDER, "public.der": x509.MarshalPKCS1PublicKey(&leafKey.PublicKey), "ca.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), "leaf.pem": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), "key.pem": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})}
	message := []byte("AeroBox independent Go RSA-8192 fixture")
	files["message.bin"] = message
	for _, entry := range []struct {
		name string
		hash crypto.Hash
	}{{"sha256", crypto.SHA256}, {"sha384", crypto.SHA384}, {"sha512", crypto.SHA512}} {
		hasher := entry.hash.New()
		hasher.Write(message)
		digest := hasher.Sum(nil)
		pkcs1, err := rsa.SignPKCS1v15(rand.Reader, leafKey, entry.hash, digest)
		if err != nil {
			panic(err)
		}
		pss, err := rsa.SignPSS(rand.Reader, leafKey, entry.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			panic(err)
		}
		if err := rsa.VerifyPKCS1v15(&leafKey.PublicKey, entry.hash, digest, pkcs1); err != nil {
			panic(err)
		}
		if err := rsa.VerifyPSS(&leafKey.PublicKey, entry.hash, digest, pss, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}); err != nil {
			panic(err)
		}
		files["pkcs1-"+entry.name+".sig"] = pkcs1
		files["pss-"+entry.name+".sig"] = pss
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(directory, name), data, 0600); err != nil {
			panic(err)
		}
	}
	fmt.Printf("Generated RSA-%d leaf signed by RSA-%d CA in %s\n", leafKey.N.BitLen(), caKey.N.BitLen(), directory)
}
