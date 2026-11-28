package main

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"errors"
)

func authenticateClient(read func() ([]byte, error), transcript, certificateDER []byte) ([]byte, error) {
	certificate, err := read()
	if err != nil {
		return nil, err
	}
	if certificate[0] != 11 {
		return nil, errors.New("missing client Certificate after ALPS")
	}
	body := reader{p: certificate[4:]}
	context := body.vector(1)
	chain := reader{p: body.vector(3)}
	leaf := chain.vector(3)
	extensions := chain.vector(2)
	if body.done() != nil || chain.done() != nil || len(context) != 0 || len(extensions) != 0 || !bytes.Equal(leaf, certificateDER) {
		return nil, errors.New("unexpected client certificate (test peer pins the fixture)")
	}
	transcript = append(transcript, certificate...)
	verify, err := read()
	if err != nil {
		return nil, err
	}
	if verify[0] != 15 {
		return nil, errors.New("missing client CertificateVerify")
	}
	body = reader{p: verify[4:]}
	algorithm := body.uint(2)
	signature := body.vector(2)
	if algorithm != 0x804 || body.done() != nil {
		return nil, errors.New("invalid client signature algorithm")
	}
	fixture, err := x509.ParseCertificate(certificateDER)
	if err != nil {
		return nil, err
	}
	input := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, client CertificateVerify\x00")...)
	input = append(input, digest(transcript)...)
	if err = rsa.VerifyPSS(fixture.PublicKey.(*rsa.PublicKey), crypto.SHA256, digest(input), signature, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}); err != nil {
		return nil, err
	}
	return append(transcript, verify...), nil
}
