// Additional explicit Android browser reference modes; old peer defaults stay intact.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

const browserPayloadBytes = 65537
const browserExporterLabel = "aerobox android browser tls13 exporter"

var browserExporterContext = []byte{0, 'a', 'n', 'd', 'r', 'o', 'i', 'd', 0, 't', 'l', 's', '1', '3', 0}

func browserClientCertificate(keyDER []byte) ([]byte, error) {
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return nil, err
	}
	key, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("browser client fixture requires RSA")
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(202611251), Subject: pkix.Name{CommonName: "AeroBox Android TLS13 client fixture"},
		NotBefore: time.Unix(1577836800, 0), NotAfter: time.Unix(2208988800, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true, SignatureAlgorithm: x509.SHA256WithRSA,
	}
	return x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
}

func validateBrowserClientCertificate(der, serverDER []byte) error {
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return err
	}
	server, err := x509.ParseCertificate(serverDER)
	if err != nil {
		return err
	}
	if !bytes.Equal(leaf.RawSubjectPublicKeyInfo, server.RawSubjectPublicKeyInfo) {
		return errors.New("unexpected browser client fixture key")
	}
	if err = leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature); err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf) // Explicitly trusted disposable fixture, also pinned in authenticateClient.
	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Unix(1893456000, 0),
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	return err
}

// A SHA256/RSA-signed, trusted ECDSA leaf ensures the negative is the TLS1.3
// SHA1 CertificateVerify algorithm, not a bad certificate signature or name.
func sha1Certificate(issuer []byte, key *rsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	parent, err := x509.ParseCertificate(issuer)
	if err != nil {
		return nil, nil, err
	}
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(202611252), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Unix(1577836800, 0), NotAfter: time.Unix(2208988800, 0), DNSNames: []string{"localhost"},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, SignatureAlgorithm: x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &private.PublicKey, key)
	return der, private, err
}

func browserPattern(server bool) []byte {
	out := make([]byte, browserPayloadBytes)
	for i := range out {
		if server {
			out[i] = byte((i*29 + 7) % 251)
		} else {
			out[i] = byte((i*17 + 3) % 251)
		}
	}
	return out
}

func browserExchange(conn net.Conn, client, server *protection, exporterMaster []byte, result peerResult) (peerResult, error) {
	// RFC8446 7.5: derive with Hash("") then expand with Hash(context).
	exporter := expand(derive(exporterMaster, browserExporterLabel, nil), "exporter", digest(browserExporterContext), 32)
	serverData := browserPattern(true)
	written := make(chan error, 1)
	go func() {
		data := append(append([]byte("AB13"), exporter...), serverData...)
		for len(data) > 0 {
			n := min(len(data), 16384)
			if err := server.write(conn, 23, data[:n]); err != nil {
				written <- err
				return
			}
			data = data[n:]
		}
		written <- nil
	}()
	clientData := make([]byte, 0, browserPayloadBytes)
	for len(clientData) < browserPayloadBytes {
		typ, payload, err := client.read(conn)
		if err != nil {
			return result, err
		}
		if typ != 23 || len(payload) == 0 || len(clientData)+len(payload) > browserPayloadBytes {
			return result, errors.New("unexpected browser application frame")
		}
		clientData = append(clientData, payload...)
	}
	if !bytes.Equal(clientData, browserPattern(false)) {
		return result, errors.New("browser client data mismatch")
	}
	if err := <-written; err != nil {
		return result, err
	}
	typ, payload, err := client.read(conn)
	if err != nil {
		return result, err
	}
	if typ != 21 || !bytes.Equal(payload, []byte{1, 0}) {
		return result, fmt.Errorf("missing browser client close_notify: type=%d", typ)
	}
	if err = server.write(conn, 21, []byte{1, 0}); err != nil {
		return result, err
	}
	clientHash, serverHash := sha256.Sum256(clientData), sha256.Sum256(serverData)
	result.Exporter, result.Bytes = hex.EncodeToString(exporter), browserPayloadBytes
	result.ClientSHA256, result.ServerSHA256 = hex.EncodeToString(clientHash[:]), hex.EncodeToString(serverHash[:])
	result.CloseNotify = true
	return result, nil
}
