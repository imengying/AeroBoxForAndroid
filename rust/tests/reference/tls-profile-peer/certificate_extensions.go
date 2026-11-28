// Explicit TLS1.3 CertificateEntry extension fixtures. This file belongs only
// to the independent Go test peer, never to the Rust runtime.
package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"time"

	"golang.org/x/crypto/ocsp"
)

func (o peerOptions) validateCertificateExtensionOptions() error {
	if o.UnsolicitedSCT && o.SCT != "" {
		return errors.New("unsolicited-sct cannot be combined with -sct")
	}
	if o.UnsolicitedOCSP && o.OCSP {
		return errors.New("unsolicited-ocsp cannot be combined with -ocsp")
	}
	if (o.UnsolicitedSCT || o.UnsolicitedOCSP || o.OCSP) && (o.Tickets != nil || o.EarlyMode != "" || o.Reality != "" || o.UnadvertisedSignature || o.SHA1Signature != "") {
		return errors.New("certificate extension fixture requires fresh ordinary TLS with the RSA leaf")
	}
	return nil
}

// A real RSA/SHA256 OCSP Good response signed by this fixture's self-signed CA.
// Runtime TLS certificate verification remains separate from OCSP status policy.
func referenceOCSP(certDER []byte, key *rsa.PrivateKey) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}
	now := time.Unix(1893456000, 0)
	return ocsp.CreateResponse(cert, cert, ocsp.Response{Status: ocsp.Good, SerialNumber: cert.SerialNumber,
		ThisUpdate: now.Add(-time.Hour), NextUpdate: now.Add(time.Hour), SignatureAlgorithm: x509.SHA256WithRSA}, key)
}

func certificateExtensionFixture(hello clientHello, o peerOptions, certDER []byte, key *rsa.PrivateKey) ([]byte, error) {
	if err := o.validateCertificateExtensionOptions(); err != nil {
		return nil, err
	}
	var result []byte
	if o.SCT != "" || o.UnsolicitedSCT {
		offered, exists := hello.extensions[18]
		if o.UnsolicitedSCT {
			if exists {
				return nil, errors.New("unsolicited SCT fixture requires no client SCT offer")
			}
		} else if !exists || len(offered) != 0 {
			return nil, errors.New("SCT not offered")
		}
		mode := o.SCT
		if o.UnsolicitedSCT {
			mode = "valid"
		}
		var timestamps []byte
		switch mode {
		case "valid":
			timestamps = vector16(append(vector16([]byte("opaque timestamp one")), vector16([]byte("opaque timestamp two"))...))
		case "empty":
			timestamps = []byte{0, 0}
		case "empty-entry":
			timestamps = []byte{0, 2, 0, 0}
		case "trailing":
			timestamps = append(vector16(vector16([]byte("opaque timestamp"))), 0)
		default:
			return nil, errors.New("unknown SCT mode")
		}
		result = append(result, extension(18, timestamps)...)
	}
	if o.OCSP || o.UnsolicitedOCSP {
		offered, exists := hello.extensions[5]
		if o.UnsolicitedOCSP {
			if exists {
				return nil, errors.New("unsolicited OCSP fixture requires no client status_request offer")
			}
		} else if !exists || !bytes.Equal(offered, []byte{1, 0, 0, 0, 0}) {
			return nil, errors.New("OCSP status_request not offered")
		}
		response, err := referenceOCSP(certDER, key)
		if err != nil {
			return nil, err
		}
		result = append(result, extension(5, append([]byte{1}, vector24(response)...))...)
	}
	return result, nil
}
