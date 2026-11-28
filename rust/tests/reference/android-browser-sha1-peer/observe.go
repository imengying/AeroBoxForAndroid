package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Observe both plaintext handshake directions without modifying TLS bytes.
// CertificateVerify, ServerKeyExchange and CertificateRequest precede CCS.
type handshakeObserver struct {
	record, handshake        []byte
	encrypted                bool
	err                      error
	extendedMasterSecret     bool
	ocspNegotiated           bool
	ocspResponse             []byte
	clientSignatureSchemes   []uint16
	serverSignature          uint16
	requestSignatureSchemes  []uint16
	clientSignature          uint16
	clientHellos, serverKeys int
	certificateRequests      int
	certificateVerifies      int
}

type observedConn struct {
	net.Conn
	client, server handshakeObserver
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.client.observe(p[:n], false)
	}
	if err == io.EOF {
		if n > 0 {
			return n, nil
		}
		return 0, errors.New("TCP EOF without authenticated TLS close_notify")
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.server.observe(p[:n], true)
	}
	return n, err
}

func (c *observedConn) validate(mutual bool) error {
	if c.client.err != nil {
		return c.client.err
	}
	if c.server.err != nil {
		return c.server.err
	}
	if c.client.clientHellos != 1 || !containsSHA1(c.client.clientSignatureSchemes) ||
		c.server.serverKeys != 1 || c.server.serverSignature != 0x0203 {
		return errors.New("missing or wrong ECDSA-SHA1 ServerKeyExchange")
	}
	if !c.server.extendedMasterSecret || !c.server.ocspNegotiated || !bytes.Equal(c.server.ocspResponse, staple) {
		return errors.New("missing EMS or expected OCSP transport fixture")
	}
	if mutual {
		if c.server.certificateRequests != 1 || len(c.server.requestSignatureSchemes) != 1 ||
			c.server.requestSignatureSchemes[0] != 0x0203 || c.client.certificateVerifies != 1 || c.client.clientSignature != 0x0203 {
			return errors.New("missing or wrong ECDSA-SHA1 CertificateRequest/CertificateVerify")
		}
	} else if c.server.certificateRequests != 0 || c.client.certificateVerifies != 0 {
		return errors.New("unexpected client authentication")
	}
	return nil
}

func containsSHA1(schemes []uint16) bool {
	for _, scheme := range schemes {
		if scheme == 0x0203 {
			return true
		}
	}
	return false
}

func (c *observedConn) report() map[string]any {
	request := append([]uint16{}, c.server.requestSignatureSchemes...)
	return map[string]any{
		"client_offered_ecdsa_sha1": containsSHA1(c.client.clientSignatureSchemes),
		"server_signature":          c.server.serverSignature, "certificate_request": request,
		"client_signature": c.client.clientSignature,
		"ems":              c.server.extendedMasterSecret,
		"ocsp":             c.server.ocspNegotiated && bytes.Equal(c.server.ocspResponse, staple),
	}
}

func (o *handshakeObserver) observe(p []byte, server bool) {
	if o.err != nil || o.encrypted {
		return
	}
	if len(o.record)+len(p) > 131072 {
		o.err = errors.New("record observation limit")
		return
	}
	o.record = append(o.record, p...)
	for len(o.record) >= 5 {
		length := int(binary.BigEndian.Uint16(o.record[3:5]))
		if length > 18432 {
			o.err = errors.New("oversized observed TLS record")
			return
		}
		if len(o.record) < 5+length {
			return
		}
		kind, body := o.record[0], o.record[5:5+length]
		if kind == 20 {
			if !bytes.Equal(body, []byte{1}) || len(o.handshake) != 0 {
				o.err = errors.New("malformed observed ChangeCipherSpec")
				return
			}
			o.encrypted = true
			o.record, o.handshake = nil, nil
			return
		}
		if kind == 22 {
			if len(o.handshake)+len(body) > 131072 {
				o.err = errors.New("handshake observation limit")
				return
			}
			o.handshake = append(o.handshake, body...)
			o.parseHandshake(server)
			if o.err != nil {
				return
			}
		}
		o.record = o.record[5+length:]
	}
}

func (o *handshakeObserver) parseHandshake(server bool) {
	for len(o.handshake) >= 4 {
		n := int(o.handshake[1])<<16 | int(o.handshake[2])<<8 | int(o.handshake[3])
		if n > 131068 {
			o.err = errors.New("oversized observed handshake")
			return
		}
		if len(o.handshake) < 4+n {
			return
		}
		kind, body := o.handshake[0], o.handshake[4:4+n]
		if server {
			switch kind {
			case 2:
				o.parseHello(body, true)
			case 12:
				o.serverKeys++
				if len(body) < 8 || body[0] != 3 {
					o.err = errors.New("malformed observed ServerKeyExchange")
					break
				}
				offset := 4 + int(body[3])
				if offset > len(body) {
					o.err = errors.New("oversized ServerKeyExchange public key")
					break
				}
				o.serverSignature = o.parseSignature(body[offset:])
			case 13:
				o.certificateRequests++
				o.parseCertificateRequest(body)
			case 22:
				if len(body) < 4 || body[0] != 1 || (int(body[1])<<16|int(body[2])<<8|int(body[3])) != len(body)-4 {
					o.err = errors.New("malformed observed CertificateStatus")
					break
				}
				o.ocspResponse = append([]byte(nil), body[4:]...)
			}
		} else {
			switch kind {
			case 1:
				o.clientHellos++
				o.parseHello(body, false)
			case 15:
				o.certificateVerifies++
				o.clientSignature = o.parseSignature(body)
			}
		}
		if o.err != nil {
			return
		}
		o.handshake = o.handshake[4+n:]
	}
}

func (o *handshakeObserver) parseSignature(body []byte) uint16 {
	if len(body) < 5 || int(binary.BigEndian.Uint16(body[2:4])) != len(body)-4 {
		o.err = errors.New("malformed observed signature")
		return 0
	}
	return binary.BigEndian.Uint16(body[:2])
}

func (o *handshakeObserver) signatureSchemes(body []byte) []uint16 {
	if len(body) < 4 || int(binary.BigEndian.Uint16(body[:2])) != len(body)-2 || len(body)%2 != 0 {
		o.err = errors.New("malformed observed signature schemes")
		return nil
	}
	out := make([]uint16, 0, (len(body)-2)/2)
	for i := 2; i < len(body); i += 2 {
		out = append(out, binary.BigEndian.Uint16(body[i:i+2]))
	}
	return out
}

func (o *handshakeObserver) parseCertificateRequest(body []byte) {
	if len(body) < 1 {
		o.err = errors.New("empty CertificateRequest")
		return
	}
	offset := 1 + int(body[0])
	if offset+2 > len(body) {
		o.err = errors.New("short CertificateRequest certificate types")
		return
	}
	size := int(binary.BigEndian.Uint16(body[offset:offset+2])) + 2
	if offset+size+2 > len(body) {
		o.err = errors.New("short CertificateRequest signature list")
		return
	}
	o.requestSignatureSchemes = o.signatureSchemes(body[offset : offset+size])
	offset += size
	if int(binary.BigEndian.Uint16(body[offset:offset+2])) != len(body)-offset-2 {
		o.err = errors.New("malformed CertificateRequest CA vector")
	}
}

func (o *handshakeObserver) parseHello(body []byte, server bool) {
	if len(body) < 35 {
		o.err = errors.New("short Hello")
		return
	}
	offset := 35 + int(body[34])
	if server {
		offset += 3 // cipher suite and compression
	} else {
		if offset+2 > len(body) {
			o.err = errors.New("short ClientHello cipher suites")
			return
		}
		offset += 2 + int(binary.BigEndian.Uint16(body[offset:offset+2]))
		if offset >= len(body) {
			o.err = errors.New("short ClientHello compression")
			return
		}
		offset += 1 + int(body[offset])
	}
	if offset+2 > len(body) || int(binary.BigEndian.Uint16(body[offset:offset+2])) != len(body)-offset-2 {
		o.err = errors.New("malformed Hello extension vector")
		return
	}
	extensions := body[offset+2:]
	for len(extensions) != 0 {
		if len(extensions) < 4 {
			o.err = errors.New("short Hello extension")
			return
		}
		typ, size := binary.BigEndian.Uint16(extensions[:2]), int(binary.BigEndian.Uint16(extensions[2:4]))
		if size > len(extensions)-4 {
			o.err = errors.New("oversized Hello extension")
			return
		}
		if server && typ == 23 {
			o.extendedMasterSecret = size == 0
		}
		if server && typ == 5 {
			o.ocspNegotiated = size == 0
		}
		if !server && typ == 13 {
			o.clientSignatureSchemes = o.signatureSchemes(extensions[4 : 4+size])
		}
		extensions = extensions[4+size:]
	}
}
