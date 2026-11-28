package main

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
)

// Inspect only server plaintext handshake records before ChangeCipherSpec.
// TLS bytes are forwarded unchanged, and both parser buffers have strict caps.
type observedConn struct {
	net.Conn
	record, handshake                    []byte
	encrypted                            bool
	extendedMasterSecret, ocspNegotiated bool
	serverHelloSeen                      bool
	ocspResponse                         []byte
	err                                  error
}

func (c *observedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if err == io.EOF {
		// Go TLS deliberately accepts bare TCP EOF at a record boundary. Turn
		// transport EOF into a distinct error so only a decrypted close_notify
		// can produce the io.EOF asserted by this fixture.
		if n > 0 {
			return n, nil
		}
		return 0, errors.New("TCP EOF without authenticated TLS close_notify")
	}
	return n, err
}

func (c *observedConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 && c.err == nil && !c.encrypted {
		c.observe(p[:n])
	}
	return n, err
}

func (c *observedConn) observe(p []byte) {
	if len(c.record)+len(p) > 131072 {
		c.err = errors.New("record observation limit")
		return
	}
	c.record = append(c.record, p...)
	for len(c.record) >= 5 {
		length := int(binary.BigEndian.Uint16(c.record[3:5]))
		if length > 18432 {
			c.err = errors.New("oversized observed TLS record")
			return
		}
		if len(c.record) < 5+length {
			return
		}
		kind := c.record[0]
		body := c.record[5 : 5+length]
		if kind == 20 {
			c.encrypted = true
			c.record = nil
			c.handshake = nil
			return
		}
		if kind == 22 {
			if len(c.handshake)+len(body) > 131072 {
				c.err = errors.New("handshake observation limit")
				return
			}
			c.handshake = append(c.handshake, body...)
			c.parseHandshake()
			if c.err != nil {
				return
			}
		}
		c.record = c.record[5+length:]
	}
}

func (c *observedConn) parseHandshake() {
	for len(c.handshake) >= 4 {
		n := int(c.handshake[1])<<16 | int(c.handshake[2])<<8 | int(c.handshake[3])
		if n > 131068 {
			c.err = errors.New("oversized observed handshake")
			return
		}
		if len(c.handshake) < 4+n {
			return
		}
		body := c.handshake[4 : 4+n]
		switch c.handshake[0] {
		case 2:
			c.parseServerHello(body)
		case 22:
			if len(body) < 4 || body[0] != 1 || (int(body[1])<<16|int(body[2])<<8|int(body[3])) != len(body)-4 {
				c.err = errors.New("malformed observed CertificateStatus")
				return
			}
			c.ocspResponse = append([]byte(nil), body[4:]...)
		}
		if c.err != nil {
			return
		}
		c.handshake = c.handshake[4+n:]
	}
}

func (c *observedConn) parseServerHello(body []byte) {
	c.serverHelloSeen = true
	if len(body) < 38 {
		c.err = errors.New("short ServerHello")
		return
	}
	offset := 35 + int(body[34]) + 3 // version/random/session-id/cipher/compression
	if offset == len(body) {
		return
	}
	if offset+2 > len(body) || int(binary.BigEndian.Uint16(body[offset:offset+2])) != len(body)-offset-2 {
		c.err = errors.New("malformed ServerHello extension vector")
		return
	}
	extensions := body[offset+2:]
	for len(extensions) != 0 {
		if len(extensions) < 4 {
			c.err = errors.New("short ServerHello extension")
			return
		}
		typ, size := binary.BigEndian.Uint16(extensions[:2]), int(binary.BigEndian.Uint16(extensions[2:4]))
		if size > len(extensions)-4 {
			c.err = errors.New("oversized ServerHello extension")
			return
		}
		if typ == 23 {
			c.extendedMasterSecret = size == 0
		}
		if typ == 5 {
			c.ocspNegotiated = size == 0
		}
		extensions = extensions[4+size:]
	}
}
