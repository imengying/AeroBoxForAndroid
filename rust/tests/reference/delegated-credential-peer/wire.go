// Independent test-only TLS1.3 record/key-schedule utilities. Derived from the
// previously validated TLS profile peer; never part of AeroBox runtime.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func vector16(p []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...)
}
func vector24(p []byte) []byte {
	return append([]byte{byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p))}, p...)
}
func handshakeMessage(kind byte, body []byte) []byte { return append([]byte{kind}, vector24(body)...) }
func extension(id uint16, body []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, id), vector16(body)...)
}

type suite struct {
	id            uint16
	hash          func() hash.Hash
	size, keySize int
	chacha        bool
}

func getSuite(id uint16) (suite, error) {
	switch id {
	case 0x1301:
		return suite{id, sha256.New, 32, 16, false}, nil
	case 0x1302:
		return suite{id, sha512.New384, 48, 32, false}, nil
	case 0x1303:
		return suite{id, sha256.New, 32, 32, true}, nil
	default:
		return suite{}, errors.New("unsupported TLS1.3 suite")
	}
}
func (s suite) digest(p []byte) []byte { h := s.hash(); h.Write(p); return h.Sum(nil) }
func (s suite) expand(secret []byte, label string, context []byte, length int) []byte {
	name := []byte("tls13 " + label)
	info := binary.BigEndian.AppendUint16(nil, uint16(length))
	info = append(info, byte(len(name)))
	info = append(info, name...)
	info = append(info, byte(len(context)))
	info = append(info, context...)
	out := make([]byte, length)
	if _, err := io.ReadFull(hkdf.Expand(s.hash, secret, info), out); err != nil {
		panic(err)
	}
	return out
}
func (s suite) derive(secret []byte, label string, transcript []byte) []byte {
	return s.expand(secret, label, s.digest(transcript), s.size)
}
func (s suite) finished(secret, transcript []byte) []byte {
	hash := hmac.New(s.hash, s.expand(secret, "finished", nil, s.size))
	hash.Write(s.digest(transcript))
	return hash.Sum(nil)
}

type reader struct {
	p   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.p) {
		r.err = io.ErrUnexpectedEOF
		return nil
	}
	p := r.p[:n]
	r.p = r.p[n:]
	return p
}
func (r *reader) uint(n int) int {
	v := 0
	for _, b := range r.take(n) {
		v = v<<8 | int(b)
	}
	return v
}
func (r *reader) vector(n int) []byte { size := r.uint(n); return r.take(size) }
func (r *reader) done() error {
	if r.err != nil {
		return r.err
	}
	if len(r.p) != 0 {
		return errors.New("trailing bytes")
	}
	return nil
}
func extensions(body []byte) (map[uint16][]byte, error) {
	outer := reader{p: body}
	inner := reader{p: outer.vector(2)}
	if err := outer.done(); err != nil {
		return nil, err
	}
	out := map[uint16][]byte{}
	for len(inner.p) > 0 && inner.err == nil {
		id := uint16(inner.uint(2))
		value := inner.vector(2)
		if _, duplicate := out[id]; duplicate {
			return nil, errors.New("duplicate extension")
		}
		out[id] = value
	}
	return out, inner.done()
}
func has16(values []byte, wanted uint16) bool {
	if len(values)%2 != 0 {
		return false
	}
	for i := 0; i < len(values); i += 2 {
		if binary.BigEndian.Uint16(values[i:]) == wanted {
			return true
		}
	}
	return false
}

type protection struct {
	aead     cipher.AEAD
	iv       []byte
	sequence uint64
}

func (s suite) protect(secret []byte) *protection {
	var aead cipher.AEAD
	var err error
	key := s.expand(secret, "key", nil, s.keySize)
	if s.chacha {
		aead, err = chacha20poly1305.New(key)
	} else {
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	}
	if err != nil {
		panic(err)
	}
	return &protection{aead: aead, iv: s.expand(secret, "iv", nil, 12)}
}
func (p *protection) nonce() []byte {
	iv := append([]byte(nil), p.iv...)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(p.sequence >> uint(8*i))
	}
	p.sequence++
	return iv
}
func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
func writePlain(w io.Writer, typ byte, payload []byte) error {
	return writeAll(w, append([]byte{typ, 3, 3}, vector16(payload)...))
}
func (p *protection) write(w io.Writer, typ byte, payload []byte) error {
	if len(payload) > 16384 {
		return errors.New("reference record too large")
	}
	inner := append(append([]byte(nil), payload...), typ)
	header := binary.BigEndian.AppendUint16([]byte{23, 3, 3}, uint16(len(inner)+p.aead.Overhead()))
	return writeAll(w, append(header, p.aead.Seal(nil, p.nonce(), inner, header)...))
}
func readRecord(r io.Reader) (byte, []byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, nil, err
	}
	length := int(binary.BigEndian.Uint16(header[3:]))
	if length > 16640 {
		return 0, nil, nil, errors.New("oversized record")
	}
	body := make([]byte, length)
	_, err := io.ReadFull(r, body)
	return header[0], header, body, err
}
func (p *protection) read(r io.Reader) (byte, []byte, error) {
	for {
		typ, header, body, err := readRecord(r)
		if err != nil {
			return 0, nil, err
		}
		if typ == 20 && bytes.Equal(body, []byte{1}) {
			continue
		}
		if typ != 23 || !bytes.Equal(header[1:3], []byte{3, 3}) {
			return 0, nil, errors.New("expected encrypted record")
		}
		inner, err := p.aead.Open(nil, p.nonce(), body, header)
		if err != nil {
			return 0, nil, err
		}
		for len(inner) > 0 && inner[len(inner)-1] == 0 {
			inner = inner[:len(inner)-1]
		}
		if len(inner) == 0 {
			return 0, nil, errors.New("missing inner content type")
		}
		return inner[len(inner)-1], inner[:len(inner)-1], nil
	}
}

type messages struct{ bytes []byte }

func (m *messages) next(read func() (byte, []byte, error)) ([]byte, error) {
	for {
		if len(m.bytes) >= 4 {
			n := int(m.bytes[1])<<16 | int(m.bytes[2])<<8 | int(m.bytes[3])
			if n > 65537 {
				return nil, errors.New("oversized handshake")
			}
			if len(m.bytes) >= n+4 {
				result := append([]byte(nil), m.bytes[:n+4]...)
				m.bytes = m.bytes[n+4:]
				return result, nil
			}
		}
		typ, body, err := read()
		if err != nil {
			return nil, err
		}
		if typ == 21 && len(body) == 2 {
			return nil, fmt.Errorf("peer alert level=%d description=%d", body[0], body[1])
		}
		if typ != 22 {
			return nil, fmt.Errorf("expected handshake, received %d", typ)
		}
		m.bytes = append(m.bytes, body...)
		if len(m.bytes) > 131072 {
			return nil, errors.New("handshake buffer limit")
		}
	}
}
