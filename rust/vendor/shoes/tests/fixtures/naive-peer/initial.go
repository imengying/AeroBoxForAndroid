// RFC 9001 client Initial decryption; only used by the local observation fixture.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type initialCapture struct {
	originalDCID []byte
	data         [65536]byte
	seen         [65536]bool
	complete     []byte
}

var errInitialAuthentication = errors.New("Initial packet authentication failed")

func expand(secret []byte, label string, n int) []byte {
	label = "tls13 " + label
	info := []byte{byte(n >> 8), byte(n), byte(len(label))}
	info = append(info, []byte(label)...)
	info = append(info, 0)
	out, e := hkdf.Expand(sha256.New, secret, string(info), n)
	must(e)
	return out
}
func (c *initialCapture) add(packet []byte) error {
	if len(packet) < 7 || packet[0]&0xf0 != 0xc0 || binary.BigEndian.Uint32(packet[1:5]) != 1 {
		return nil
	}
	r := bytes.NewReader(packet[5:])
	n, e := r.ReadByte()
	if e != nil {
		return e
	}
	dcid := make([]byte, n)
	if _, e = io.ReadFull(r, dcid); e != nil {
		return e
	}
	n, e = r.ReadByte()
	if e != nil {
		return e
	}
	if _, e = r.Seek(int64(n), io.SeekCurrent); e != nil {
		return e
	}
	token, e := readVar(r)
	if e != nil {
		return e
	}
	if _, e = r.Seek(int64(token), io.SeekCurrent); e != nil {
		return e
	}
	length, e := readVar(r)
	if e != nil {
		return e
	}
	offset := len(packet) - r.Len()
	if length > uint64(len(packet)-offset) || length < 20 {
		return fmt.Errorf("truncated initial")
	}
	packet = append([]byte(nil), packet[:offset+int(length)]...)
	// Subsequent client Initials address the server's SCID, but retain the
	// keys derived from the client's original destination connection ID.
	if c.originalDCID != nil {
		dcid = c.originalDCID
	}
	salt, _ := hex.DecodeString("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
	extract := hmac.New(sha256.New, salt)
	extract.Write(dcid)
	secret := expand(extract.Sum(nil), "client in", 32)
	hp, e := aes.NewCipher(expand(secret, "quic hp", 16))
	if e != nil {
		return e
	}
	mask := make([]byte, 16)
	hp.Encrypt(mask, packet[offset+4:offset+20])
	packet[0] ^= mask[0] & 15
	pnlen := int(packet[0]&3) + 1
	number := uint64(0)
	for i := 0; i < pnlen; i++ {
		packet[offset+i] ^= mask[i+1]
		number = number<<8 | uint64(packet[offset+i])
	}
	block, e := aes.NewCipher(expand(secret, "quic key", 16))
	if e != nil {
		return e
	}
	aead, e := cipher.NewGCM(block)
	if e != nil {
		return e
	}
	nonce := expand(secret, "quic iv", 12)
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(number >> (8 * i))
	}
	body, e := aead.Open(nil, nonce, packet[offset+pnlen:], packet[:offset+pnlen])
	if e != nil {
		return fmt.Errorf("%w: %v", errInitialAuthentication, e)
	}
	if c.originalDCID == nil {
		c.originalDCID = append([]byte{}, dcid...)
	}
	frames := bytes.NewReader(body)
	for frames.Len() > 0 {
		typ, e := readVar(frames)
		if e != nil {
			return e
		}
		switch typ {
		case 0, 1:
		case 2, 3:
			for i := 0; i < 2; i++ {
				if _, e = readVar(frames); e != nil {
					return e
				}
			}
			ranges, e := readVar(frames)
			if e != nil {
				return e
			}
			if ranges > 1024 {
				return fmt.Errorf("too many ACK ranges")
			}
			for i := uint64(0); i < 1+2*ranges; i++ {
				if _, e = readVar(frames); e != nil {
					return e
				}
			}
			if typ == 3 {
				for i := 0; i < 3; i++ {
					if _, e = readVar(frames); e != nil {
						return e
					}
				}
			}
		case 6:
			off, e := readVar(frames)
			if e != nil {
				return e
			}
			n, e := readVar(frames)
			if e != nil {
				return e
			}
			if off > 65536 || n > 65536-off {
				return fmt.Errorf("crypto exceeds limit")
			}
			data := make([]byte, n)
			if _, e = io.ReadFull(frames, data); e != nil {
				return e
			}
			for i, b := range data {
				p := int(off) + i
				if c.seen[p] && c.data[p] != b {
					return fmt.Errorf("conflicting CRYPTO")
				}
				c.data[p] = b
				c.seen[p] = true
			}
		default:
			return fmt.Errorf("unexpected initial frame %d", typ)
		}
	}
	if c.seen[0] && c.seen[1] && c.seen[2] && c.seen[3] {
		n := 4 + (int(c.data[1]) << 16) + (int(c.data[2]) << 8) + int(c.data[3])
		if n > 65536 {
			return fmt.Errorf("hello exceeds limit")
		}
		all := true
		for _, v := range c.seen[:n] {
			all = all && v
		}
		if all {
			c.complete = append([]byte(nil), c.data[:n]...)
		}
	}
	return nil
}
