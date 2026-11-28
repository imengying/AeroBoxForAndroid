// Independent three-suite TLS1.3 key schedule, copied and adapted from the
// previously validated delegated-credential peer. Default wire.go stays 1301.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

type dynamicSuite struct {
	id            uint16
	hash          func() hash.Hash
	size, keySize int
	chacha        bool
}

func getDynamicSuite(id uint16) (dynamicSuite, error) {
	switch id {
	case 0x1301:
		return dynamicSuite{id, sha256.New, 32, 16, false}, nil
	case 0x1302:
		return dynamicSuite{id, sha512.New384, 48, 32, false}, nil
	case 0x1303:
		return dynamicSuite{id, sha256.New, 32, 32, true}, nil
	default:
		return dynamicSuite{}, errors.New("unsupported dynamic TLS1.3 suite")
	}
}
func (s dynamicSuite) digest(p []byte) []byte { h := s.hash(); h.Write(p); return h.Sum(nil) }
func (s dynamicSuite) expand(secret []byte, label string, context []byte, length int) []byte {
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
func (s dynamicSuite) derive(secret []byte, label string, transcript []byte) []byte {
	return s.expand(secret, label, s.digest(transcript), s.size)
}
func (s dynamicSuite) finished(secret, transcript []byte) []byte {
	h := hmac.New(s.hash, s.expand(secret, "finished", nil, s.size))
	h.Write(s.digest(transcript))
	return h.Sum(nil)
}
func (s dynamicSuite) protect(secret []byte) (*protection, error) {
	key := s.expand(secret, "key", nil, s.keySize)
	var aead cipher.AEAD
	var err error
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
		return nil, err
	}
	return &protection{aead: aead, iv: s.expand(secret, "iv", nil, 12)}, nil
}
func selectDynamicSuite(ciphers []byte, wanted uint16) (dynamicSuite, error) {
	if wanted != 0 {
		if !has16(ciphers, wanted) {
			return dynamicSuite{}, errors.New("explicit REALITY suite was not offered")
		}
		return getDynamicSuite(wanted)
	}
	for i := 0; i+1 < len(ciphers); i += 2 {
		id := binary.BigEndian.Uint16(ciphers[i:])
		if id >= 0x1301 && id <= 0x1303 {
			return getDynamicSuite(id)
		}
	}
	return dynamicSuite{}, errors.New("no dynamic TLS1.3 suite offered")
}
func serverHelloSuite(session, random, keyShare []byte, suite uint16) []byte {
	message := serverHello(session, random, keyShare)
	pos := 4 + 2 + 32 + 1 + len(session)
	binary.BigEndian.PutUint16(message[pos:pos+2], suite)
	return message
}
func helloRetrySuite(session []byte, group uint16, cookie bool, suite uint16) []byte {
	message := helloRetry(session, group, cookie)
	pos := 4 + 2 + 32 + 1 + len(session)
	binary.BigEndian.PutUint16(message[pos:pos+2], suite)
	return message
}
