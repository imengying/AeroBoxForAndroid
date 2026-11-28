package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
)

type clientHello struct {
	session, random, ciphers []byte
	extensions               map[uint16][]byte
	shares                   map[uint16][]byte
	shareOrder               []uint16
}

func parseHello(message []byte) (hello clientHello, err error) {
	return parseHelloWithCipherRequirement(message, true)
}
func parseHelloWithCipherRequirement(message []byte, requireAES128 bool) (hello clientHello, err error) {
	if len(message) < 4 || message[0] != 1 {
		return hello, errors.New("expected ClientHello")
	}
	r := reader{p: message[4:]}
	if r.uint(2) != 0x303 {
		return hello, errors.New("ClientHello legacy version")
	}
	hello.random = r.take(32)
	hello.session = r.vector(1)
	hello.ciphers = r.vector(2)
	if (requireAES128 && !has16(hello.ciphers, 0x1301)) || !bytes.Equal(r.vector(1), []byte{0}) {
		return hello, errors.New("AES128GCM TLS13 not offered")
	}
	hello.extensions, err = extensions(r.p)
	if err != nil || r.err != nil {
		return hello, errors.New("invalid ClientHello extensions")
	}
	versions := reader{p: hello.extensions[43]}
	if !has16(versions.vector(1), 0x304) {
		return hello, errors.New("TLS13 not offered")
	}
	sigs := reader{p: hello.extensions[13]}
	if !has16(sigs.vector(2), 0x804) {
		return hello, errors.New("RSA-PSS SHA256 not offered")
	}
	outer := reader{p: hello.extensions[51]}
	shares := reader{p: outer.vector(2)}
	hello.shares = map[uint16][]byte{}
	for len(shares.p) > 0 && shares.err == nil {
		group := uint16(shares.uint(2))
		key := shares.vector(2)
		if _, ok := hello.shares[group]; ok {
			return hello, errors.New("duplicate key share")
		}
		hello.shares[group] = key
		hello.shareOrder = append(hello.shareOrder, group)
	}
	if err = outer.done(); err != nil {
		return hello, err
	}
	return hello, shares.done()
}
func serverHello(session, random, keyShare []byte) []byte {
	body := append([]byte{3, 3}, random...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = append(body, 0x13, 1, 0)
	exts := extension(43, []byte{3, 4})
	if keyShare != nil {
		exts = append(exts, extension(51, keyShare)...)
	}
	return handshakeMessage(2, append(body, vector16(exts)...))
}
func helloRetry(session []byte, group uint16, cookieOnly bool) []byte {
	random, _ := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
	if cookieOnly {
		message := serverHello(session, random, nil)
		pos := 4 + 2 + 32 + 1 + len(session) + 2 + 1
		return handshakeMessage(2, append(append([]byte(nil), message[4:pos]...), vector16(append(append([]byte(nil), message[pos+2:]...), extension(44, vector16([]byte("aerobox-cookie")))...))...))
	}
	return serverHello(session, random, binary.BigEndian.AppendUint16(nil, group))
}
func exchange(group uint16, public []byte) (server, shared []byte, err error) {
	var curve ecdh.Curve
	var pqKey *mlkem.EncapsulationKey768
	switch group {
	case 256, 257:
		return ffdheExchange(group, public)
	case 29:
		curve = ecdh.X25519()
	case 23:
		curve = ecdh.P256()
	case 24:
		curve = ecdh.P384()
	case 25:
		curve = ecdh.P521()
	case 0x11ec:
		curve = ecdh.X25519()
		if len(public) != 1216 {
			return nil, nil, errors.New("invalid X25519MLKEM768 share length")
		}
		pqKey, err = mlkem.NewEncapsulationKey768(public[:1184])
		if err != nil {
			return nil, nil, err
		}
		public = public[1184:]
	default:
		return nil, nil, errors.New("unsupported group")
	}
	peer, err := curve.NewPublicKey(public)
	if err != nil {
		return nil, nil, err
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	shared, err = key.ECDH(peer)
	if err != nil {
		return nil, nil, err
	}
	server = key.PublicKey().Bytes()
	if pqKey != nil {
		pqSecret, ciphertext := pqKey.Encapsulate()
		server = append(ciphertext, server...)
		shared = append(pqSecret, shared...)
	}
	return server, shared, nil
}
