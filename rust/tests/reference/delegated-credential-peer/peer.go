package main

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"golang.org/x/crypto/hkdf"
	"net"
	"time"
)

const payloadBytes = 65537
const exporterLabel = "aerobox delegated credential exporter"

var exporterContext = []byte("\x00android\x00rfc9345\x00")

type hello struct {
	session, random, ciphers []byte
	extensions               map[uint16][]byte
	shares                   map[uint16][]byte
}

func parseHello(message []byte, cipher uint16) (out hello, err error) {
	if len(message) < 4 || message[0] != 1 {
		return out, errors.New("expected ClientHello")
	}
	r := reader{p: message[4:]}
	if r.uint(2) != 0x303 {
		return out, errors.New("legacy ClientHello version")
	}
	out.random = r.take(32)
	out.session = r.vector(1)
	out.ciphers = r.vector(2)
	if !has16(out.ciphers, cipher) || !bytes.Equal(r.vector(1), []byte{0}) {
		return out, errors.New("selected suite/compression not offered")
	}
	out.extensions, err = extensions(r.p)
	if err != nil || r.err != nil {
		return out, errors.New("malformed ClientHello extensions")
	}
	versions := reader{p: out.extensions[43]}
	if !has16(versions.vector(1), 0x304) || versions.done() != nil {
		return out, errors.New("TLS13 not offered")
	}
	if _, ok := out.extensions[41]; ok {
		return out, errors.New("DC test must not resume a PSK")
	}
	if _, ok := out.extensions[42]; ok {
		return out, errors.New("DC test must not offer early data")
	}
	sigs := reader{p: out.extensions[13]}
	if !has16(sigs.vector(2), 0x0804) || sigs.done() != nil {
		return out, errors.New("RSA-PSS SHA256 not offered")
	}
	outer := reader{p: out.extensions[51]}
	shares := reader{p: outer.vector(2)}
	out.shares = map[uint16][]byte{}
	for len(shares.p) > 0 && shares.err == nil {
		group := uint16(shares.uint(2))
		key := shares.vector(2)
		if _, ok := out.shares[group]; ok {
			return out, errors.New("duplicate share")
		}
		out.shares[group] = key
	}
	if err = outer.done(); err != nil {
		return out, err
	}
	return out, shares.done()
}
func serverHello(session, random, keyShare []byte, cipher uint16, extra []byte) []byte {
	body := append([]byte{3, 3}, random...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = binary.BigEndian.AppendUint16(body, cipher)
	body = append(body, 0)
	exts := extension(43, []byte{3, 4})
	if keyShare != nil {
		exts = append(exts, extension(51, keyShare)...)
	}
	exts = append(exts, extra...)
	return handshakeMessage(2, append(body, vector16(exts)...))
}
func exchange(group uint16, public []byte) (server, shared []byte, err error) {
	var curve ecdh.Curve
	switch group {
	case 29:
		curve = ecdh.X25519()
	case 23:
		curve = ecdh.P256()
	case 24:
		curve = ecdh.P384()
	case 25:
		curve = ecdh.P521()
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
	return key.PublicKey().Bytes(), shared, nil
}
func advertised(h hello, dc delegated, options options) error {
	if options.Mode == "omit" {
		return nil
	}
	main := reader{p: h.extensions[13]}
	schemes := main.vector(2)
	offer := reader{p: h.extensions[34]}
	delegated := offer.vector(2)
	if options.Mode == "unadvertised" {
		if _, ok := h.extensions[34]; ok {
			return errors.New("negative client unexpectedly advertised DC")
		}
		return nil
	}
	if offer.done() != nil || len(delegated) == 0 || len(delegated)%2 != 0 {
		return errors.New("DC not offered correctly")
	}
	if options.Mode != "unadvertised-delegated" && options.Mode != "bad-delegated-scheme" && options.Mode != "sha1-cv" && !has16(delegated, dc.scheme) {
		return errors.New("delegated CV not offered")
	}
	if options.IssuerCase != "Ed25519" && options.Mode != "sha1-issuer" && !has16(schemes, dc.issuer) {
		return errors.New("issuer scheme not offered")
	}
	return nil
}
func serve(conn net.Conn, f *fixtures, options options) (out result, err error) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	s, err := getSuite(options.Cipher)
	if err != nil {
		return out, err
	}
	dc, err := credential(f, options)
	if err != nil {
		return out, err
	}
	out.Group = options.Group
	out.Cipher = s.id
	out.Delegated = options.Mode != "omit"
	out.DCAlgorithm = dc.scheme
	out.IssuerAlgorithm = dc.issuer
	var stream messages
	readPlain := func() (byte, []byte, error) {
		for {
			typ, _, body, err := readRecord(conn)
			if err == nil && typ == 20 && bytes.Equal(body, []byte{1}) {
				continue
			}
			return typ, body, err
		}
	}
	ch, err := stream.next(readPlain)
	if err != nil {
		return out, err
	}
	h, err := parseHello(ch, s.id)
	if err != nil {
		return out, err
	}
	if err = advertised(h, dc, options); err != nil {
		return out, err
	}
	var transcript []byte
	if _, ok := h.shares[options.Group]; !ok || options.Cookie || options.Mode == "hrr" {
		groupList := reader{p: h.extensions[10]}
		groups := groupList.vector(2)
		if !has16(groups, options.Group) || groupList.done() != nil {
			return out, errors.New("requested group not supported")
		}
		random, _ := hex.DecodeString("cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c")
		key := binary.BigEndian.AppendUint16(nil, options.Group)
		var extra []byte
		if options.Cookie {
			key = nil
			extra = extension(44, vector16([]byte("rfc9345-cookie")))
		}
		if options.Mode == "hrr" {
			extra = append(extra, extension(34, dc.wire)...)
		}
		hrr := serverHello(h.session, random, key, s.id, extra)
		transcript = append(handshakeMessage(254, s.digest(ch)), hrr...)
		if err = writePlain(conn, 22, hrr); err != nil {
			return out, err
		}
		ch, err = stream.next(readPlain)
		if err != nil {
			return out, err
		}
		if options.Mode == "hrr" {
			return out, errors.New("client accepted DC in HRR")
		}
		next, err := parseHello(ch, s.id)
		if err != nil {
			return out, err
		}
		if !bytes.Equal(h.session, next.session) || !bytes.Equal(h.random, next.random) || !bytes.Equal(h.ciphers, next.ciphers) || !bytes.Equal(h.extensions[13], next.extensions[13]) || !bytes.Equal(h.extensions[34], next.extensions[34]) {
			return out, errors.New("HRR changed immutable identity or signature offers")
		}
		if options.Cookie {
			if !bytes.Equal(next.extensions[44], vector16([]byte("rfc9345-cookie"))) || !bytes.Equal(h.extensions[51], next.extensions[51]) {
				return out, errors.New("invalid cookie HRR")
			}
		} else if len(next.shares) != 1 {
			return out, errors.New("HRR must produce one requested share")
		}
		h = next
		out.HelloRetry = true
		if err = advertised(h, dc, options); err != nil {
			return out, err
		}
	}
	serverShare, shared, err := exchange(options.Group, h.shares[options.Group])
	if err != nil {
		return out, err
	}
	alpnOuter := reader{p: h.extensions[16]}
	alpn := reader{p: alpnOuter.vector(2)}
	h2 := false
	for len(alpn.p) > 0 && alpn.err == nil {
		name := alpn.vector(1)
		h2 = h2 || bytes.Equal(name, []byte("h2"))
	}
	if !h2 || alpn.done() != nil || alpnOuter.done() != nil {
		return out, errors.New("h2 not offered")
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return out, err
	}
	var extra []byte
	if options.Mode == "serverhello" {
		extra = extension(34, dc.wire)
	}
	sh := serverHello(h.session, random, append(binary.BigEndian.AppendUint16(nil, options.Group), vector16(serverShare)...), s.id, extra)
	transcript = append(transcript, ch...)
	transcript = append(transcript, sh...)
	if err = writePlain(conn, 22, sh); err != nil {
		return out, err
	}
	early := hkdf.Extract(s.hash, make([]byte, s.size), nil)
	hs := hkdf.Extract(s.hash, shared, s.derive(early, "derived", nil))
	clientHS, serverHS := s.derive(hs, "c hs traffic", transcript), s.derive(hs, "s hs traffic", transcript)
	clientKeys, serverKeys := s.protect(clientHS), s.protect(serverHS)
	writeHandshake := func(message []byte) error {
		for remaining := message; len(remaining) > 0; {
			n := min(len(remaining), 1024)
			if err := serverKeys.write(conn, 22, remaining[:n]); err != nil {
				return err
			}
			remaining = remaining[n:]
		}
		transcript = append(transcript, message...)
		return nil
	}
	ee := extension(16, vector16([]byte{2, 'h', '2'}))
	if options.Mode == "encryptedextensions" {
		ee = append(ee, extension(34, dc.wire)...)
	}
	if err = writeHandshake(handshakeMessage(8, vector16(ee))); err != nil {
		return out, err
	}
	if options.Mutual {
		request := append([]byte{0}, vector16(extension(13, vector16([]byte{8, 4})))...)
		if err = writeHandshake(handshakeMessage(13, request)); err != nil {
			return out, err
		}
	}
	var leafExtensions []byte
	if options.Mode != "omit" && options.Mode != "nonleaf" {
		leafExtensions = extension(34, dc.wire)
	}
	if options.Mode == "duplicate" {
		leafExtensions = append(leafExtensions, extension(34, dc.wire)...)
	}
	chain := append(vector24(dc.certificate), vector16(leafExtensions)...)
	if options.Mode == "nonleaf" {
		root, err := decode(f.CA)
		if err != nil {
			return out, err
		}
		chain = append(chain, append(vector24(root), vector16(extension(34, dc.wire))...)...)
	}
	if err = writeHandshake(handshakeMessage(11, append([]byte{0}, vector24(chain)...))); err != nil {
		return out, err
	}
	input := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, server CertificateVerify\x00")...)
	input = append(input, s.digest(transcript)...)
	key, scheme := dc.private, dc.scheme
	if options.Mode == "omit" || options.Mode == "bad-delegated-scheme" {
		keyDER, err := decode(f.IssuerKey)
		if err != nil {
			return out, err
		}
		key, err = x509.ParsePKCS8PrivateKey(keyDER)
		if err != nil {
			return out, err
		}
		scheme = 0x0804
	}
	sig, err := signature(key, scheme, input)
	if err != nil {
		return out, err
	}
	if options.Mode == "bad-cv" {
		sig[len(sig)-1] ^= 1
	}
	if err = writeHandshake(handshakeMessage(15, append(binary.BigEndian.AppendUint16(nil, scheme), vector16(sig)...))); err != nil {
		return out, err
	}
	verify := s.finished(serverHS, transcript)
	if options.Mode == "bad-finished" {
		verify[0] ^= 1
	}
	if err = writeHandshake(handshakeMessage(20, verify)); err != nil {
		return out, err
	}
	master := hkdf.Extract(s.hash, make([]byte, s.size), s.derive(hs, "derived", nil))
	exporter := s.derive(master, "exp master", transcript)
	clientApp, serverApp := s.protect(s.derive(master, "c ap traffic", transcript)), s.protect(s.derive(master, "s ap traffic", transcript))
	readHandshake := func() ([]byte, error) {
		return stream.next(func() (byte, []byte, error) { return clientKeys.read(conn) })
	}
	if options.Mutual {
		transcript, err = authenticateClient(readHandshake, transcript, f, s)
		if err != nil {
			return out, err
		}
		out.ClientVerified = true
	}
	clientFinished, err := readHandshake()
	if err != nil {
		return out, err
	}
	if clientFinished[0] != 20 || !bytes.Equal(clientFinished[4:], s.finished(clientHS, transcript)) {
		return out, errors.New("invalid client Finished")
	}
	if len(stream.bytes) != 0 {
		return out, errors.New("unexpected buffered post-Finished handshake")
	}
	out.ClientFinished = true
	return application(conn, clientApp, serverApp, exporter, s, out)
}
func authenticateClient(read func() ([]byte, error), transcript []byte, f *fixtures, s suite) ([]byte, error) {
	certificate, err := read()
	if err != nil {
		return nil, err
	}
	if certificate[0] != 11 {
		return nil, errors.New("missing client Certificate")
	}
	body := reader{p: certificate[4:]}
	context := body.vector(1)
	chain := reader{p: body.vector(3)}
	leaf := chain.vector(3)
	exts := chain.vector(2)
	expected, err := decode(f.Certificates["valid"])
	if err != nil {
		return nil, err
	}
	if body.done() != nil || chain.done() != nil || len(context) != 0 || len(exts) != 0 || !bytes.Equal(leaf, expected) {
		return nil, errors.New("unexpected client certificate or unsolicited delegation")
	}
	if err = f.verifyCertificate(leaf, true); err != nil {
		return nil, fmt.Errorf("client chain: %w", err)
	}
	transcript = append(transcript, certificate...)
	cv, err := read()
	if err != nil {
		return nil, err
	}
	if cv[0] != 15 {
		return nil, errors.New("missing client CV")
	}
	body = reader{p: cv[4:]}
	scheme := body.uint(2)
	sig := body.vector(2)
	if scheme != 0x0804 || body.done() != nil {
		return nil, errors.New("wrong client CV algorithm")
	}
	parsed, err := x509.ParseCertificate(leaf)
	if err != nil {
		return nil, err
	}
	public, ok := parsed.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("RSA fixture required")
	}
	input := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, client CertificateVerify\x00")...)
	input = append(input, s.digest(transcript)...)
	hash := sha256.Sum256(input)
	if err = rsa.VerifyPSS(public, crypto.SHA256, hash[:], sig, &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256}); err != nil {
		return nil, err
	}
	return append(transcript, cv...), nil
}
func pattern(server bool) []byte {
	data := make([]byte, payloadBytes)
	for i := range data {
		if server {
			data[i] = byte((i*29 + 7) % 251)
		} else {
			data[i] = byte((i*17 + 3) % 251)
		}
	}
	return data
}
func application(conn net.Conn, client, server *protection, exporterMaster []byte, s suite, out result) (result, error) {
	exporter := s.expand(s.derive(exporterMaster, exporterLabel, nil), "exporter", s.digest(exporterContext), 32)
	serverData := pattern(true)
	done := make(chan error, 1)
	go func() {
		data := append(append([]byte("ABDC"), exporter...), serverData...)
		for len(data) > 0 {
			n := min(len(data), 16384)
			if err := server.write(conn, 23, data[:n]); err != nil {
				done <- err
				return
			}
			data = data[n:]
		}
		done <- nil
	}()
	clientData := make([]byte, 0, payloadBytes)
	for len(clientData) < payloadBytes {
		typ, payload, err := client.read(conn)
		if err != nil {
			return out, err
		}
		if typ != 23 || len(payload) == 0 || len(clientData)+len(payload) > payloadBytes {
			return out, errors.New("invalid application data record")
		}
		clientData = append(clientData, payload...)
	}
	if !bytes.Equal(clientData, pattern(false)) {
		return out, errors.New("client data mismatch")
	}
	if err := <-done; err != nil {
		return out, err
	}
	typ, payload, err := client.read(conn)
	if err != nil {
		return out, err
	}
	if typ != 21 || !bytes.Equal(payload, []byte{1, 0}) {
		return out, errors.New("missing client close_notify")
	}
	if err = server.write(conn, 21, []byte{1, 0}); err != nil {
		return out, err
	}
	clientHash, serverHash := sha256.Sum256(clientData), sha256.Sum256(serverData)
	out.Exporter = hex.EncodeToString(exporter)
	out.ClientSHA256 = hex.EncodeToString(clientHash[:])
	out.ServerSHA256 = hex.EncodeToString(serverHash[:])
	out.Bytes = payloadBytes
	out.CloseNotify = true
	return out, nil
}
