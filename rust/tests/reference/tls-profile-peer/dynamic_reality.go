// Isolated fresh-handshake path for randomized REALITY. The old 1301 peer's
// tickets, compression, mTLS and record-size behavior remain untouched.
package main

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/hkdf"
)

const realityExporterLabel = "aerobox randomized reality exporter"

var realityExporterContext = []byte{0, 'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'd', 0, 'r', 'e', 'a', 'l', 'i', 't', 'y', 0}

func dynamicOptions(o peerOptions) error {
	if o.Tickets != nil || o.EarlyMode != "" || o.Compress || o.Mutual || o.BrowserExchange || o.RecordSize != nil || o.RealityDelegated || o.UnadvertisedSignature || o.SHA1Signature != "" || o.BothALPS || o.SkipALPSOfferCheck || o.UnsolicitedEarlyData || o.OversizedEE || o.UnadvertisedGroup || o.CertificateLength != 0 || o.CertificateInflateSize != 0 || o.SCT != "" || o.OCSP || o.UnsolicitedSCT || o.UnsolicitedOCSP {
		return errors.New("dynamic REALITY peer supports only fresh uncompressed authenticated TLS1.3")
	}
	if o.ALPS != 0 && o.ALPS != 17513 {
		return errors.New("randomized REALITY only has the legacy h2 ALPS object")
	}
	if o.Reality != "" && (!o.RealityBrowser || o.RealityProfile != "randomized") {
		return errors.New("dynamic REALITY requires explicit randomized browser profile")
	}
	if o.Reality == "" && (o.RealityBrowser || o.RealityProfile != "") {
		return errors.New("normal dynamic selftest must not pretend to be REALITY")
	}
	return nil
}

func serveDynamicReality(conn net.Conn, certDER, keyDER []byte, o peerOptions) (result peerResult, err error) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(45 * time.Second))
	if err = dynamicOptions(o); err != nil {
		return result, err
	}
	keyAny, err := x509.ParsePKCS8PrivateKey(keyDER)
	if err != nil {
		return result, err
	}
	private, ok := keyAny.(*rsa.PrivateKey)
	if !ok {
		return result, errors.New("dynamic peer fixture must be RSA")
	}
	var stream messages
	readPlain := func() (byte, []byte, error) {
		for {
			kind, _, body, err := readRecord(conn)
			if err == nil && kind == 20 && bytes.Equal(body, []byte{1}) {
				continue
			}
			return kind, body, err
		}
	}
	ch, err := stream.next(readPlain)
	if err != nil {
		return result, err
	}
	hello, err := parseHelloWithCipherRequirement(ch, false)
	if err != nil {
		return result, err
	}
	suite, err := selectDynamicSuite(hello.ciphers, o.RealitySuite)
	if err != nil {
		return result, err
	}
	result.Suite = suite.id
	var signing ed25519.PrivateKey
	if o.Reality != "" {
		certDER, signing, err = realityCredential(ch, hello, o.Reality, true, "randomized")
		if err != nil {
			return result, err
		}
		result.RealityAuthenticated = true
	}
	if err = checkPeerALPN(hello, o); err != nil {
		return result, err
	}
	if o.ALPS != 0 && !bytes.Equal(hello.extensions[17513], []byte{0, 3, 2, 'h', '2'}) {
		return result, errors.New("dynamic peer ALPS object not offered")
	}
	if o.ExpectedShares != nil {
		if len(o.ExpectedShares) != len(hello.shareOrder) {
			return result, errors.New("wrong dynamic initial share count")
		}
		for i, g := range o.ExpectedShares {
			if g != hello.shareOrder[i] {
				return result, errors.New("wrong dynamic initial share order")
			}
		}
	}
	group := o.Group
	if group == 0 {
		group = 29
	}
	if group != 29 && group != 23 && group != 24 && group != 25 {
		return result, errors.New("dynamic REALITY requires a classical group")
	}
	result.Group = group
	groups := reader{p: hello.extensions[10]}
	supported := groups.vector(2)
	if groups.done() != nil || !has16(supported, group) {
		return result, errors.New("dynamic selected group not offered")
	}
	var transcript []byte
	if _, offered := hello.shares[group]; !offered || o.CookieRetry || o.ForceRetry {
		hrr := helloRetrySuite(hello.session, group, o.CookieRetry, suite.id)
		transcript = append(handshakeMessage(254, suite.digest(ch)), hrr...)
		if err = writePlain(conn, 22, hrr); err != nil {
			return result, err
		}
		ch, err = stream.next(readPlain)
		if err != nil {
			return result, err
		}
		next, err := parseHelloWithCipherRequirement(ch, false)
		if err != nil {
			return result, err
		}
		if !bytes.Equal(hello.session, next.session) || !bytes.Equal(hello.random, next.random) || !bytes.Equal(hello.ciphers, next.ciphers) {
			return result, errors.New("dynamic retry changed immutable hello")
		}
		for id, value := range hello.extensions {
			if id != 51 && id != 21 && !bytes.Equal(value, next.extensions[id]) {
				return result, errors.New("dynamic retry changed original extension")
			}
		}
		for id := range next.extensions {
			if _, exists := hello.extensions[id]; !exists && id != 44 && id != 21 {
				return result, errors.New("dynamic retry added extension")
			}
		}
		if o.CookieRetry {
			if !bytes.Equal(next.extensions[44], vector16([]byte("aerobox-cookie"))) || !bytes.Equal(next.extensions[51], hello.extensions[51]) {
				return result, errors.New("dynamic cookie retry altered shares")
			}
		} else if len(next.shares) != 1 || len(next.shares[group]) == 0 {
			return result, errors.New("dynamic retry missing sole requested share")
		}
		hello = next
		result.HelloRetry = true
	}
	serverShare, shared, err := exchange(group, hello.shares[group])
	if err != nil {
		return result, err
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		return result, err
	}
	sh := serverHelloSuite(hello.session, random, append(binary.BigEndian.AppendUint16(nil, group), vector16(serverShare)...), suite.id)
	transcript = append(transcript, ch...)
	transcript = append(transcript, sh...)
	if err = writePlain(conn, 22, sh); err != nil {
		return result, err
	}
	early := hkdf.Extract(suite.hash, make([]byte, suite.size), nil)
	hs := hkdf.Extract(suite.hash, shared, suite.derive(early, "derived", nil))
	clientHS, serverHS := suite.derive(hs, "c hs traffic", transcript), suite.derive(hs, "s hs traffic", transcript)
	clientKeys, err := suite.protect(clientHS)
	if err != nil {
		return result, err
	}
	serverKeys, err := suite.protect(serverHS)
	if err != nil {
		return result, err
	}
	writeHandshake := func(message []byte) error {
		for rest := message; len(rest) > 0; {
			n := min(len(rest), 16384)
			if err := serverKeys.write(conn, 22, rest[:n]); err != nil {
				return err
			}
			rest = rest[n:]
		}
		transcript = append(transcript, message...)
		return nil
	}
	var ee []byte
	if !o.OmitALPN {
		name := o.SelectedALPN
		if name == "" {
			name = "h2"
		}
		ee = extension(16, vector16(append([]byte{byte(len(name))}, []byte(name)...)))
	}
	if o.ALPS != 0 {
		ee = append(ee, extension(o.ALPS, o.ServerSettings)...)
	}
	if err = writeHandshake(handshakeMessage(8, vector16(ee))); err != nil {
		return result, err
	}
	certificate := append([]byte{0}, vector24(append(vector24(certDER), 0, 0))...)
	if err = writeHandshake(handshakeMessage(11, certificate)); err != nil {
		return result, err
	}
	input := append(bytes.Repeat([]byte{32}, 64), []byte("TLS 1.3, server CertificateVerify\x00")...)
	input = append(input, suite.digest(transcript)...)
	var signature []byte
	scheme := uint16(0x0804)
	if signing != nil {
		scheme = 0x0807
		signature = ed25519.Sign(signing, input)
		if o.Reality == "bad-signature" {
			signature[0] ^= 1
		}
	} else {
		// CertificateVerify's RSA-PSS SHA256 scheme remains separate from the
		// negotiated transcript/HKDF hash, which can be SHA384 for suite 1302.
		hash := sha256.Sum256(input)
		signature, err = rsa.SignPSS(rand.Reader, private, crypto.SHA256, hash[:], &rsa.PSSOptions{SaltLength: 32, Hash: crypto.SHA256})
		if err != nil {
			return result, err
		}
	}
	if err = writeHandshake(handshakeMessage(15, append(binary.BigEndian.AppendUint16(nil, scheme), vector16(signature)...))); err != nil {
		return result, err
	}
	verify := suite.finished(serverHS, transcript)
	if o.BadFinished {
		verify[0] ^= 1
	}
	if err = writeHandshake(handshakeMessage(20, verify)); err != nil {
		return result, err
	}
	master := hkdf.Extract(suite.hash, make([]byte, suite.size), suite.derive(hs, "derived", nil))
	exporterMaster := suite.derive(master, "exp master", transcript)
	clientApp, err := suite.protect(suite.derive(master, "c ap traffic", transcript))
	if err != nil {
		return result, err
	}
	serverApp, err := suite.protect(suite.derive(master, "s ap traffic", transcript))
	if err != nil {
		return result, err
	}
	readHandshake := func() ([]byte, error) {
		return stream.next(func() (byte, []byte, error) { return clientKeys.read(conn) })
	}
	if o.ALPS != 0 {
		message, err := readHandshake()
		if err != nil {
			return result, err
		}
		if message[0] != 8 {
			return result, errors.New("dynamic client omitted ALPS")
		}
		ext, err := extensions(message[4:])
		if err != nil {
			return result, err
		}
		settings, present := ext[o.ALPS]
		if !present || len(ext) != 1 || !bytes.Equal(settings, o.ExpectedClientSettings) {
			return result, errors.New("wrong dynamic client ALPS")
		}
		result.ClientSettings = append([]byte{}, settings...)
		transcript = append(transcript, message...)
	}
	clientFinished, err := readHandshake()
	if err != nil {
		return result, err
	}
	if clientFinished[0] != 20 || !hmac.Equal(clientFinished[4:], suite.finished(clientHS, transcript)) || len(stream.bytes) != 0 {
		return result, errors.New("invalid dynamic client Finished")
	}
	result.ALPS = o.ALPS
	if o.RealityExchange {
		return dynamicRealityExchange(conn, suite, clientApp, serverApp, exporterMaster, result)
	}
	for {
		typ, payload, err := clientApp.read(conn)
		if err != nil {
			return result, err
		}
		if typ == 21 && bytes.Equal(payload, []byte{1, 0}) {
			if err = serverApp.write(conn, 21, []byte{1, 0}); err == nil {
				result.CloseNotify = true
			}
			return result, err
		}
		if typ != 23 {
			return result, fmt.Errorf("unexpected dynamic post-handshake type %d", typ)
		}
		result.Bytes += len(payload)
		if err = serverApp.write(conn, 23, payload); err != nil {
			return result, err
		}
	}
}

func dynamicRealityExchange(conn net.Conn, suite dynamicSuite, client, server *protection, exporterMaster []byte, result peerResult) (peerResult, error) {
	exporter := suite.expand(suite.derive(exporterMaster, realityExporterLabel, nil), "exporter", suite.digest(realityExporterContext), 32)
	serverData := browserPattern(true)
	written := make(chan error, 1)
	go func() {
		data := append(append([]byte("RR13"), exporter...), serverData...)
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
	// On every error, close before waiting so an independent writer cannot leak
	// or outlive this single-shot connection.
	finish := func(err error) (peerResult, error) {
		if err != nil {
			_ = conn.Close()
		}
		writeErr := <-written
		if err == nil {
			err = writeErr
		}
		return result, err
	}
	received := make([]byte, 0, browserPayloadBytes)
	for len(received) < browserPayloadBytes {
		typ, payload, err := client.read(conn)
		if err != nil {
			return finish(err)
		}
		if typ != 23 || len(payload) == 0 || len(received)+len(payload) > browserPayloadBytes {
			return finish(errors.New("invalid dynamic application frame"))
		}
		received = append(received, payload...)
	}
	if !bytes.Equal(received, browserPattern(false)) {
		return finish(errors.New("dynamic client payload mismatch"))
	}
	_, err := finish(nil)
	if err != nil {
		return result, err
	}
	typ, payload, err := client.read(conn)
	if err != nil {
		return result, err
	}
	if typ != 21 || !bytes.Equal(payload, []byte{1, 0}) {
		return result, errors.New("dynamic client close_notify missing")
	}
	if err = server.write(conn, 21, []byte{1, 0}); err != nil {
		return result, err
	}
	clientHash, serverHash := sha256.Sum256(received), sha256.Sum256(serverData)
	result.Bytes, result.CloseNotify = browserPayloadBytes, true
	result.Exporter = hex.EncodeToString(exporter)
	result.ClientSHA256, result.ServerSHA256 = hex.EncodeToString(clientHash[:]), hex.EncodeToString(serverHash[:])
	return result, nil
}
