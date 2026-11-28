// Independent PSK binder and ticket checks for the test server. Tickets are
// held in a one-entry in-memory store and never persisted outside a test run.
package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/hkdf"
)

type ticketState struct {
	identity, secret, clientSettings, serverSettings []byte
	alps                                             uint16
	created                                          time.Time
}
type ticketStore struct {
	mu   sync.Mutex
	last *ticketState
}

func (s *ticketStore) selectPSK(hello []byte, extensions map[uint16][]byte, prefix []byte) (*ticketState, error) {
	if s == nil || extensions[41] == nil {
		return nil, nil
	}
	r := reader{p: extensions[41]}
	identities := reader{p: r.vector(2)}
	identity := identities.vector(2)
	identities.uint(4) // ticket_age_add is zero in this test server.
	bindersBytes := r.vector(2)
	binders := reader{p: bindersBytes}
	binder := binders.vector(1)
	if r.done() != nil || identities.done() != nil || binders.done() != nil || len(binder) != 32 {
		return nil, errors.New("malformed reference PSK offer")
	}
	// RFC 8446 requires pre_shared_key to be the final ClientHello extension.
	if !bytes.HasSuffix(hello, extension(41, extensions[41])) {
		return nil, errors.New("PSK is not last")
	}
	s.mu.Lock()
	previous := s.last
	s.mu.Unlock()
	if previous == nil || !bytes.Equal(identity, previous.identity) || time.Since(previous.created) > time.Minute {
		return nil, nil
	}
	early := hkdf.Extract(sha256.New, previous.secret, nil)
	partial := append(append([]byte(nil), prefix...), hello[:len(hello)-2-len(bindersBytes)]...)
	expected := finished(derive(early, "res binder", nil), partial)
	if !hmac.Equal(binder, expected) {
		return nil, errors.New("invalid PSK binder")
	}
	return previous, nil
}

func (s *ticketStore) issue(master, transcript []byte, options peerOptions, early bool) []byte {
	identity, nonce := make([]byte, 32), make([]byte, 8)
	if _, err := rand.Read(identity); err != nil {
		panic(err)
	}
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	secret := expand(derive(master, "res master", transcript), "resumption", nonce, 32)
	state := &ticketState{identity: identity, secret: secret, alps: options.ALPS,
		clientSettings: append([]byte(nil), options.ExpectedClientSettings...),
		serverSettings: append([]byte(nil), options.ServerSettings...), created: time.Now()}
	s.mu.Lock()
	s.last = state
	s.mu.Unlock()
	body := binary.BigEndian.AppendUint32(nil, 60)
	body = binary.BigEndian.AppendUint32(body, 0)
	body = append(body, byte(len(nonce)))
	body = append(body, nonce...)
	body = append(body, vector16(identity)...)
	var extensions []byte
	if early {
		extensions = extension(42, []byte{0, 0, 16, 0})
	}
	return handshakeMessage(4, append(body, vector16(extensions)...))
}

func (p *protection) decrypt(header, body []byte) (byte, []byte, error) {
	inner, err := p.aead.Open(nil, p.nonce(), body, header)
	if err != nil {
		return 0, nil, err
	}
	if err = p.observeRecordSize(inner); err != nil {
		return 0, nil, err
	}
	for len(inner) > 0 && inner[len(inner)-1] == 0 {
		inner = inner[:len(inner)-1]
	}
	if len(inner) == 0 {
		return 0, nil, errors.New("empty protected record")
	}
	return inner[len(inner)-1], inner[:len(inner)-1], nil
}
