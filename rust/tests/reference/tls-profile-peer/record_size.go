// Optional RFC8449 reference behavior. Every default option keeps the original
// peer's negotiation and record paths; no production TLS library uses this file.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
)

type recordSizeOptions struct {
	Limit     int
	Mode      string
	KeyUpdate bool
	Padding   int
}

type recordSizeStats struct {
	Offered                int    `json:"offered"`
	Selected               int    `json:"selected"`
	Mode                   string `json:"mode"`
	Negotiated             bool   `json:"negotiated"`
	HandshakeRecords       int    `json:"handshake_records"`
	ApplicationRecords     int    `json:"application_records"`
	CloseRecords           int    `json:"close_records"`
	MaxHandshakeInner      int    `json:"max_handshake_inner"`
	MaxApplicationInner    int    `json:"max_application_inner"`
	MaxAfterKeyUpdateInner int    `json:"max_after_key_update_inner"`
	MaxCloseInner          int    `json:"max_close_inner"`
	ClientKeyUpdates       int    `json:"client_key_updates"`
	ServerKeyUpdates       int    `json:"server_key_updates"`
	MaxServerInner         int    `json:"max_server_inner"`
	ServerPadding          int    `json:"server_padding"`
}

type recordSizeProtection struct {
	Limit  int
	Epoch  string
	Stats  *recordSizeStats
	Secret []byte
}

func (o recordSizeOptions) validateOptions(options peerOptions) error {
	if o.Limit < 0 || o.Limit > 65535 || o.Padding < 0 || o.Padding > 1024 {
		return errors.New("record-size option outside bounded reference range")
	}
	switch o.Mode {
	case "normal", "omit", "unsolicited", "duplicate", "serverhello", "hrr", "malformed", "oversize-content", "oversize-padding":
	default:
		return errors.New("unknown record-size mode")
	}
	if !options.BrowserExchange || options.ALPS != 0 || options.Compress || options.Tickets != nil || options.EarlyMode != "" || options.Reality != "" {
		return errors.New("record-size reference requires plain fresh browser exchange with ALPS/compression disabled")
	}
	return nil
}

func (o recordSizeOptions) validateHello(hello clientHello) error {
	value, present := hello.extensions[28]
	if o.Mode == "unsolicited" {
		if present {
			return errors.New("unsolicited fixture requires no client RSL offer")
		}
		return nil
	}
	if !present || !bytes.Equal(value, []byte{0x40, 1}) {
		return fmt.Errorf("expected exact client record_size_limit 16385, got %x", value)
	}
	return nil
}

func (o recordSizeOptions) encoding() []byte {
	return binary.BigEndian.AppendUint16(nil, uint16(o.Limit))
}

func (o recordSizeOptions) appendEE(extensions []byte) []byte {
	if o.Mode == "omit" || o.Mode == "serverhello" || o.Mode == "hrr" {
		return extensions
	}
	value := o.encoding()
	if o.Mode == "malformed" {
		value = value[:1]
	}
	extensions = append(extensions, extension(28, value)...)
	if o.Mode == "duplicate" {
		extensions = append(extensions, extension(28, value)...)
	}
	return extensions
}

func appendServerHelloExtension(message, extra []byte) []byte {
	pos := 4 + 2 + 32 + 1 + int(message[38]) + 2 + 1
	body := append([]byte(nil), message[4:pos]...)
	extensions := append(append([]byte(nil), message[pos+2:]...), extra...)
	return handshakeMessage(2, append(body, vector16(extensions)...))
}

func (o recordSizeOptions) attach(p *protection, secret []byte, stats *recordSizeStats, epoch string) {
	limit := 16385
	negotiated := o.Mode != "omit" && o.Mode != "serverhello" && o.Mode != "hrr" && o.Limit >= 64 && o.Limit <= 16385
	if negotiated {
		limit = o.Limit
	}
	stats.Negotiated = negotiated
	p.recordSize = &recordSizeProtection{Limit: limit, Epoch: epoch, Stats: stats, Secret: append([]byte(nil), secret...)}
}

// Called only after authenticating the complete AEAD plaintext and before
// stripping content type or zero padding, in both handshake and app readers.
func (p *protection) observeRecordSize(inner []byte) error {
	state := p.recordSize
	if state == nil || state.Stats == nil {
		return nil
	}
	if len(inner) > state.Limit {
		return fmt.Errorf("protected record plaintext %d exceeds negotiated limit %d", len(inner), state.Limit)
	}
	pos := len(inner) - 1
	for pos >= 0 && inner[pos] == 0 {
		pos--
	}
	if pos < 0 {
		return errors.New("missing inner type for record-size witness")
	}
	stats := state.Stats
	if state.Epoch == "handshake" {
		stats.HandshakeRecords++
		stats.MaxHandshakeInner = max(stats.MaxHandshakeInner, len(inner))
	} else {
		switch inner[pos] {
		case 23:
			stats.ApplicationRecords++
			stats.MaxApplicationInner = max(stats.MaxApplicationInner, len(inner))
			if stats.ClientKeyUpdates > 0 {
				stats.MaxAfterKeyUpdateInner = max(stats.MaxAfterKeyUpdateInner, len(inner))
			}
		case 21:
			stats.CloseRecords++
			stats.MaxCloseInner = max(stats.MaxCloseInner, len(inner))
		case 22: // KeyUpdate is parsed and authenticated by recordSizeExchange.
		default:
			return errors.New("unexpected inner type in record-size exchange")
		}
	}
	return nil
}

func (p *protection) updateRecordSizeKeys() error {
	state := p.recordSize
	if state == nil || len(state.Secret) != 32 {
		return errors.New("missing KeyUpdate traffic secret")
	}
	next := expand(state.Secret, "traffic upd", nil, 32)
	clear(state.Secret)
	state.Secret = next
	fresh := protect(next)
	fresh.recordSize = state
	*p = *fresh
	return nil
}

func (p *protection) writeRecordSize(w io.Writer, typ byte, payload []byte, padding int, malicious bool) error {
	inner := append(append([]byte(nil), payload...), typ)
	inner = append(inner, make([]byte, padding)...)
	if !malicious && len(inner) > 16385 {
		return errors.New("reference exceeded client receive limit")
	}
	if len(inner) > 16386 {
		return errors.New("reference malicious fixture exceeds fixed bound")
	}
	header := binary.BigEndian.AppendUint16([]byte{23, 3, 3}, uint16(len(inner)+p.aead.Overhead()))
	return writeAll(w, append(header, p.aead.Seal(nil, p.nonce(), inner, header)...))
}

func recordSizeExchange(conn net.Conn, client, server *protection, exporterMaster []byte, result peerResult, options recordSizeOptions) (peerResult, error) {
	stats := result.RecordSize
	if options.Mode == "oversize-content" || options.Mode == "oversize-padding" {
		var payload []byte
		padding := 0
		if options.Mode == "oversize-content" {
			payload = make([]byte, 16385)
		} else {
			payload = []byte("bounded")
			padding = 16386 - len(payload) - 1
		}
		if err := server.writeRecordSize(conn, 23, payload, padding, true); err != nil {
			return result, err
		}
		_, _, err := client.read(conn)
		if err == nil {
			err = errors.New("oversized server record must abort the client")
		}
		return result, err
	}
	exporter := expand(derive(exporterMaster, browserExporterLabel, nil), "exporter", digest(browserExporterContext), 32)
	serverData := browserPattern(true)
	type writeResult struct {
		err              error
		updates, maximum int
	}
	written := make(chan writeResult, 1)
	// This is the only writer until its completion is received. Client-requested
	// updates are acknowledged afterwards, avoiding concurrent nonce/key use.
	go func() {
		outcome := writeResult{}
		if options.KeyUpdate {
			if outcome.err = server.write(conn, 22, handshakeMessage(24, []byte{0})); outcome.err != nil {
				written <- outcome
				return
			}
			if outcome.err = server.updateRecordSizeKeys(); outcome.err != nil {
				written <- outcome
				return
			}
			outcome.updates++
		}
		data := append(append([]byte("AB13"), exporter...), serverData...)
		for len(data) > 0 {
			n := min(len(data), 16384-options.Padding)
			if outcome.err = server.writeRecordSize(conn, 23, data[:n], options.Padding, false); outcome.err != nil {
				written <- outcome
				return
			}
			outcome.maximum = max(outcome.maximum, n+1+options.Padding)
			data = data[n:]
		}
		written <- outcome
	}()
	pendingReply := false
	readApplication := func() (byte, []byte, error) {
		for {
			typ, body, err := client.read(conn)
			if err != nil {
				return 0, nil, err
			}
			if typ != 22 {
				return typ, body, nil
			}
			if len(body) != 5 || !bytes.Equal(body[:4], []byte{24, 0, 0, 1}) || body[4] > 1 || stats.ClientKeyUpdates >= 4 {
				return 0, nil, errors.New("invalid or excessive post-handshake KeyUpdate")
			}
			if body[4] == 1 {
				pendingReply = true
			}
			if err = client.updateRecordSizeKeys(); err != nil {
				return 0, nil, err
			}
			stats.ClientKeyUpdates++
		}
	}
	clientData := make([]byte, 0, browserPayloadBytes)
	for len(clientData) < browserPayloadBytes {
		typ, body, err := readApplication()
		if err != nil {
			return result, err
		}
		if typ != 23 || len(body) == 0 || len(clientData)+len(body) > browserPayloadBytes {
			return result, errors.New("unexpected RSL application frame")
		}
		clientData = append(clientData, body...)
	}
	if !bytes.Equal(clientData, browserPattern(false)) {
		return result, errors.New("RSL client data mismatch")
	}
	outcome := <-written
	if outcome.err != nil {
		return result, outcome.err
	}
	stats.ServerKeyUpdates = outcome.updates
	stats.MaxServerInner, stats.ServerPadding = outcome.maximum, options.Padding
	if options.KeyUpdate && stats.ClientKeyUpdates == 0 {
		return result, errors.New("required client KeyUpdate missing")
	}
	if pendingReply {
		if err := server.write(conn, 22, handshakeMessage(24, []byte{0})); err != nil {
			return result, err
		}
		if err := server.updateRecordSizeKeys(); err != nil {
			return result, err
		}
		stats.ServerKeyUpdates++
	}
	typ, body, err := readApplication()
	if err != nil {
		return result, err
	}
	if typ != 21 || !bytes.Equal(body, []byte{1, 0}) {
		return result, errors.New("missing RSL client close_notify")
	}
	if err = server.write(conn, 21, []byte{1, 0}); err != nil {
		return result, err
	}
	clientHash, serverHash := sha256.Sum256(clientData), sha256.Sum256(serverData)
	result.Exporter, result.Bytes = hex.EncodeToString(exporter), browserPayloadBytes
	result.ClientSHA256, result.ServerSHA256 = hex.EncodeToString(clientHash[:]), hex.EncodeToString(serverHash[:])
	result.CloseNotify = true
	return result, nil
}
