package main

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestRecordSizeRequiresExactOfferAndPreservesOmittedMode(t *testing.T) {
	options := recordSizeOptions{Limit: 64, Mode: "normal"}
	for _, value := range [][]byte{nil, {}, {0x40}, {0x40, 0}, {0, 64}, {0x40, 1, 0}} {
		hello := clientHello{extensions: map[uint16][]byte{28: value}}
		if err := options.validateHello(hello); err == nil {
			t.Fatalf("accepted wrong RSL offer %x", value)
		}
	}
	hello := clientHello{extensions: map[uint16][]byte{28: {0x40, 1}}}
	if err := options.validateHello(hello); err != nil {
		t.Fatal(err)
	}
	original := extension(16, []byte{0, 3, 2, 'h', '2'})
	options.Mode = "omit"
	if !bytes.Equal(options.appendEE(append([]byte(nil), original...)), original) {
		t.Fatal("omit mode changed EE")
	}
	stats := &recordSizeStats{}
	p := protect(bytes.Repeat([]byte{9}, 32))
	options.attach(p, nil, stats, "handshake")
	if stats.Negotiated || p.recordSize.Limit != 16385 {
		t.Fatal("omitted extension restricted client records")
	}
	options.Mode = "unsolicited"
	if err := options.validateHello(hello); err == nil {
		t.Fatal("unsolicited mode accepted client offer")
	}
	if err := options.validateHello(clientHello{extensions: map[uint16][]byte{}}); err != nil {
		t.Fatal(err)
	}
}

func TestRecordSizeMalformedAndWrongLocationFixturesAreActuallyEncoded(t *testing.T) {
	options := recordSizeOptions{Limit: 64, Mode: "normal"}
	ee, err := extensions(vector16(options.appendEE(nil)))
	if err != nil || !bytes.Equal(ee[28], []byte{0, 64}) {
		t.Fatal("normal RSL not encoded")
	}
	options.Mode = "duplicate"
	if _, err = extensions(vector16(options.appendEE(nil))); err == nil {
		t.Fatal("duplicate fixture is not duplicate")
	}
	options.Mode = "malformed"
	ee, err = extensions(vector16(options.appendEE(nil)))
	if err != nil || len(ee[28]) != 1 {
		t.Fatal("malformed length fixture changed")
	}
	for _, mode := range []string{"serverhello", "hrr"} {
		options.Mode = mode
		if len(options.appendEE(nil)) != 0 {
			t.Fatal("wrong-location fixture still included in EE")
		}
		hello := serverHello(make([]byte, 32), make([]byte, 32), []byte{0, 29, 0, 1, 7})
		hello = appendServerHelloExtension(hello, extension(28, options.encoding()))
		pos := 4 + 2 + 32 + 1 + 32 + 2 + 1
		exts, err := extensions(hello[pos:])
		if err != nil || !bytes.Equal(exts[28], []byte{0, 64}) {
			t.Fatal("server hello extension malformed")
		}
		declared := int(hello[1])<<16 | int(hello[2])<<8 | int(hello[3])
		if declared != len(hello)-4 {
			t.Fatal("server hello handshake length stale")
		}
	}
}

func TestRecordSizeChecksAuthenticatedInnerTypeAndPaddingInBothReaders(t *testing.T) {
	secret := bytes.Repeat([]byte{0x17}, 32)
	for _, decryptOnly := range []bool{false, true} {
		for _, typ := range []byte{21, 22, 23} {
			for _, padding := range []int{0, 7, 62, 63} {
				sender, receiver := protect(secret), protect(secret)
				stats := &recordSizeStats{}
				epoch := "application"
				if typ == 22 {
					epoch = "handshake"
				}
				receiver.recordSize = &recordSizeProtection{Limit: 64, Stats: stats, Epoch: epoch}
				var wire bytes.Buffer
				if err := sender.writeRecordSize(&wire, typ, []byte{1}, padding, false); err != nil {
					t.Fatal(err)
				}
				var gotType byte
				var payload []byte
				var err error
				if decryptOnly {
					encoded := wire.Bytes()
					gotType, payload, err = receiver.decrypt(encoded[:5], encoded[5:])
				} else {
					gotType, payload, err = receiver.read(&wire)
				}
				if padding == 63 {
					if err == nil {
						t.Fatalf("reader %t ignored type/padding in size", decryptOnly)
					}
					continue
				}
				if err != nil || gotType != typ || !bytes.Equal(payload, []byte{1}) {
					t.Fatalf("valid boundary failed: %v", err)
				}
				maximum := max(stats.MaxHandshakeInner, stats.MaxApplicationInner, stats.MaxCloseInner)
				if maximum != 2+padding {
					t.Fatalf("witness measured %d, expected %d", maximum, 2+padding)
				}
			}
		}
	}
}

func TestRecordSizeLimitPersistsAfterRealTrafficSecretUpdate(t *testing.T) {
	secret := bytes.Repeat([]byte{0x23}, 32)
	sender, receiver := protect(secret), protect(secret)
	sender.recordSize = &recordSizeProtection{Secret: append([]byte(nil), secret...)}
	stats := &recordSizeStats{ClientKeyUpdates: 1}
	receiver.recordSize = &recordSizeProtection{Secret: append([]byte(nil), secret...), Limit: 64, Stats: stats, Epoch: "application"}
	if err := sender.updateRecordSizeKeys(); err != nil {
		t.Fatal(err)
	}
	if err := receiver.updateRecordSizeKeys(); err != nil {
		t.Fatal(err)
	}
	if sender.sequence != 0 || receiver.sequence != 0 || receiver.recordSize.Limit != 64 {
		t.Fatal("KeyUpdate lost state")
	}
	var wire bytes.Buffer
	if err := sender.write(&wire, 23, bytes.Repeat([]byte{7}, 63)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.read(&wire); err != nil {
		t.Fatal(err)
	}
	if stats.MaxAfterKeyUpdateInner != 64 {
		t.Fatal("new epoch not measured")
	}
	if err := sender.write(&wire, 23, bytes.Repeat([]byte{7}, 64)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := receiver.read(&wire); err == nil {
		t.Fatal("new epoch lost receive limit")
	}
}

func TestRecordSizeOversizeFixturesRemainBoundedAndDefaultReadIsUnchanged(t *testing.T) {
	secret := bytes.Repeat([]byte{0x31}, 32)
	for _, padding := range []int{0, 16384} {
		sender := protect(secret)
		var wire bytes.Buffer
		payload := []byte{1}
		if padding == 0 {
			payload = make([]byte, 16385)
		}
		if err := sender.writeRecordSize(&wire, 23, payload, padding, true); err != nil {
			t.Fatal(err)
		}
		if int(binary.BigEndian.Uint16(wire.Bytes()[3:5])) != 16386+16 {
			t.Fatal("malicious boundary wrong")
		}
		receiver := protect(secret)
		receiver.recordSize = &recordSizeProtection{Limit: 16385, Stats: &recordSizeStats{}, Epoch: "application"}
		if _, _, err := receiver.read(&wire); err == nil {
			t.Fatal("accepted full inner overflow")
		}
	}
	sender, receiver := protect(secret), protect(secret)
	var wire bytes.Buffer
	if err := sender.write(&wire, 23, []byte("original defaults")); err != nil {
		t.Fatal(err)
	}
	typ, payload, err := receiver.read(&wire)
	if err != nil || typ != 23 || string(payload) != "original defaults" {
		t.Fatal("default peer changed")
	}
}
