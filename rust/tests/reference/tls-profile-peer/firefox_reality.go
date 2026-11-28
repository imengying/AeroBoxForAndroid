// Test-only fixed Firefox120 cover with the sing-box REALITY metadata policy.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func checkFirefoxRealityLayout(hello clientHello) error {
	encode := func(values ...uint16) []byte {
		var result []byte
		for _, value := range values {
			result = binary.BigEndian.AppendUint16(result, value)
		}
		return result
	}
	if !bytes.Equal(hello.ciphers, encode(0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f,
		0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035)) ||
		!bytes.Equal(hello.extensions[10], vector16(encode(29, 23, 24, 25, 256, 257))) ||
		!bytes.Equal(hello.extensions[13], vector16(encode(0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201))) ||
		!bytes.Equal(hello.extensions[34], vector16(encode(0x0403, 0x0503, 0x0603, 0x0203))) ||
		!bytes.Equal(hello.extensions[28], encode(16385)) ||
		!bytes.Equal(hello.extensions[43], []byte{4, 3, 4, 3, 3}) {
		return errors.New("incorrect Firefox REALITY algorithms or record/DC advertisement")
	}
	if len(hello.shares) != 2 || len(hello.shareOrder) != 2 ||
		hello.shareOrder[0] != 29 || hello.shareOrder[1] != 23 ||
		len(hello.shares[29]) != 32 || len(hello.shares[23]) != 65 || hello.shares[23][0] != 4 {
		return errors.New("Firefox REALITY needs independent X25519 and P256 shares without GREASE")
	}
	for _, forbidden := range []uint16{18, 21, 27, 17513, 17613} {
		if _, exists := hello.extensions[forbidden]; exists {
			return errors.New("Firefox REALITY has a non-template extension")
		}
	}
	ech := reader{p: hello.extensions[65037]}
	outer, kdf, aead := ech.uint(1), ech.uint(2), ech.uint(2)
	_ = ech.uint(1) // Random config ID.
	enc, payload := ech.vector(2), ech.vector(2)
	if outer != 0 || kdf != 1 || (aead != 1 && aead != 3) || len(enc) != 32 || len(payload) != 239 || ech.done() != nil {
		return errors.New("invalid Firefox REALITY GREASE ECH")
	}
	return nil
}
