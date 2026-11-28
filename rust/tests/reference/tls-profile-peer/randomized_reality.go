// A strict structural validator for the fixed Android randomized generator,
// after the sing-box REALITY adapter removes hybrid groups and shares.
package main

import (
	"bytes"
	"crypto/ecdh"
	"encoding/binary"
	"errors"
)

func randomizedIDs(data []byte, allowed []uint16, maximum int) ([]uint16, error) {
	if len(data) == 0 || len(data)%2 != 0 || len(data) > maximum*2 {
		return nil, errors.New("invalid randomized vector length")
	}
	var out []uint16
	for len(data) > 0 {
		id := binary.BigEndian.Uint16(data)
		data = data[2:]
		found := false
		for _, value := range allowed {
			found = found || value == id
		}
		if !found {
			return nil, errors.New("unknown randomized capability")
		}
		for _, value := range out {
			if value == id {
				return nil, errors.New("duplicate randomized capability")
			}
		}
		out = append(out, id)
	}
	return out, nil
}
func randomizedVector(data []byte, allowed []uint16, maximum int) ([]uint16, error) {
	r := reader{p: data}
	values := r.vector(2)
	if err := r.done(); err != nil {
		return nil, err
	}
	return randomizedIDs(values, allowed, maximum)
}
func randomizedContains(values []uint16, id uint16) bool {
	for _, value := range values {
		if value == id {
			return true
		}
	}
	return false
}
func randomizedProtocols(data []byte) error {
	r := reader{p: data}
	names := reader{p: r.vector(2)}
	if err := r.done(); err != nil {
		return err
	}
	count := 0
	for len(names.p) > 0 && names.err == nil {
		if len(names.vector(1)) == 0 {
			return errors.New("empty randomized ALPN name")
		}
		count++
	}
	if count == 0 {
		return errors.New("empty randomized ALPN list")
	}
	return names.done()
}
func checkRandomizedRealityLayout(hello clientHello) error {
	cipherPool := []uint16{0x1301, 0x1302, 0x1303, 0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc013, 0xc023, 0xc009, 0xc014, 0xc00a, 0x009c, 0x009d, 0x003c, 0x002f, 0x0035, 0xc012, 0x000a}
	suites, err := randomizedIDs(hello.ciphers, cipherPool, 22)
	if err != nil {
		return err
	}
	modern, legacy, slow := false, false, false
	fast := []uint16{0xcca8, 0xcca9, 0xc02f, 0xc02b, 0xc030, 0xc02c, 0xc027, 0xc023, 0x009c, 0x009d, 0x003c}
	for _, suite := range suites {
		if suite >= 0x1301 && suite <= 0x1303 {
			if legacy {
				return errors.New("randomized modern suites must precede legacy suites")
			}
			modern = true
		} else {
			legacy = true
			if randomizedContains(fast, suite) {
				if slow {
					return errors.New("randomized slow cipher precedes a fast cipher")
				}
			} else {
				slow = true
			}
		}
	}
	if !modern || !legacy {
		return errors.New("randomized REALITY needs modern and legacy cipher offers")
	}
	signatures, err := randomizedVector(hello.extensions[13], []uint16{0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601, 0x0203, 0x0603, 0x0804, 0x0805, 0x0806}, 11)
	if err != nil {
		return err
	}
	for _, id := range []uint16{0x0403, 0x0401, 0x0503, 0x0501, 0x0201, 0x0601, 0x0804} {
		if !randomizedContains(signatures, id) {
			return errors.New("randomized mandatory signature missing")
		}
	}
	if randomizedContains(signatures, 0x0805) != randomizedContains(signatures, 0x0806) {
		return errors.New("randomized PSS384/PSS512 are a pair")
	}
	groups, err := randomizedVector(hello.extensions[10], []uint16{29, 23, 24, 25}, 4)
	if err != nil {
		return err
	}
	if len(groups) < 3 || groups[0] != 29 || groups[1] != 23 || groups[2] != 24 || (len(groups) == 4 && groups[3] != 25) {
		return errors.New("wrong randomized REALITY group order")
	}
	if len(hello.shares) != len(hello.shareOrder) || len(hello.shareOrder) < 1 || len(hello.shareOrder) > 2 || hello.shareOrder[0] != 29 || (len(hello.shareOrder) == 2 && hello.shareOrder[1] != 23) || len(hello.shares[29]) != 32 {
		return errors.New("wrong randomized REALITY share order or length")
	}
	if len(hello.shareOrder) == 2 {
		if _, err := ecdh.P256().NewPublicKey(hello.shares[23]); err != nil {
			return errors.New("invalid independent randomized P256 share")
		}
	}
	allowed := []uint16{0, 35, 13, 11, 10, 16, 21, 5, 18, 65281, 23, 51, 45, 43, 17513}
	for id, value := range hello.extensions {
		if !randomizedContains(allowed, id) {
			return errors.New("randomized REALITY has an unknown, GREASE or ECH extension")
		}
		switch id {
		case 35, 18, 23:
			if len(value) != 0 {
				return errors.New("nonempty randomized empty extension")
			}
		case 11:
			if !bytes.Equal(value, []byte{1, 0}) {
				return errors.New("wrong randomized point format")
			}
		case 5:
			if !bytes.Equal(value, []byte{1, 0, 0, 0, 0}) {
				return errors.New("wrong randomized status_request")
			}
		case 65281:
			if !bytes.Equal(value, []byte{0}) {
				return errors.New("wrong randomized renegotiation indication")
			}
		case 45:
			if !bytes.Equal(value, []byte{1, 1}) {
				return errors.New("wrong randomized PSK modes")
			}
		case 43:
			if !bytes.Equal(value, []byte{4, 3, 4, 3, 3}) && !bytes.Equal(value, []byte{8, 3, 4, 3, 3, 3, 2, 3, 1}) {
				return errors.New("wrong randomized supported versions")
			}
		case 16:
			if err := randomizedProtocols(value); err != nil {
				return err
			}
		case 17513:
			if _, ok := hello.extensions[16]; !ok || !bytes.Equal(value, []byte{0, 3, 2, 'h', '2'}) {
				return errors.New("wrong randomized h2 ALPS object")
			}
		case 21:
			if !bytes.Equal(value, make([]byte, len(value))) {
				return errors.New("nonzero randomized padding")
			}
		case 0:
			outer := reader{p: value}
			names := reader{p: outer.vector(2)}
			kind, name := names.uint(1), names.vector(2)
			if outer.done() != nil || names.done() != nil || kind != 0 || len(name) == 0 || len(name) > 253 {
				return errors.New("invalid randomized SNI")
			}
		}
	}
	for _, id := range []uint16{0, 35, 13, 11, 10, 51, 45, 43} {
		if _, ok := hello.extensions[id]; !ok {
			return errors.New("randomized mandatory extension missing")
		}
	}
	return nil
}
