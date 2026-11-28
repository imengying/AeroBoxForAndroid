package main

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"
)

func TestDNSNames(t *testing.T) {
	for length := 1; length <= 253; length++ {
		name := dnsName(length)
		if len(name) != length {
			t.Fatal(length, name)
		}
		for _, label := range strings.Split(name, ".") {
			if len(label) == 0 || len(label) > 63 {
				t.Fatal(length, name)
			}
		}
	}
}

func TestActualFirstFlights(t *testing.T) {
	for _, name := range []string{"chrome", "android", "edge", "qq", "firefox", "safari", "ios", "360"} {
		profile, _ := profileID(name)
		for _, test := range cases() {
			t.Run(name+"/"+test.name, func(t *testing.T) {
				result := capture(name, profile, test)
				if result.BuildError != "" || result.Panic != "" || result.HandshakeComplete || result.HandshakeError == "" {
					t.Fatalf("expected a constructed hello followed by failed EOF handshake: %+v", result)
				}
				wire, err := hex.DecodeString(result.WireHex)
				if err != nil || len(wire) < 9 || wire[0] != 22 || wire[5] != 1 {
					t.Fatal("missing ClientHello record", result)
				}
				length := int(binary.BigEndian.Uint16(wire[3:5]))
				if len(wire) < 5+length {
					t.Fatal("truncated record")
				}
				built, err := hex.DecodeString(result.BuiltClientHelloHex)
				if err != nil || len(built) != length {
					t.Fatal("wire differs from built ClientHello length")
				}
				if result.UnpaddedHelloLength+result.PaddingExtensionLength != length {
					t.Fatal("inconsistent padding metadata")
				}
			})
		}
	}
}
