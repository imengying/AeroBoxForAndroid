package main

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestHRRCaptures(t *testing.T) {
	for _, name := range []string{"edge", "qq", "safari", "ios", "firefox"} {
		profile, _ := profileID(name)
		for _, mode := range []string{"cookie-only", "cookie-group"} {
			for _, test := range cases() {
				t.Run(name+"/"+mode+"/"+test.name, func(t *testing.T) {
					r := capture(name, mode, profile, test, 0)
					if r.BuildError != "" || r.Panic != "" || r.ValidationError != "" || r.HandshakeComplete || !r.ExpectedEOF {
						t.Fatalf("bad two-flight capture: %+v", r)
					}
					if len(r.ClientHellosHex) != 2 || len(r.ClientRecordsHex) != 2 {
						t.Fatal("missing flights")
					}
					if len(r.ObjectsAfter) != len(r.ObjectsBefore)+1 {
						t.Fatal("missing inserted Cookie object")
					}
				})
			}
		}
	}
}

func TestFlightFramingAndTruncation(t *testing.T) {
	first := handshake(1, []byte{1, 2, 3})
	second := handshake(1, []byte{4, 5, 6})
	wire := append(record(22, first[:2]), record(22, first[2:])...)
	wire = append(wire, record(20, []byte{1})...)
	wire = append(wire, record(22, second)...)
	hellos, frames, err := clientFlights(wire)
	if err != nil || len(hellos) != 2 || len(frames) != 2 || !bytes.Equal(hellos[0], first) || !bytes.Equal(hellos[1], second) {
		t.Fatal(hellos, frames, err)
	}
	for _, bad := range [][]byte{
		wire[:len(wire)-1], record(22, first[:3]), record(20, []byte{2}),
		record(22, handshake(2, nil)), append(record(22, first[:2]), record(20, []byte{1})...),
	} {
		if _, _, err := clientFlights(bad); err == nil {
			t.Fatal("accepted malformed flight", hex.EncodeToString(bad))
		}
	}
}
