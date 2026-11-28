package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

func TestFFDHEMatchesIndependentPythonVectors(t *testing.T) {
	fixtures := os.Getenv("AEROBOX_TLS_FIXTURES")
	if fixtures == "" {
		fixtures = "../../../crates/aerobox-crypto/tests/fixtures"
	}
	encoded, err := os.ReadFile(filepath.Join(fixtures, "..", "..", "src", "ffdhe", "vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Group  int    `json:"group"`
		Case   string `json:"case"`
		Secret string `json:"secret"`
		Public string `json:"public"`
		Peer   string `json:"peer"`
		Shared string `json:"shared"`
	}
	if err := json.Unmarshal(encoded, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) != 8 {
		t.Fatalf("unexpected vector count %d", len(vectors))
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	leadingZeros := 0
	for _, vector := range vectors {
		group := uint16(256)
		if vector.Group == 3072 {
			group = 257
		} else if vector.Group != 2048 {
			t.Fatal("wrong group")
		}
		public, shared, err := ffdheWithSecret(group, decode(vector.Peer), decode(vector.Secret))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(public, decode(vector.Public)) || !bytes.Equal(shared, decode(vector.Shared)) {
			t.Fatalf("group %d case %s disagrees with Python arithmetic", vector.Group, vector.Case)
		}
		if len(shared) != vector.Group/8 {
			t.Fatal("unpadded shared secret")
		}
		if vector.Case == "leading-zero" {
			if shared[0] != 0 {
				t.Fatal("lost leading zero")
			}
			leadingZeros++
		}
	}
	if leadingZeros != 2 {
		t.Fatal("missing leading-zero vectors")
	}
}

func TestFFDHERejectsInvalidPeerAndGroup(t *testing.T) {
	for _, group := range []uint16{256, 257} {
		prime, width, size, err := ffdheParameters(group)
		if err != nil {
			t.Fatal(err)
		}
		secret := bytes.Repeat([]byte{0xa5}, size)
		p := prime.FillBytes(make([]byte, width))
		pMinusOne := new(big.Int).Sub(prime, big.NewInt(1)).FillBytes(make([]byte, width))
		one := make([]byte, width)
		one[width-1] = 1
		invalid := [][]byte{nil, {2}, make([]byte, width), one, pMinusOne, p,
			bytes.Repeat([]byte{255}, width), p[:width-1], append([]byte{0}, p...)}
		for _, value := range invalid {
			if _, _, err := ffdheWithSecret(group, value, secret); err == nil {
				t.Fatalf("group %d accepted invalid peer length %d", group, len(value))
			}
		}
	}
	for _, group := range []uint16{0, 29, 258, 65535} {
		if _, _, err := ffdheExchange(group, []byte{2}); err == nil {
			t.Fatal("accepted unknown group")
		}
	}
}
