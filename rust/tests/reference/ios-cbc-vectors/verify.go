// Independent Go-standard-library verifier. Test tool, not a product dependency.
// Parent runs under the shared lock; the child does not compile this source.
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"os"
)

type vector struct {
	Name     string  `json:"name"`
	Sequence uint64  `json:"sequence"`
	Plain    string  `json:"plaintext_hex"`
	Padding  int     `json:"padding"`
	Valid    bool    `json:"valid"`
	Fault    *string `json:"fault"`
	Derived  bool    `json:"derived_iv"`
	Tag      string  `json:"tag_hex"`
	Wire     string  `json:"wire_hex"`
}
type group struct {
	Key     string   `json:"key_hex"`
	MAC     string   `json:"mac_key_hex"`
	Digest  string   `json:"digest"`
	Vectors []vector `json:"vectors"`
}
type prfVector struct {
	Digest         string `json:"digest"`
	Secret         string `json:"secret_hex"`
	Label          string `json:"label_hex"`
	Seed           string `json:"seed_hex"`
	Output         string `json:"output_hex"`
	Transcript     string `json:"transcript_hex"`
	TranscriptHash string `json:"transcript_hash_hex"`
}

func decode(s string) []byte {
	p, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return p
}
func digest(name string) func() hash.Hash {
	switch name {
	case "sha256":
		return sha256.New
	case "sha384":
		return sha512.New384
	default:
		panic("unknown digest")
	}
}
func mac(h func() hash.Hash, key []byte, chunks ...[]byte) []byte {
	m := hmac.New(h, key)
	for _, p := range chunks {
		m.Write(p)
	}
	return m.Sum(nil)
}
func require(ok bool, context string) {
	if !ok {
		panic(context)
	}
}
func check(g group, v vector) {
	key, mk, plain, wire := decode(g.Key), decode(g.MAC), decode(v.Plain), decode(v.Wire)
	aad := binary.BigEndian.AppendUint64(nil, v.Sequence)
	aad = append(aad, 23, 3, 3)
	aad = binary.BigEndian.AppendUint16(aad, uint16(len(plain)))
	tag := mac(digest(g.Digest), mk, aad, plain)
	require(bytes.Equal(tag, decode(v.Tag)), v.Name+" HMAC mismatch")
	iv := bytes.Repeat([]byte{0x33}, aes.BlockSize)
	if v.Derived {
		params := binary.BigEndian.AppendUint16(nil, uint16(len(key)))
		params = binary.BigEndian.AppendUint16(params, uint16(len(mk)))
		derived := mac(sha256.New, mk, []byte("aerobox/tls12-cbc-sha2-explicit-iv-key/v1\x00"), params, key)
		permutation, err := aes.NewCipher(derived)
		if err != nil {
			panic(err)
		}
		iv = make([]byte, aes.BlockSize)
		binary.BigEndian.PutUint64(iv[8:], v.Sequence)
		permutation.Encrypt(iv, iv)
	}
	require(len(wire) >= 16 && bytes.Equal(wire[:16], iv), v.Name+" IV mismatch")
	clear := append(append(append([]byte(nil), plain...), tag...), bytes.Repeat([]byte{byte(v.Padding - 1)}, v.Padding)...)
	if v.Fault != nil {
		switch *v.Fault {
		case "bad-mac":
			clear[len(plain)] ^= 0x80
		case "bad-padding":
			clear[len(clear)-1] ^= 1
		case "oversized-plaintext":
			require(len(plain) == 16385, v.Name+" oversized fixture")
		default:
			panic("unknown fault")
		}
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	encrypted := make([]byte, len(clear))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, clear)
	require(bytes.Equal(encrypted, wire[16:]), v.Name+" ciphertext mismatch")
	decrypted := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(decrypted, encrypted)
	require(bytes.Equal(decrypted, clear), v.Name+" plaintext mismatch")
	pad := int(decrypted[len(decrypted)-1]) + 1
	accepted := pad <= len(decrypted)-len(tag)
	if accepted {
		n := len(decrypted) - len(tag) - pad
		accepted = n <= 16384 && bytes.Equal(decrypted[len(decrypted)-pad:], bytes.Repeat([]byte{byte(pad - 1)}, pad))
		if accepted {
			header := binary.BigEndian.AppendUint64(nil, v.Sequence)
			header = append(header, 23, 3, 3)
			header = binary.BigEndian.AppendUint16(header, uint16(n))
			accepted = hmac.Equal(mac(digest(g.Digest), mk, header, decrypted[:n]), decrypted[n:n+len(tag)])
		}
	}
	require(accepted == v.Valid, v.Name+" validity mismatch")
}
func main() {
	require(len(os.Args) == 2, "usage: verify vectors.json")
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var document struct {
		Format int         `json:"format"`
		Groups []group     `json:"groups"`
		PRFs   []prfVector `json:"prfs"`
	}
	if err = json.Unmarshal(data, &document); err != nil {
		panic(err)
	}
	require(document.Format == 1 && len(document.Groups) == 3 && len(document.PRFs) == 2, "unexpected vector schema")
	count := 0
	for _, g := range document.Groups {
		for _, v := range g.Vectors {
			check(g, v)
			count++
		}
	}
	for _, v := range document.PRFs {
		h := digest(v.Digest)
		secret, label, seed, expected := decode(v.Secret), decode(v.Label), decode(v.Seed), decode(v.Output)
		a := append(append([]byte(nil), label...), seed...)
		var output []byte
		for len(output) < len(expected) {
			a = mac(h, secret, a)
			output = append(output, mac(h, secret, a, label, seed)...)
		}
		require(bytes.Equal(output[:len(expected)], expected), v.Digest+" PRF mismatch")
		transcript := h()
		transcript.Write(decode(v.Transcript))
		require(bytes.Equal(transcript.Sum(nil), decode(v.TranscriptHash)), v.Digest+" transcript mismatch")
	}
	fmt.Printf("verified %d independent AES/HMAC records and %d PRF/transcript vectors\n", count, len(document.PRFs))
}
