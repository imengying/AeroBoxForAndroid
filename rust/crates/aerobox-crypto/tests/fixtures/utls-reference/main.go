// Standalone fixed-uTLS capture tool. Never linked into the Rust product.
package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	utls "github.com/metacubex/utls"
)

type captureConn struct{ bytes.Buffer }

func (c *captureConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *captureConn) Close() error             { return nil }
func (c *captureConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
}
func (c *captureConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
}
func (c *captureConn) SetDeadline(time.Time) error      { return nil }
func (c *captureConn) SetReadDeadline(time.Time) error  { return nil }
func (c *captureConn) SetWriteDeadline(time.Time) error { return nil }

func u16(p []byte) uint16 { return binary.BigEndian.Uint16(p) }
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func parse(record []byte) map[string]any {
	r := map[string]any{"record_hex": hex.EncodeToString(record)}
	if len(record) < 5 {
		return r
	}
	r["record_type"] = record[0]
	r["record_version"] = fmt.Sprintf("%04x", u16(record[1:3]))
	n := int(u16(record[3:5]))
	r["record_length"] = n
	if len(record) < 5+n || n < 38 {
		return r
	}
	p := record[5 : 5+n]
	r["handshake_type"] = p[0]
	r["hello_version"] = fmt.Sprintf("%04x", u16(p[4:6]))
	i := 38
	sid := int(p[i])
	i++
	r["session_id_len"] = sid
	r["session_id"] = hex.EncodeToString(p[i : i+sid])
	i += sid
	norm := append([]byte(nil), record[:5+n]...)
	clear(norm[11:43])
	clear(norm[5+39 : 5+39+sid])
	r["normalized_hex"] = hex.EncodeToString(norm)
	ncipher := int(u16(p[i : i+2]))
	i += 2
	var ciphers []string
	for stop := i + ncipher; i < stop; i += 2 {
		ciphers = append(ciphers, fmt.Sprintf("%04x", u16(p[i:i+2])))
	}
	r["ciphers"] = ciphers
	ncomp := int(p[i])
	i++
	r["compression"] = hex.EncodeToString(p[i : i+ncomp])
	i += ncomp
	if i == len(p) {
		return r
	}
	nex := int(u16(p[i : i+2]))
	i += 2
	var exts []map[string]any
	for stop := i + nex; i < stop; {
		id := u16(p[i : i+2])
		length := int(u16(p[i+2 : i+4]))
		i += 4
		exts = append(exts, map[string]any{"id": id, "hex": hex.EncodeToString(p[i : i+length])})
		i += length
	}
	r["extensions"] = exts
	return r
}

type captureCase struct {
	name   string
	modify func(*utls.Config)
}

func echConfig() []byte {
	secret := bytes.Repeat([]byte{1}, 32)
	key, err := ecdh.X25519().NewPrivateKey(secret)
	if err != nil {
		panic(err)
	}
	length16 := func(p []byte) []byte { return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...) }
	content := []byte{1, 0, 0x20}
	content = append(content, length16(key.PublicKey().Bytes())...)
	content = append(content, length16([]byte{0, 1, 0, 1})...)
	name := "public.test"
	content = append(content, 32, byte(len(name)))
	content = append(content, name...)
	content = append(content, 0, 0)
	return length16(append([]byte{0xfe, 0x0d}, length16(content)...))
}
func capture(profile utls.ClientHelloID, tc captureCase) (r map[string]any) {
	r = map[string]any{"profile": profile.Str(), "case": tc.name}
	defer func() {
		if p := recover(); p != nil {
			r["panic"] = fmt.Sprint(p)
		}
	}()
	cfg := &utls.Config{ServerName: "android11.example"}
	tc.modify(cfg)
	requestedALPN := append([]string(nil), cfg.NextProtos...)
	r["min_before"] = cfg.MinVersion
	r["max_before"] = cfg.MaxVersion
	wire := new(captureConn)
	conn := utls.UClient(wire, cfg, profile)
	err := conn.BuildHandshakeState()
	// Match sing-box's wrapper: keep its original requested ALPN before the
	// profile's ApplyConfig can overwrite Config.NextProtos.
	if err == nil && len(requestedALPN) > 0 {
		for _, ext := range conn.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = requestedALPN
				err = conn.BuildHandshakeState()
				break
			}
		}
	}
	r["build_error"] = errString(err)
	r["min_after"] = cfg.MinVersion
	r["max_after"] = cfg.MaxVersion
	r["config_curves_after"] = cfg.CurvePreferences
	r["config_ciphers_after"] = cfg.CipherSuites
	r["config_alpn_after"] = cfg.NextProtos
	if err == nil {
		r["has_ecdhe_keyshare"] = conn.HandshakeState.State13.KeyShareKeys != nil && conn.HandshakeState.State13.KeyShareKeys.Ecdhe != nil
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		err = conn.HandshakeContext(ctx)
		cancel()
		r["handshake_error"] = errString(err)
		r["wire"] = parse(wire.Bytes())
	}
	return r
}
func main() {
	if len(os.Args) > 1 && os.Args[1] == "negotiate" {
		negotiate()
		return
	}
	cases := []captureCase{
		{"default", func(*utls.Config) {}},
		{"min12_max12", func(c *utls.Config) { c.MinVersion = utls.VersionTLS12; c.MaxVersion = utls.VersionTLS12 }},
		{"min13_max13", func(c *utls.Config) { c.MinVersion = utls.VersionTLS13; c.MaxVersion = utls.VersionTLS13 }},
		{"min11_max11", func(c *utls.Config) { c.MinVersion = utls.VersionTLS11; c.MaxVersion = utls.VersionTLS11 }},
		{"cipher_only_c02f", func(c *utls.Config) { c.CipherSuites = []uint16{utls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256} }},
		{"group_only_p521", func(c *utls.Config) { c.CurvePreferences = []utls.CurveID{utls.CurveP521} }},
		{"alpn_h2_h1", func(c *utls.Config) { c.NextProtos = []string{"h2", "http/1.1"} }},
		{"alpn_custom", func(c *utls.Config) { c.NextProtos = []string{"audit-custom"} }},
		{"no_sni_verify_name", func(c *utls.Config) { c.ServerName = ""; c.InsecureServerNameToVerify = "android11.example" }},
		{"ip_sni", func(c *utls.Config) { c.ServerName = "192.0.2.1" }},
		{"session_cache_enabled", func(c *utls.Config) { c.ClientSessionCache = utls.NewLRUClientSessionCache(8) }},
		{"ech_default", func(c *utls.Config) { c.EncryptedClientHelloConfigList = echConfig() }},
		{"ech_min13_max13", func(c *utls.Config) {
			c.MinVersion = utls.VersionTLS13
			c.MaxVersion = utls.VersionTLS13
			c.EncryptedClientHelloConfigList = echConfig()
		}},
		{"ech_min12_max12", func(c *utls.Config) {
			c.MinVersion = utls.VersionTLS12
			c.MaxVersion = utls.VersionTLS12
			c.EncryptedClientHelloConfigList = echConfig()
		}},
	}
	var results []map[string]any
	for _, profile := range []utls.ClientHelloID{utls.HelloAndroid_11_OkHttp, utls.HelloChrome_133} {
		for _, tc := range cases {
			results = append(results, capture(profile, tc))
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		panic(err)
	}
}
