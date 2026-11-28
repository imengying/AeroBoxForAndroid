// Capture two real uTLS flights around a synthetic, unauthenticated HRR.
// An EOF after ClientHello2 is construction evidence, never handshake success.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

const sourceVersion = "github.com/metacubex/utls v1.8.7"
const defaultName = "browser-profile.example"
const captureLimit = 1 << 20

var profilesFlag = flag.String("profiles", "edge,qq", "edge,qq,safari,ios,firefox; optionally chrome")
var modesFlag = flag.String("modes", "cookie-only,cookie-group", "cookie-only,cookie-group (P384 for Firefox, P256 otherwise)")
var samplesFlag = flag.Int("samples", 16, "independent default-name samples per profile/mode, 1..256")
var casesFlag = flag.String("cases", "", "optional comma-separated base cases; empty also tests attainable second-flight padding boundaries")

var cookie = []byte("aerobox-cookie")
var hrrRandom = []byte{
	0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
}

type captureConn struct {
	output bytes.Buffer
	input  *bytes.Reader
}

func (c *captureConn) Read(p []byte) (int, error) {
	if c.input == nil {
		return 0, io.EOF
	}
	return c.input.Read(p)
}
func (c *captureConn) Write(p []byte) (int, error) {
	if c.output.Len()+len(p) > captureLimit {
		return 0, errors.New("capture exceeds 1 MiB")
	}
	return c.output.Write(p)
}
func (*captureConn) Close() error                     { return nil }
func (*captureConn) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234} }
func (*captureConn) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (*captureConn) SetDeadline(time.Time) error      { return nil }
func (*captureConn) SetReadDeadline(time.Time) error  { return nil }
func (*captureConn) SetWriteDeadline(time.Time) error { return nil }

type extensionObject struct {
	Type       string `json:"type"`
	WireLength int    `json:"wire_length"`
}

func objects(connection *utls.UConn) []extensionObject {
	result := make([]extensionObject, 0, len(connection.Extensions))
	for _, extension := range connection.Extensions {
		result = append(result, extensionObject{reflect.TypeOf(extension).String(), extension.Len()})
	}
	return result
}

type result struct {
	Source            string            `json:"source"`
	Name              string            `json:"name"`
	Profile           string            `json:"profile"`
	Mode              string            `json:"mode"`
	Case              string            `json:"case"`
	Sample            int               `json:"sample"`
	ServerName        string            `json:"server_name"`
	RequestedALPN     []string          `json:"requested_alpn"`
	CookieHex         string            `json:"cookie_hex"`
	HRRHex            string            `json:"hrr_handshake_hex,omitempty"`
	HRRRecordHex      string            `json:"hrr_record_hex,omitempty"`
	OutboundWireHex   string            `json:"outbound_wire_hex,omitempty"`
	ClientHellosHex   []string          `json:"client_hellos_hex,omitempty"`
	ClientRecordsHex  []string          `json:"client_hello_records_hex,omitempty"`
	BuiltHelloHex     string            `json:"built_first_hello_hex,omitempty"`
	ObjectsBefore     []extensionObject `json:"objects_before,omitempty"`
	ObjectsAfter      []extensionObject `json:"objects_after,omitempty"`
	PaddingBefore     bool              `json:"has_padding_object"`
	SecondUnpadded    int               `json:"second_unpadded_hello_length,omitempty"`
	SecondTarget      int               `json:"second_unpadded_target,omitempty"`
	HandshakeComplete bool              `json:"handshake_complete"`
	ExpectedEOF       bool              `json:"expected_eof"`
	BuildError        string            `json:"build_error"`
	HandshakeError    string            `json:"handshake_error"`
	ValidationError   string            `json:"validation_error,omitempty"`
	Panic             string            `json:"panic,omitempty"`
	SkippedReason     string            `json:"skipped_reason,omitempty"`
}

type captureCase struct {
	name   string
	modify func(*utls.Config)
}

func profileID(name string) (utls.ClientHelloID, bool) {
	switch name {
	case "edge":
		return utls.HelloEdge_85, true
	case "qq":
		return utls.HelloQQ_11_1, true
	case "firefox":
		return utls.HelloFirefox_120, true
	case "safari":
		return utls.HelloSafari_16_0, true
	case "ios":
		return utls.HelloIOS_14, true
	case "chrome":
		return utls.HelloChrome_133, true
	default:
		return utls.ClientHelloID{}, false
	}
}

func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func vector16(p []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(p))), p...)
}
func extension(id uint16, p []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, id), vector16(p)...)
}
func handshake(typ byte, p []byte) []byte {
	return append([]byte{typ, byte(len(p) >> 16), byte(len(p) >> 8), byte(len(p))}, p...)
}
func record(typ byte, p []byte) []byte {
	return append([]byte{typ, 3, 3}, vector16(p)...)
}

// The HRR is deliberately not followed by a certificate or Finished.
func helloRetry(session []byte, changedGroup bool, requestedGroup uint16) []byte {
	body := append([]byte{3, 3}, hrrRandom...)
	body = append(body, byte(len(session)))
	body = append(body, session...)
	body = append(body, 0x13, 1, 0) // AES128GCM and null compression
	exts := extension(43, []byte{3, 4})
	if changedGroup {
		exts = append(exts, extension(51, binary.BigEndian.AppendUint16(nil, requestedGroup))...)
	}
	exts = append(exts, extension(44, vector16(cookie))...)
	return handshake(2, append(body, vector16(exts)...))
}

func capture(name, mode string, profile utls.ClientHelloID, test captureCase, sample int) (out result) {
	out.Source, out.Name, out.Profile, out.Mode = sourceVersion, name, profile.Str(), mode
	out.Case, out.Sample, out.CookieHex = test.name, sample, hex.EncodeToString(cookie)
	defer func() {
		if failure := recover(); failure != nil {
			out.Panic = fmt.Sprint(failure)
		}
	}()
	config := &utls.Config{ServerName: defaultName}
	test.modify(config)
	out.ServerName = config.ServerName
	out.RequestedALPN = append([]string(nil), config.NextProtos...)
	wire := new(captureConn)
	connection := utls.UClient(wire, config, profile)
	err := connection.BuildHandshakeState()
	if err == nil && len(out.RequestedALPN) > 0 {
		// Fixed sing-box wrapper: replace an existing ALPN extension.
		for _, ext := range connection.Extensions {
			if alpn, ok := ext.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = out.RequestedALPN
				err = connection.BuildHandshakeState()
				break
			}
		}
	}
	out.BuildError = errorText(err)
	if err != nil {
		return out
	}
	out.BuiltHelloHex = hex.EncodeToString(connection.HandshakeState.Hello.Raw)
	out.ObjectsBefore = objects(connection)
	for _, ext := range connection.Extensions {
		if _, ok := ext.(*utls.UtlsPaddingExtension); ok {
			out.PaddingBefore = true
		}
	}
	requestedGroup := uint16(23)
	if name == "firefox" {
		requestedGroup = 24 // P256 is already in Firefox's first flight.
	}
	hrr := helloRetry(connection.HandshakeState.Hello.SessionId, mode == "cookie-group", requestedGroup)
	hrrRecord := record(22, hrr)
	out.HRRHex, out.HRRRecordHex = hex.EncodeToString(hrr), hex.EncodeToString(hrrRecord)
	wire.input = bytes.NewReader(hrrRecord)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	err = connection.HandshakeContext(ctx)
	cancel()
	out.HandshakeError = errorText(err)
	out.HandshakeComplete = connection.ConnectionState().HandshakeComplete
	out.ExpectedEOF = errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF)
	out.ObjectsAfter = objects(connection)
	out.OutboundWireHex = hex.EncodeToString(wire.output.Bytes())
	hellos, records, parseErr := clientFlights(wire.output.Bytes())
	for _, hello := range hellos {
		out.ClientHellosHex = append(out.ClientHellosHex, hex.EncodeToString(hello))
	}
	for _, message := range records {
		out.ClientRecordsHex = append(out.ClientRecordsHex, hex.EncodeToString(message))
	}
	if parseErr != nil {
		out.ValidationError = parseErr.Error()
		return out
	}
	if len(hellos) != 2 || len(records) != 2 || out.HandshakeComplete || !out.ExpectedEOF {
		out.ValidationError = "expected exactly two ClientHello flights followed by unauthenticated EOF"
		return out
	}
	if !bytes.Equal(hellos[0], connectionRaw(out.BuiltHelloHex)) {
		out.ValidationError = "built first ClientHello differs from actual wire"
		return out
	}
	pad, err := paddingLength(hellos[1])
	if err != nil {
		out.ValidationError = err.Error()
		return out
	}
	out.SecondUnpadded = len(hellos[1]) - pad
	return out
}

func connectionRaw(s string) []byte { p, _ := hex.DecodeString(s); return p }

// Extract actual complete ClientHello messages, preserving their TLS records.
// CCS records stay in OutboundWireHex and never enter the transcript flights.
func clientFlights(wire []byte) (hellos, records [][]byte, err error) {
	var pending, frames []byte
	for len(wire) != 0 {
		if len(wire) < 5 {
			return nil, nil, errors.New("truncated TLS header")
		}
		length := int(binary.BigEndian.Uint16(wire[3:5]))
		if len(wire) < 5+length {
			return nil, nil, errors.New("truncated TLS record")
		}
		frame := wire[:5+length]
		wire = wire[5+length:]
		switch frame[0] {
		case 20:
			if !bytes.Equal(frame[5:], []byte{1}) || len(pending) != 0 {
				return nil, nil, errors.New("invalid/interleaved compatibility CCS")
			}
			continue
		case 22:
			pending = append(pending, frame[5:]...)
			frames = append(frames, frame...)
		default:
			return nil, nil, fmt.Errorf("unexpected client record type %d", frame[0])
		}
		if len(pending) < 4 {
			continue
		}
		length = 4 + (int(pending[1]) << 16) + (int(pending[2]) << 8) + int(pending[3])
		if len(pending) < length {
			continue
		}
		if len(pending) != length || pending[0] != 1 {
			return nil, nil, errors.New("unexpected coalesced/non-ClientHello handshake")
		}
		hellos = append(hellos, append([]byte(nil), pending...))
		records = append(records, append([]byte(nil), frames...))
		pending, frames = nil, nil
	}
	if len(pending) != 0 {
		return nil, nil, errors.New("incomplete ClientHello")
	}
	return hellos, records, nil
}

func paddingLength(hello []byte) (int, error) {
	if len(hello) < 39 || hello[0] != 1 {
		return 0, errors.New("short ClientHello")
	}
	i := 38
	i += 1 + int(hello[i])
	if i+2 > len(hello) {
		return 0, errors.New("short cipher vector")
	}
	i += 2 + int(binary.BigEndian.Uint16(hello[i:i+2]))
	if i+1 > len(hello) {
		return 0, errors.New("short compression vector")
	}
	i += 1 + int(hello[i])
	if i+2 > len(hello) || i+2+int(binary.BigEndian.Uint16(hello[i:i+2])) != len(hello) {
		return 0, errors.New("invalid extension vector")
	}
	i += 2
	pad := 0
	for i < len(hello) {
		if i+4 > len(hello) {
			return 0, errors.New("short extension header")
		}
		typ, n := binary.BigEndian.Uint16(hello[i:i+2]), int(binary.BigEndian.Uint16(hello[i+2:i+4]))
		if i+4+n > len(hello) {
			return 0, errors.New("short extension payload")
		}
		if typ == 21 {
			if pad != 0 || !bytes.Equal(hello[i+4:i+4+n], make([]byte, n)) {
				return 0, errors.New("duplicate/nonzero padding")
			}
			pad = 4 + n
		}
		i += 4 + n
	}
	return pad, nil
}

func dnsName(length int) string {
	if length < 1 || length > 253 {
		panic("DNS name length out of range")
	}
	var labels []string
	for length > 63 {
		n := 63
		if length == 64 {
			n = 62
		}
		labels = append(labels, strings.Repeat("a", n))
		length -= n + 1
	}
	return strings.Join(append(labels, strings.Repeat("b", length)), ".")
}

func cases() []captureCase {
	out := []captureCase{
		{"default", func(*utls.Config) {}},
		{"no_sni_verify_name", func(c *utls.Config) { c.ServerName = ""; c.InsecureServerNameToVerify = defaultName }},
		{"ipv4", func(c *utls.Config) { c.ServerName = "192.0.2.1" }},
		{"alpn_custom", func(c *utls.Config) { c.NextProtos = []string{"audit-custom"} }},
		{"alpn_h2", func(c *utls.Config) { c.NextProtos = []string{"h2"} }},
		{"alpn_h2_setter", func(c *utls.Config) { c.NextProtos = []string{"h2", "http/1.1"} }},
	}
	for _, length := range []int{63, 127, 191, 253} {
		out = append(out, captureCase{fmt.Sprintf("long_sni_%d", length), func(c *utls.Config) { c.ServerName = dnsName(length) }})
	}
	return out
}

func main() {
	flag.Parse()
	if *samplesFlag < 1 || *samplesFlag > 256 {
		panic("--samples must be 1..256")
	}
	filter := map[string]bool{}
	if *casesFlag != "" {
		for _, name := range strings.Split(*casesFlag, ",") {
			filter[name] = true
		}
		for name := range filter {
			found := false
			for _, test := range cases() {
				found = found || test.name == name
			}
			if !found {
				panic("unknown case " + name)
			}
		}
	}
	var results []result
	for _, name := range strings.Split(*profilesFlag, ",") {
		profile, ok := profileID(name)
		if !ok {
			panic("unknown/unsupported HRR profile " + name)
		}
		for _, mode := range strings.Split(*modesFlag, ",") {
			if mode != "cookie-only" && mode != "cookie-group" {
				panic("unknown mode " + mode)
			}
			var baseline result
			for _, test := range cases() {
				if len(filter) != 0 && !filter[test.name] {
					continue
				}
				samples := 1
				if test.name == "default" {
					samples = *samplesFlag
				}
				for i := 0; i < samples; i++ {
					r := capture(name, mode, profile, test, i)
					results = append(results, r)
					if test.name == "default" && i == 0 {
						baseline = r
					}
				}
			}
			if len(filter) != 0 || !baseline.PaddingBefore {
				continue
			}
			for _, target := range []int{255, 256, 507, 508, 511, 512} {
				nameLength := target - (baseline.SecondUnpadded - len(defaultName))
				caseName := fmt.Sprintf("second_padding_unpadded_%d", target)
				if nameLength < 1 || nameLength > 253 {
					results = append(results, result{Source: sourceVersion, Name: name, Profile: profile.Str(), Mode: mode, Case: caseName, SecondTarget: target, SkippedReason: "unreachable by changing only a valid DNS SNI length (1..253)"})
					continue
				}
				r := capture(name, mode, profile, captureCase{caseName, func(c *utls.Config) { c.ServerName = dnsName(nameLength) }}, 0)
				r.SecondTarget = target
				if r.SecondUnpadded != target {
					r.ValidationError = "second-flight unpadded length differs from requested target"
				}
				results = append(results, r)
			}
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		panic(err)
	}
	for _, r := range results {
		if r.SkippedReason != "" {
			continue
		}
		if r.Panic != "" || r.BuildError != "" || r.ValidationError != "" || r.HandshakeComplete || !r.ExpectedEOF {
			os.Exit(1)
		}
	}
}
