// Capture actual first-flight bytes from fixed uTLS. EOF is not handshake success.
package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
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

var selectedProfiles = flag.String("profiles", "chrome,android,edge,qq,firefox,safari,ios,360", "comma-separated fixed profile names")
var selectedCases = flag.String("cases", "", "optional comma-separated base case names; empty also adds attainable padding boundary cases")

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

func profileID(name string) (utls.ClientHelloID, bool) {
	switch name {
	case "chrome":
		return utls.HelloChrome_133, true
	case "android":
		return utls.HelloAndroid_11_OkHttp, true
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
	case "360":
		return utls.Hello360_7_5, true
	default:
		return utls.ClientHelloID{}, false
	}
}

type captureCase struct {
	name   string
	modify func(*utls.Config)
}

type captureResult struct {
	Source                 string   `json:"source"`
	Name                   string   `json:"name"`
	Profile                string   `json:"profile"`
	Case                   string   `json:"case"`
	ServerName             string   `json:"server_name"`
	RequestedALPN          []string `json:"requested_alpn"`
	MinBefore              uint16   `json:"min_before"`
	MaxBefore              uint16   `json:"max_before"`
	MinAfter               uint16   `json:"min_after"`
	MaxAfter               uint16   `json:"max_after"`
	ConfigALPNAfter        []string `json:"config_alpn_after"`
	ExtensionObjects       []string `json:"extension_objects"`
	HasPaddingTemplate     bool     `json:"has_padding_template"`
	UnpaddedHelloLength    int      `json:"unpadded_hello_length"`
	PaddingExtensionLength int      `json:"padding_extension_length"`
	PaddingTarget          int      `json:"padding_target,omitempty"`
	HasECDHEKey            bool     `json:"has_ecdhe_keyshare"`
	HandshakeComplete      bool     `json:"handshake_complete"`
	BuildError             string   `json:"build_error"`
	HandshakeError         string   `json:"handshake_error"`
	Panic                  string   `json:"panic,omitempty"`
	SkippedReason          string   `json:"skipped_reason,omitempty"`
	ValidationError        string   `json:"validation_error,omitempty"`
	BuiltClientHelloHex    string   `json:"built_client_hello_hex,omitempty"`
	WireHex                string   `json:"wire_hex,omitempty"`
}

func errorText(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func capture(name string, profile utls.ClientHelloID, test captureCase) (result captureResult) {
	result.Source, result.Name, result.Profile, result.Case = sourceVersion, name, profile.Str(), test.name
	defer func() {
		if failure := recover(); failure != nil {
			result.Panic = fmt.Sprint(failure)
		}
	}()
	config := &utls.Config{ServerName: defaultName}
	test.modify(config)
	requestedALPN := append([]string(nil), config.NextProtos...)
	result.ServerName, result.RequestedALPN = config.ServerName, requestedALPN
	result.MinBefore, result.MaxBefore = config.MinVersion, config.MaxVersion
	wire := new(captureConn)
	connection := utls.UClient(wire, config, profile)
	err := connection.BuildHandshakeState()
	// Match the fixed sing-box wrapper: replace an existing ALPN extension;
	// do not add one to an Android11 hello which did not contain it.
	if err == nil && len(requestedALPN) > 0 {
		for _, extension := range connection.Extensions {
			if alpn, ok := extension.(*utls.ALPNExtension); ok {
				alpn.AlpnProtocols = requestedALPN
				err = connection.BuildHandshakeState()
				break
			}
		}
	}
	result.BuildError = errorText(err)
	result.MinAfter, result.MaxAfter = config.MinVersion, config.MaxVersion
	result.ConfigALPNAfter = append([]string(nil), config.NextProtos...)
	if err != nil {
		return result
	}
	for _, extension := range connection.Extensions {
		result.ExtensionObjects = append(result.ExtensionObjects, reflect.TypeOf(extension).String())
		if padding, ok := extension.(*utls.UtlsPaddingExtension); ok {
			result.HasPaddingTemplate = true
			result.PaddingExtensionLength += padding.Len()
		}
	}
	result.UnpaddedHelloLength = len(connection.HandshakeState.Hello.Raw) - result.PaddingExtensionLength
	result.BuiltClientHelloHex = hex.EncodeToString(connection.HandshakeState.Hello.Raw)
	result.HasECDHEKey = connection.HandshakeState.State13.KeyShareKeys != nil && connection.HandshakeState.State13.KeyShareKeys.Ecdhe != nil
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	err = connection.HandshakeContext(ctx)
	cancel()
	result.HandshakeError = errorText(err)
	result.HandshakeComplete = connection.ConnectionState().HandshakeComplete
	result.WireHex = hex.EncodeToString(wire.Bytes())
	return result
}

// Produce a valid all-ASCII DNS name of the exact length, with labels <=63.
func dnsName(length int) string {
	if length < 1 || length > 253 {
		panic("DNS name length out of range")
	}
	var labels []string
	for length > 63 {
		labelLength := 63
		if length == 64 {
			labelLength = 62
		}
		labels = append(labels, strings.Repeat("a", labelLength))
		length -= labelLength + 1
	}
	labels = append(labels, strings.Repeat("b", length))
	return strings.Join(labels, ".")
}

func cases() []captureCase {
	output := []captureCase{
		{"default", func(*utls.Config) {}},
		{"no_sni_verify_name", func(c *utls.Config) { c.ServerName = ""; c.InsecureServerNameToVerify = defaultName }},
		{"ipv4", func(c *utls.Config) { c.ServerName = "192.0.2.1" }},
		{"alpn_custom", func(c *utls.Config) { c.NextProtos = []string{"audit-custom"} }},
		{"alpn_h2", func(c *utls.Config) { c.NextProtos = []string{"h2"} }},
		// Only SetNextProtos([h2]), not direct options.ALPN, adds HTTP/1.1.
		{"alpn_h2_setter", func(c *utls.Config) { c.NextProtos = []string{"h2", "http/1.1"} }},
	}
	for _, length := range []int{63, 127, 191, 253} {
		output = append(output, captureCase{fmt.Sprintf("long_sni_%d", length), func(c *utls.Config) { c.ServerName = dnsName(length) }})
	}
	return output
}

func main() {
	flag.Parse()
	filter := map[string]bool{}
	if *selectedCases != "" {
		for _, name := range strings.Split(*selectedCases, ",") {
			filter[name] = true
		}
		for name := range filter {
			found := false
			for _, test := range cases() {
				found = found || test.name == name
			}
			if !found {
				fmt.Fprintln(os.Stderr, "unknown case:", name)
				os.Exit(1)
			}
		}
	}
	var results []captureResult
	for _, name := range strings.Split(*selectedProfiles, ",") {
		profile, ok := profileID(name)
		if !ok {
			fmt.Fprintln(os.Stderr, "unknown profile:", name)
			os.Exit(1)
		}
		var baseline captureResult
		for _, test := range cases() {
			if len(filter) != 0 && !filter[test.name] {
				continue
			}
			result := capture(name, profile, test)
			results = append(results, result)
			if test.name == "default" {
				baseline = result
			}
		}
		if len(filter) != 0 || !baseline.HasPaddingTemplate {
			continue
		}
		for _, target := range []int{255, 256, 507, 508, 511, 512} {
			nameLength := target - (baseline.UnpaddedHelloLength - len(defaultName))
			caseName := fmt.Sprintf("padding_unpadded_%d", target)
			if nameLength < 1 || nameLength > 253 {
				results = append(results, captureResult{Source: sourceVersion, Name: name, Profile: profile.Str(), Case: caseName, PaddingTarget: target, SkippedReason: "unreachable by changing only a valid DNS SNI length (1..253)"})
				continue
			}
			result := capture(name, profile, captureCase{caseName, func(c *utls.Config) { c.ServerName = dnsName(nameLength) }})
			result.PaddingTarget = target
			if result.UnpaddedHelloLength != target {
				result.ValidationError = "observed unpadded length differs from requested target"
			}
			results = append(results, result)
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(results); err != nil {
		panic(err)
	}
	for _, result := range results {
		if result.SkippedReason != "" {
			continue
		}
		if result.Panic != "" || result.BuildError != "" || result.ValidationError != "" || result.HandshakeComplete || result.WireHex == "" {
			os.Exit(1)
		}
	}
}
