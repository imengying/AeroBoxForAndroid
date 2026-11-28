package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	utls "github.com/metacubex/utls"
)

type tlsClient interface {
	net.Conn
	Handshake() error
	CloseWrite() error
}

func fixtureFiles(directory string) ([]byte, []byte) {
	cert, err := os.ReadFile(filepath.Join(directory, "rsa-cert.der"))
	if err != nil {
		panic(err)
	}
	key, err := os.ReadFile(filepath.Join(directory, "rsa-key.der"))
	if err != nil {
		panic(err)
	}
	return cert, key
}

func selftest(cert, key []byte) error {
	root, err := x509.ParseCertificate(cert)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	clock := func() time.Time { return time.Unix(1893456000, 0) }
	type test struct {
		name           string
		standard       bool
		options        peerOptions
		expectError    bool
		clientSettings map[string][]byte
	}
	// A SETTINGS frame with HEADER_TABLE_SIZE=4096, and a separate empty
	// SETTINGS frame from the client. TLS treats these settings as opaque.
	settings := []byte{0, 0, 6, 4, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0x10, 0}
	clientSettings := []byte{0, 0, 0, 4, 0, 0, 0, 0, 0}
	cases := []test{
		{name: "standard_go_tls13", standard: true},
		{name: "standard_go_p384_hrr", standard: true, options: peerOptions{Group: 24}},
		{name: "standard_go_cookie_hrr", standard: true, options: peerOptions{CookieRetry: true}},
		{name: "chrome133_plain"},
		{name: "chrome133_hybrid_brotli_alps", options: peerOptions{Group: 0x11ec, ALPS: 17613, Compress: true}},
		{name: "chrome133_p256_hrr_brotli_alps", options: peerOptions{Group: 23, ALPS: 17613, Compress: true}},
		{name: "chrome133_p384_hrr_brotli_alps", options: peerOptions{Group: 24, ALPS: 17613, Compress: true}},
		{name: "chrome133_cookie_hrr_brotli_alps", options: peerOptions{CookieRetry: true, ALPS: 17613, Compress: true}},
		{name: "chrome133_brotli", options: peerOptions{Compress: true}},
		{name: "chrome133_alps17613_empty", options: peerOptions{ALPS: 17613}},
		{name: "chrome133_alps17613_brotli", options: peerOptions{ALPS: 17613, Compress: true, ServerSettings: settings}},
		{name: "chrome133_configured_h2_settings_ignored", options: peerOptions{ALPS: 17613, Compress: true, ServerSettings: settings}, clientSettings: map[string][]byte{"h2": clientSettings}},
		{name: "utls_empty_alpn_lookup_workaround", options: peerOptions{ALPS: 17613, Compress: true, ServerSettings: settings, ExpectedClientSettings: clientSettings}, clientSettings: map[string][]byte{"": clientSettings}},
		{name: "custom_alps17513_brotli", options: peerOptions{ALPS: 17513, Compress: true, ServerSettings: settings}},
		{name: "chrome133_valid_sct", options: peerOptions{ALPS: 17613, Compress: true, SCT: "valid"}},
		{name: "chrome133_empty_sct", options: peerOptions{ALPS: 17613, Compress: true, SCT: "empty"}, expectError: true},
		{name: "chrome133_empty_sct_entry", options: peerOptions{ALPS: 17613, Compress: true, SCT: "empty-entry"}, expectError: true},
		{name: "chrome133_trailing_sct", options: peerOptions{ALPS: 17613, Compress: true, SCT: "trailing"}, expectError: true},
		{name: "bad_brotli_length", options: peerOptions{Compress: true, BadCertificateLength: true}, expectError: true},
		{name: "bad_finished", options: peerOptions{ALPS: 17613, Compress: true, BadFinished: true}, expectError: true},
	}
	var outcomes []map[string]any
	for _, tc := range cases {
		if !tc.standard {
			tc.options.ExpectedShares = []uint16{4588, 29}
		}
		left, right := net.Pipe()
		_ = left.SetDeadline(time.Now().Add(15 * time.Second))
		type completion struct {
			result peerResult
			err    error
		}
		server := make(chan completion, 1)
		go func() { r, e := serveWire(right, cert, key, tc.options); server <- completion{r, e} }()
		var client tlsClient
		if tc.standard {
			client = tls.Client(left, &tls.Config{ServerName: "localhost", RootCAs: roots, Time: clock, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}})
		} else {
			cfg := &utls.Config{ServerName: "localhost", RootCAs: roots, Time: clock}
			cfg.ApplicationSettings = tc.clientSettings
			uc := utls.UClient(left, cfg, utls.HelloChrome_133)
			if tc.options.ALPS == 17513 {
				if err := uc.BuildHandshakeState(); err != nil {
					return err
				}
				for i, ext := range uc.Extensions {
					if _, ok := ext.(*utls.ApplicationSettingsExtensionNew); ok {
						uc.Extensions[i] = &utls.ApplicationSettingsExtension{SupportedProtocols: []string{"h2"}}
					}
				}
			}
			client = uc
		}
		err = client.Handshake()
		if tc.expectError {
			_ = left.Close()
			outcome := <-server
			if err == nil {
				return fmt.Errorf("%s: client accepted malicious handshake", tc.name)
			}
			outcomes = append(outcomes, map[string]any{"case": tc.name, "rejected": true, "client_error": err.Error(), "server_failed": outcome.err != nil})
			continue
		}
		if err != nil {
			_ = left.Close()
			outcome := <-server
			return fmt.Errorf("%s handshake: %w; server: %v", tc.name, err, outcome.err)
		}
		if uc, ok := client.(*utls.UConn); ok && !bytes.Equal(uc.ConnectionState().PeerApplicationSettings, tc.options.ServerSettings) {
			return fmt.Errorf("%s server settings lost", tc.name)
		}
		payload := make([]byte, 65537)
		for i := range payload {
			payload[i] = byte(i % 251)
		}
		writeDone := make(chan error, 1)
		go func() { writeDone <- writeAll(client, payload) }()
		got := make([]byte, len(payload))
		_, err = io.ReadFull(client, got)
		if err != nil || !bytes.Equal(got, payload) {
			_ = left.Close()
			<-writeDone
			<-server
			return fmt.Errorf("%s data: %v", tc.name, err)
		}
		if err = <-writeDone; err != nil {
			return err
		}
		if err = client.CloseWrite(); err != nil {
			return err
		}
		var extra [1]byte
		n, err := client.Read(extra[:])
		if n != 0 || err != io.EOF {
			return fmt.Errorf("%s close_notify: %v", tc.name, err)
		}
		_ = left.Close()
		outcome := <-server
		if outcome.err != nil {
			return fmt.Errorf("%s server: %w", tc.name, outcome.err)
		}
		outcomes = append(outcomes, map[string]any{"case": tc.name, "completed": true, "result": outcome.result})
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(outcomes)
}

func main() {
	directory := flag.String("fixtures", "../../../crates/aerobox-crypto/tests/fixtures", "public test certificate/key directory")
	self := flag.Bool("selftest", false, "validate against standard Go TLS and pinned uTLS Chrome133")
	alps := flag.Uint("alps", 17613, "ALPS codepoint: 0, 17513 or 17613")
	group := flag.Uint("group", 29, "key exchange: 29 X25519, 23 P256, 24 P384, 25 P521, 256 FFDHE2048, 257 FFDHE3072, 4588 X25519MLKEM768")
	compressed := flag.Bool("brotli", true, "send compressed server Certificate")
	zlibCertificate := flag.Bool("zlib", false, "use zlib Certificate compression instead of Brotli")
	skipCompressionOffer := flag.Bool("skip-compression-check", false, "send compression not advertised by the client")
	corruptCompressed := flag.Bool("corrupt-compressed-data", false, "damage compressed Certificate checksum")
	truncateCompressed := flag.Bool("truncate-compressed-data", false, "truncate compressed Certificate stream")
	sha1Signature := flag.String("sha1-certificate-verify", "", "invalid TLS1.3 signature mode: rsa or ecdsa")
	browserExchange := flag.Bool("android-browser-exchange", false, "one connection with authenticated exporter and duplex data evidence")
	badLength := flag.Bool("bad-certificate-length", false, "deliberately mismatch the decompressed length")
	badFinished := flag.Bool("bad-finished", false, "deliberately send invalid Finished")
	serverSettings := flag.String("server-settings", "", "hex encoded opaque server settings")
	clientSettings := flag.String("client-settings", "", "hex encoded expected client settings")
	selectedALPN := flag.String("selected-alpn", "h2", "server selected ALPN")
	omitALPN := flag.Bool("omit-alpn", false, "malformed ALPS without ALPN")
	skipALPSCheck := flag.Bool("skip-alps-check", false, "send ALPS even when not offered")
	bothALPS := flag.Bool("both-alps", false, "malformed simultaneous ALPS codepoints")
	earlyData := flag.Bool("unsolicited-early-data", false, "send early_data acknowledgement without resumption")
	tickets := flag.Bool("tickets", false, "issue and accept test session tickets")
	earlyMode := flag.String("early", "", "early data mode: empty, accept, reject")
	anyClientSettings := flag.Bool("any-client-settings", false, "allow changed client settings across test sessions")
	oversizedEE := flag.Bool("oversized-ee", false, "declare an impossible EncryptedExtensions length")
	certificateLength := flag.Int("certificate-length", 0, "override advertised decompressed certificate length")
	certificateInflateSize := flag.Int("certificate-inflate-size", 0, "pad decompressed certificate for bounded expansion rejection, at most 1 MiB")
	trailingCompressed := flag.Bool("trailing-compressed-data", false, "append garbage after the compressed certificate")
	mutual := flag.Bool("mutual", false, "require client CertificateVerify and the pinned fixture certificate")
	rotateSettings := flag.Bool("rotate-server-settings", false, "change server settings each resumed connection and reject early data")
	expectedShares := flag.String("expect-shares", "", "expected real initial key share groups in wire order, allowing one leading GREASE dummy")
	cookieRetry := flag.Bool("cookie-retry", false, "issue a cookie-only HelloRetryRequest preserving all original shares")
	forceRetry := flag.Bool("force-retry", false, "request the selected group even if already offered (malformed HRR)")
	sct := flag.String("sct", "", "timestamp framing: valid, empty, empty-entry, trailing")
	unsolicitedSCT := flag.Bool("unsolicited-sct", false, "send a well-framed unadvertised Certificate SCT extension")
	normalOCSP := flag.Bool("ocsp", false, "send a signed fixture OCSP response; requires status_request")
	unsolicitedOCSP := flag.Bool("unsolicited-ocsp", false, "send a well-framed unadvertised Certificate OCSP extension")
	allowNoALPN := flag.Bool("allow-no-alpn", false, "allow absent client ALPN only with -omit-alpn -alps=0")
	unsolicitedALPN := flag.Bool("unsolicited-alpn", false, "send valid h2 without a client ALPN offer; requires ALPS=0")
	realitySuite := flag.Uint("reality-suite", 0, "randomized REALITY suite: 0 selects first actually offered; 4865, 4866 or 4867 explicit")
	realityExchange := flag.Bool("randomized-reality-exchange", false, "single authenticated REALITY connection with exporter/duplex evidence")
	unadvertised := flag.Bool("unadvertised-group", false, "send an invalid P521 HRR")
	realityBrowser := flag.Bool("reality-browser", false, "require the pinned sing-box REALITY share and group layout")
	realityDelegated := flag.Bool("reality-delegated", false, "send a forbidden DC with the authenticated REALITY certificate")
	realityProfile := flag.String("reality-profile", "", "browser layout: chrome (default), edge, qq, safari, ios, firefox or randomized; requires -reality-browser")
	reality := flag.String("reality", "", "test REALITY: valid, bad-hmac, bad-signature, bad-short-id")
	unadvertisedSignature := flag.Bool("unadvertised-signature", false, "send a valid unadvertised Ed25519 CertificateVerify")
	rslLimit := flag.Int("record-size-limit", -1, "opt-in RSL peer limit, including TLS13 inner type and padding; -1 disables mode")
	rslMode := flag.String("record-size-mode", "normal", "normal, omit, unsolicited, duplicate, serverhello, hrr, malformed, oversize-content, oversize-padding")
	rslUpdate := flag.Bool("record-size-key-update", false, "require client KeyUpdate and also send an independent server KeyUpdate")
	rslPadding := flag.Int("record-size-padding", 0, "server application record padding, 0..1024")
	flag.Parse()
	cert, key := fixtureFiles(*directory)
	if *self {
		if err := selftest(cert, key); err != nil {
			panic(err)
		}
		return
	}
	if *alps != 0 && *alps != 17513 && *alps != 17613 {
		panic("unsupported ALPS codepoint")
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	if *group != 29 && *group != 23 && *group != 24 && *group != 25 && *group != 256 && *group != 257 && *group != 0x11ec {
		panic("unsupported key exchange group")
	}
	options := peerOptions{Group: uint16(*group), ALPS: uint16(*alps), Compress: *compressed, BadCertificateLength: *badLength, BadFinished: *badFinished}
	if *zlibCertificate {
		options.Compress, options.CompressionAlgorithm = true, 1
	}
	options.SkipCompressionOffer = *skipCompressionOffer
	options.CorruptCompressedData, options.TruncateCompressedData = *corruptCompressed, *truncateCompressed
	options.SHA1Signature = *sha1Signature
	options.BrowserExchange = *browserExchange
	if *rslLimit >= 0 {
		options.RecordSize = &recordSizeOptions{Limit: *rslLimit, Mode: *rslMode, KeyUpdate: *rslUpdate, Padding: *rslPadding}
		if err := options.RecordSize.validateOptions(options); err != nil {
			panic(err)
		}
	} else if *rslLimit != -1 || *rslMode != "normal" || *rslUpdate || *rslPadding != 0 {
		panic("record-size options require -record-size-limit")
	}
	options.UnadvertisedGroup = *unadvertised
	options.UnadvertisedSignature = *unadvertisedSignature
	options.SCT = *sct
	options.UnsolicitedSCT, options.OCSP, options.UnsolicitedOCSP = *unsolicitedSCT, *normalOCSP, *unsolicitedOCSP
	options.AllowNoALPN = *allowNoALPN
	options.UnsolicitedALPN = *unsolicitedALPN
	if *realitySuite > 65535 {
		panic("invalid REALITY suite")
	}
	options.RealitySuite, options.RealityExchange = uint16(*realitySuite), *realityExchange
	options.Reality = *reality
	options.RealityBrowser = *realityBrowser
	options.RealityProfile = *realityProfile
	options.RealityDelegated = *realityDelegated
	if *realityProfile != "" && !*realityBrowser {
		panic("-reality-profile requires -reality-browser")
	}
	options.SelectedALPN, options.OmitALPN = *selectedALPN, *omitALPN
	options.SkipALPSOfferCheck, options.BothALPS = *skipALPSCheck, *bothALPS
	options.UnsolicitedEarlyData = *earlyData
	if *earlyMode != "" && *earlyMode != "accept" && *earlyMode != "reject" {
		panic("invalid early mode")
	}
	options.EarlyMode = *earlyMode
	options.AnyClientSettings = *anyClientSettings
	options.OversizedEE, options.CertificateLength, options.TrailingCompressedData = *oversizedEE, *certificateLength, *trailingCompressed
	options.CertificateInflateSize = *certificateInflateSize
	options.Mutual = *mutual
	options.RotateServerSettings = *rotateSettings
	options.CookieRetry, options.ForceRetry = *cookieRetry, *forceRetry
	if *expectedShares != "" {
		for _, text := range strings.Split(*expectedShares, ",") {
			group, err := strconv.ParseUint(text, 10, 16)
			if err != nil {
				panic(err)
			}
			options.ExpectedShares = append(options.ExpectedShares, uint16(group))
		}
	}
	if *tickets || *earlyMode != "" {
		options.Tickets = &ticketStore{}
	}
	options.ServerSettings, err = hex.DecodeString(*serverSettings)
	if err != nil {
		panic(err)
	}
	options.ExpectedClientSettings, err = hex.DecodeString(*clientSettings)
	if err != nil {
		panic(err)
	}
	ready := map[string]any{"port": listener.Addr().(*net.TCPAddr).Port}
	if options.BrowserExchange || options.RealityExchange {
		ready["phase"] = "ready"
		if options.Mutual {
			options.ClientCertificate, err = browserClientCertificate(key)
			if err != nil {
				panic(err)
			}
			ready["client_certificate_der_hex"] = hex.EncodeToString(options.ClientCertificate)
		}
		if err = listener.SetDeadline(time.Now().Add(45 * time.Second)); err != nil {
			panic(err)
		}
	}
	if err = json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		panic(err)
	}
	if options.BrowserExchange || options.RealityExchange {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		result, err := serveWire(conn, cert, key, options)
		report := map[string]any{"phase": "complete", "result": result}
		if err != nil {
			report["phase"], report["error"] = "error", err.Error()
		}
		if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
			panic(err)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		go func() {
			result, err := serveWire(conn, cert, key, options)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				_ = json.NewEncoder(os.Stderr).Encode(result)
			}
		}()
	}
}
