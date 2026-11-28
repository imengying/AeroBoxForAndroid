// Standalone RFC9345 reference. All keys and credentials are public test data.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

type options struct {
	Curve, Mode, IssuerCase string
	Group, Cipher           uint16
	Mutual, Cookie          bool
}
type result struct {
	Group           uint16 `json:"group"`
	Cipher          uint16 `json:"cipher"`
	HelloRetry      bool   `json:"hello_retry"`
	Delegated       bool   `json:"delegated"`
	DCAlgorithm     uint16 `json:"dc_algorithm"`
	IssuerAlgorithm uint16 `json:"issuer_algorithm"`
	ClientVerified  bool   `json:"client_verified"`
	ClientFinished  bool   `json:"client_finished"`
	CloseNotify     bool   `json:"close_notify"`
	Bytes           int    `json:"bytes"`
	Exporter        string `json:"exporter"`
	ClientSHA256    string `json:"client_sha256"`
	ServerSHA256    string `json:"server_sha256"`
}

func main() {
	path := flag.String("fixtures", "../../../crates/aerobox-crypto/src/delegated_credentials/fixtures.json", "public OpenSSL fixture JSON")
	curve := flag.String("curve", "P-256", "P-256, P-384, P-521, Ed25519")
	mode := flag.String("mode", "valid", "credential/wire negative mode")
	issuer := flag.String("issuer-case", "", "pre-signed independent issuer case name")
	group := flag.Uint("group", 29, "29 X25519, 23 P256, 24 P384, 25 P521")
	cipher := flag.Uint("cipher", 0x1301, "TLS13 0x1301, 0x1302 or 0x1303")
	mutual := flag.Bool("mutual", false, "verify the original fixture client chain and CertificateVerify")
	cookie := flag.Bool("cookie", false, "cookie-only HelloRetryRequest")
	flag.Parse()
	f, err := loadFixtures(*path)
	if err != nil {
		panic(err)
	}
	if *group != 29 && *group != 23 && *group != 24 && *group != 25 {
		panic("unsupported group")
	}
	if *cipher > 65535 {
		panic("invalid cipher")
	}
	opts := options{*curve, *mode, *issuer, uint16(*group), uint16(*cipher), *mutual, *cookie}
	if _, err = getSuite(opts.Cipher); err != nil {
		panic(err)
	}
	if _, err = credential(f, opts); err != nil {
		panic(err)
	}
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(45 * time.Second))
	encoder := json.NewEncoder(os.Stdout)
	if err = encoder.Encode(map[string]any{"phase": "ready", "port": listener.Addr().(*net.TCPAddr).Port}); err != nil {
		panic(err)
	}
	conn, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	outcome, err := serve(conn, f, opts)
	if err != nil {
		_ = encoder.Encode(map[string]any{"phase": "rejected", "error": err.Error(), "result": outcome})
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err = encoder.Encode(map[string]any{"phase": "complete", "result": outcome}); err != nil {
		panic(err)
	}
}
