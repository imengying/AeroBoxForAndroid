package main

import (
	tls "github.com/metacubex/utls"
	"testing"
)

func TestRecordSizeReferenceAuthenticatesFullLimitWithPinnedFirefox(t *testing.T) {
	previousFirst, previousSecond := *recordFirst, *recordSecond
	defer func() { *recordFirst, *recordSecond = previousFirst, previousSecond }()
	*recordFirst, *recordSecond = 16384, 16384
	for _, suite := range []uint16{0xc013, 0xc02f} {
		result, err := exercise(t, tls.VersionTLS12, suite, "firefox", "valid", true)
		if err != nil {
			t.Fatal(err)
		}
		if result.RecordCounts[1] < 2 || result.RecordCounts[2] < 2 || result.RecordMaximum[1] > 16384 || result.RecordMaximum[2] > 16384 {
			t.Fatalf("invalid authenticated record evidence: %+v", result)
		}
	}
}

func TestRecordSizeReferenceRejectsPinnedFirefoxIgnoringItsFakeExtension(t *testing.T) {
	previousFirst, previousSecond := *recordFirst, *recordSecond
	defer func() { *recordFirst, *recordSecond = previousFirst, previousSecond }()
	// The pinned uTLS profile advertises a FakeRecordSizeLimitExtension but
	// does not enforce a smaller server limit. This is intentionally negative.
	for _, limits := range [][2]int{{64, 16384}, {16384, 64}} {
		*recordFirst, *recordSecond = limits[0], limits[1]
		result, err := exercise(t, tls.VersionTLS12, 0xc02f, "firefox", "valid", true)
		requireTLSFailure(t, err)
		if result.Phase != "error" {
			t.Fatalf("oversized record accepted: %+v", result)
		}
	}
}
