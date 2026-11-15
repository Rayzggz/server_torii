package token

import (
	"strings"
	"testing"
	"time"
)

const (
	testKey = "0123456789abcdef"
	// Computed outside Go: the signature is an HMAC-SHA256 over the fields "v2", the label,
	// "1700000000", "example.com" and "UA-X", each after its length as four big-endian bytes.
	// Every node, of every release, has to agree on this value.
	reference = "v2.1700000000.tNuJKQAaAnW32fCWPU_mmCZbI1r3cULhwMRC610v4Ew"
)

var issued = time.Unix(1700000000, 0)

func TestSignerVector(t *testing.T) {
	s := Signer{Key: testKey, Label: "CAPTCHA-CLEARANCE@shop"}
	if got := s.Sign("example.com", "UA-X", issued); got != reference {
		t.Fatalf("Sign = %s", got)
	}
	if !s.Verify(reference, "example.com", "UA-X", 60, issued.Add(60*time.Second)) {
		t.Error("token rejected at exactly maxAge")
	}
	if s.Verify(reference, "example.com", "UA-X", 60, issued.Add(61*time.Second)) {
		t.Error("token accepted past maxAge")
	}
	if !s.Verify(reference, "example.com", "UA-X", 0, issued.Add(24*365*time.Hour)) {
		t.Error("token without maxAge expired")
	}
	if s.Verify(reference, "other.example", "UA-X", 0, issued) || s.Verify(reference, "example.com", "UA-Y", 0, issued) {
		t.Error("token accepted for another host or user agent")
	}
	if (Signer{Key: s.Key, Label: "CAPTCHA-SESSION@shop"}).Verify(reference, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another label")
	}
	if (Signer{Key: "fedcba9876543210", Label: s.Label}).Verify(reference, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another key")
	}
}

func TestMalformedTokens(t *testing.T) {
	s := Signer{Key: testKey, Label: "CAPTCHA-CLEARANCE@shop"}
	parts := strings.Split(reference, ".")
	join := func(p ...string) string { return strings.Join(p, ".") }
	for name, value := range map[string]string{
		"empty":                  "",
		"two parts":              join(parts[0], parts[1]),
		"four parts":             reference + ".x",
		"old format":             "1700000000:d52db683cd3f70018f08ba8778646732",
		"another version":        join("v1", parts[1], parts[2]),
		"another time":           join(parts[0], "1700000001", parts[2]),
		"time with a sign":       join(parts[0], "+1700000000", parts[2]),
		"time with a zero":       join(parts[0], "01700000000", parts[2]),
		"time that is no number": join(parts[0], "soon", parts[2]),
		"truncated signature":    reference[:len(reference)-1],
		"padded signature":       reference + "=",
	} {
		if s.Verify(value, "example.com", "UA-X", 0, issued) {
			t.Errorf("%s: %q accepted", name, value)
		}
	}
}

// Fields are signed with their lengths: moving a character from one field to its neighbour
// gives another signature.
func TestFieldsDoNotRunTogether(t *testing.T) {
	s := Signer{Key: testKey, Label: "L"}
	value := s.Sign("example.com", "UA-X", issued)
	if s.Verify(value, "example.comU", "A-X", 0, issued) || s.Verify(value, "example.co", "mUA-X", 0, issued) {
		t.Error("host and user agent run together")
	}
	if (Signer{Key: s.Key, Label: "L1"}).Sign("x", "", issued) == (Signer{Key: s.Key, Label: "L"}).Sign("x", "", issued) {
		t.Error("labels sign alike")
	}
}

// Check says why a token is refused. A forged token is never called expired: its age means nothing.
func TestCheckSaysWhy(t *testing.T) {
	signer := Signer{Key: "0123456789abcdef", Label: "CAPTCHA-CLEARANCE@shop"}
	at := time.Unix(1700000000, 0)
	valid := signer.Sign("example.com", "UA-X", at)
	forged := "v2.1600000000." + strings.Split(valid, ".")[2]
	for _, tt := range []struct {
		name, value, host string
		now               time.Time
		want              error
	}{
		{"valid", valid, "example.com", at.Add(time.Minute), nil},
		{"expired", valid, "example.com", at.Add(time.Hour), ErrExpired},
		{"other host", valid, "other.example", at.Add(time.Minute), ErrSignature},
		{"old and forged", forged, "example.com", at.Add(time.Minute), ErrSignature},
		{"malformed", "v1.1700000000.x", "example.com", at, ErrMalformed},
		{"bad timestamp", "v2.01700000000.x", "example.com", at, ErrMalformed},
	} {
		if err := signer.Check(tt.value, tt.host, "UA-X", 600, tt.now); err != tt.want {
			t.Errorf("%s: Check = %v, want %v", tt.name, err, tt.want)
		}
		if got := signer.Verify(tt.value, tt.host, "UA-X", 600, tt.now); got != (tt.want == nil) {
			t.Errorf("%s: Verify = %v", tt.name, got)
		}
	}
}
