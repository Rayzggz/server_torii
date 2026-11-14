package token

import (
	"strings"
	"testing"
	"time"
)

const (
	testKey = "0123456789abcdef"
	// Computed outside Go: the key id is the first six bytes of
	// SHA-256("torii token key id\0" + key), and the signature an HMAC-SHA256 over the fields
	// "v2", the label, "1700000000", "example.com" and "UA-X", each after its length as four
	// big-endian bytes. Every node, of every release, has to agree on this value.
	reference = "v2.OABn0b72.1700000000.tNuJKQAaAnW32fCWPU_mmCZbI1r3cULhwMRC610v4Ew"
)

var issued = time.Unix(1700000000, 0)

func TestSignerVector(t *testing.T) {
	s := Signer{Keys: []string{testKey}, Label: "CAPTCHA-CLEARANCE@shop"}
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
	if (Signer{Keys: s.Keys, Label: "CAPTCHA-SESSION@shop"}).Verify(reference, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another label")
	}
	if (Signer{Keys: []string{"fedcba9876543210"}, Label: s.Label}).Verify(reference, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another key")
	}
	if (Signer{Label: s.Label}).Verify(reference, "example.com", "UA-X", 0, issued) || (Signer{}).Sign("example.com", "UA-X", issued) != "" {
		t.Error("a signer without keys signs or verifies")
	}
}

func TestMalformedTokens(t *testing.T) {
	s := Signer{Keys: []string{testKey}, Label: "CAPTCHA-CLEARANCE@shop"}
	parts := strings.Split(reference, ".")
	join := func(p ...string) string { return strings.Join(p, ".") }
	for name, value := range map[string]string{
		"empty":                  "",
		"three parts":            join(parts[0], parts[1], parts[2]),
		"five parts":             reference + ".x",
		"old format":             "1700000000:d52db683cd3f70018f08ba8778646732",
		"another version":        join("v1", parts[1], parts[2], parts[3]),
		"another key id":         join(parts[0], "AAAAAAAA", parts[2], parts[3]),
		"another time":           join(parts[0], parts[1], "1700000001", parts[3]),
		"time with a sign":       join(parts[0], parts[1], "+1700000000", parts[3]),
		"time with a zero":       join(parts[0], parts[1], "01700000000", parts[3]),
		"time that is no number": join(parts[0], parts[1], "soon", parts[3]),
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
	s := Signer{Keys: []string{testKey}, Label: "L"}
	value := s.Sign("example.com", "UA-X", issued)
	if s.Verify(value, "example.comU", "A-X", 0, issued) || s.Verify(value, "example.co", "mUA-X", 0, issued) {
		t.Error("host and user agent run together")
	}
	if (Signer{Keys: s.Keys, Label: "L1"}).Sign("x", "", issued) == (Signer{Keys: s.Keys, Label: "L"}).Sign("x", "", issued) {
		t.Error("labels sign alike")
	}
}

// Replacing a key: the new key goes in front and signs, the old one keeps verifying, and a node
// that has not been updated yet accepts neither more nor less than its own keys allow.
func TestKeyRotation(t *testing.T) {
	const oldKey, newKey = "old-key-0123456789", "new-key-0123456789"
	before := Signer{Keys: []string{oldKey}, Label: "L"}
	during := Signer{Keys: []string{newKey, oldKey}, Label: "L"}
	after := Signer{Keys: []string{newKey}, Label: "L"}

	oldToken := before.Sign("h", "ua", issued)
	newToken := during.Sign("h", "ua", issued)
	if newToken != after.Sign("h", "ua", issued) || newToken == oldToken {
		t.Fatal("the first key must sign")
	}
	if !strings.Contains(newToken, "."+KeyID(newKey)+".") || !strings.Contains(oldToken, "."+KeyID(oldKey)+".") {
		t.Error("a token names its key")
	}
	for name, ok := range map[string]bool{
		"old token during the change": during.Verify(oldToken, "h", "ua", 0, issued),
		"new token during the change": during.Verify(newToken, "h", "ua", 0, issued),
		"new token afterwards":        after.Verify(newToken, "h", "ua", 0, issued),
		// Two nodes with the same keys in another order still share every token.
		"keys in another order": (Signer{Keys: []string{oldKey, newKey}, Label: "L"}).Verify(newToken, "h", "ua", 0, issued),
	} {
		if !ok {
			t.Errorf("%s: rejected", name)
		}
	}
	if after.Verify(oldToken, "h", "ua", 0, issued) || before.Verify(newToken, "h", "ua", 0, issued) {
		t.Error("a token verified without its key")
	}
}
