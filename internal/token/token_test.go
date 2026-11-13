package token

import (
	"testing"
	"time"
)

func TestSignerVector(t *testing.T) {
	// Reference produced with:
	//   printf '%s' '1700000000example.comUA-XCAPTCHA-CLEARANCE' | openssl dgst -sha512 -hmac 0123456789abcdef
	const want = "1700000000:d52db683cd3f70018f08ba8778646732e1c5233ec2de95fd142859dcb836543e7e47d3fca6d5d476e680c96a4bd76353f054b43c326818c12fd54c1775f1f759"
	s := Signer{Key: "0123456789abcdef", Label: "CAPTCHA-CLEARANCE"}
	issued := time.Unix(1700000000, 0)
	if got := s.Sign("example.com", "UA-X", issued); got != want {
		t.Fatalf("Sign = %s", got)
	}

	verify := func(s Signer, value, host, ua string, maxAge int64, now time.Time) bool {
		ok, err := s.Verify(value, host, ua, maxAge, now)
		if err != nil {
			t.Fatalf("Verify(%q): %v", value, err)
		}
		return ok
	}
	if !verify(s, want, "example.com", "UA-X", 60, issued.Add(60*time.Second)) {
		t.Error("token rejected at exactly maxAge")
	}
	if verify(s, want, "example.com", "UA-X", 60, issued.Add(61*time.Second)) {
		t.Error("token accepted past maxAge")
	}
	if !verify(s, want, "example.com", "UA-X", 0, issued.Add(24*365*time.Hour)) {
		t.Error("token without maxAge expired")
	}
	if verify(s, want, "other.example", "UA-X", 0, issued) || verify(s, want, "example.com", "UA-Y", 0, issued) {
		t.Error("token accepted for another host or user agent")
	}
	if verify(Signer{Key: s.Key, Label: "CAPTCHA-SESSION"}, want, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another label")
	}
	if verify(Signer{Key: "fedcba9876543210", Label: s.Label}, want, "example.com", "UA-X", 0, issued) {
		t.Error("token accepted under another key")
	}
	for _, malformed := range []string{"", "1700000000", want + ":x"} {
		if verify(s, malformed, "example.com", "UA-X", 0, issued) {
			t.Errorf("malformed token %q accepted", malformed)
		}
	}
	if ok, err := s.Verify("soon:abc", "example.com", "UA-X", 0, issued); ok || err == nil {
		t.Errorf("non-numeric timestamp: ok=%v err=%v", ok, err)
	}
}
