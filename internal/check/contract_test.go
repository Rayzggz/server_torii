package check

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests pin the cookie and signature formats. Cookies already issued to visitors, by any
// node that holds the key, and signatures exchanged with the external mitigation provider must
// keep verifying after an upgrade, so the expected values are computed here independently of
// the implementation.

const contractKey = "0123456789abcdef"

func contractMAC(message string) string {
	mac := hmac.New(sha512.New, []byte(contractKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

// contractCookie builds a cookie the way the format is documented, without the token package:
// "v2.<unix seconds>.<signature>". The signature is an HMAC-SHA256 over the version, the label,
// the timestamp, the host and the user agent, each after its length as four big-endian bytes,
// in base64url without padding.
func contractCookie(ts int64, host, ua, label string) string {
	stamp := strconv.FormatInt(ts, 10)
	mac := hmac.New(sha256.New, []byte(contractKey))
	for _, field := range []string{"v2", label, stamp, host, ua} {
		mac.Write(binary.BigEndian.AppendUint32(nil, uint32(len(field))))
		mac.Write([]byte(field))
	}
	return "v2." + stamp + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func contractFixture(mode config.ChallengeMode) (request.UserRequest, config.RuleSet) {
	return request.UserRequest{Host: "example.com", UserAgent: "UA-X"},
		config.RuleSet{
			Challenge: &config.ChallengeRule{Mode: mode, CookieKey: contractKey, ExternalSecret: contractKey, ClearanceTTL: 600 * time.Second, SessionTTL: 120 * time.Second},
			// The site ID is part of every token, so a token of one site is useless on another.
			ID: "shop",
		}
}

func TestCookieFormatContract(t *testing.T) {
	// "UA-X" is not a browser user agent, so it is signed verbatim.
	if got := GetClearanceUserAgent("UA-X"); got != "UA-X" {
		t.Fatalf("GetClearanceUserAgent = %q", got)
	}
	// Reference vector computed outside Go, see the token package.
	const want = "v2.1700000000.tNuJKQAaAnW32fCWPU_mmCZbI1r3cULhwMRC610v4Ew"
	if got := contractCookie(1700000000, "example.com", "UA-X", "CAPTCHA-CLEARANCE@shop"); got != want {
		t.Fatalf("reference cookie mismatch: %s", got)
	}

	now := time.Now().Unix()
	verifyClearance := func(r request.UserRequest, rs config.RuleSet, v string) bool {
		r.ToriiClearance = v
		return verifyClearanceCookie(r, rs)
	}
	verifySession := func(r request.UserRequest, rs config.RuleSet, v string) bool {
		r.ToriiSessionID = v
		return VerifySessionIDCookie(r, rs)
	}
	for _, tc := range []struct {
		name   string
		mode   config.ChallengeMode
		label  string
		maxAge int64
		gen    func(request.UserRequest, config.RuleSet) []byte
		verify func(request.UserRequest, config.RuleSet, string) bool
	}{
		{"captcha clearance", config.ChallengeHCaptcha, "CAPTCHA-CLEARANCE@shop", 600, GenClearance, verifyClearance},
		{"altcha clearance", config.ChallengeAltcha, "CAPTCHA-CLEARANCE@shop", 600, GenClearance, verifyClearance},
		{"captcha session", config.ChallengeHCaptcha, "CAPTCHA-SESSION@shop", 120, GenSessionID, verifySession},
		{"external clearance", config.ChallengeExternal, "EXTERNAL-CLEARANCE@shop", 600, GenClearance, verifyClearance},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, rs := contractFixture(tc.mode)

			issued := string(tc.gen(req, rs))
			parts := strings.Split(issued, ".")
			if len(parts) != 3 {
				t.Fatalf("issued cookie %q does not have three parts", issued)
			}
			ts, err := strconv.ParseInt(parts[1], 10, 64)
			if err != nil || ts < now || ts > now+5 {
				t.Fatalf("issued cookie %q has no current timestamp", issued)
			}
			if want := contractCookie(ts, req.Host, req.UserAgent, tc.label); issued != want {
				t.Fatalf("issued cookie = %q, want %q", issued, want)
			}

			valid := contractCookie(now-1, req.Host, req.UserAgent, tc.label)
			if !tc.verify(req, rs, valid) {
				t.Fatal("independently built cookie rejected")
			}
			for name, bad := range map[string]string{
				"empty":            "",
				"no separator":     strings.ReplaceAll(valid, ".", ""),
				"extra field":      valid + ".x",
				"old format":       fmt.Sprintf("%d:%s", now-1, contractMAC(fmt.Sprintf("%d%s%s%s", now-1, req.Host, req.UserAgent, tc.label))),
				"other version":    "v1" + strings.TrimPrefix(valid, "v2"),
				"tampered mac":     valid[:len(valid)-2] + "00",
				"other host":       contractCookie(now-1, "other.example", req.UserAgent, tc.label),
				"other user agent": contractCookie(now-1, req.Host, "UA-Y", tc.label),
				"other label":      contractCookie(now-1, req.Host, req.UserAgent, "OTHER"),
			} {
				if tc.verify(req, rs, bad) {
					t.Errorf("%s cookie accepted", name)
				}
			}

			old := contractCookie(now-100000, req.Host, req.UserAgent, tc.label)
			if !tc.verify(req, rs, contractCookie(now-tc.maxAge+2, req.Host, req.UserAgent, tc.label)) {
				t.Error("cookie rejected before its expiry")
			}
			if tc.verify(req, rs, contractCookie(now-tc.maxAge-2, req.Host, req.UserAgent, tc.label)) {
				t.Error("expired cookie accepted")
			}
			if tc.verify(req, rs, old) {
				t.Error("very old cookie accepted")
			}
		})
	}
}

// The session of the external mode is read by the provider, which takes the timestamp in front
// of the colon to verify the redirect. It keeps the form "<unix seconds>:<hex HMAC-SHA512>".
func TestExternalSessionContract(t *testing.T) {
	req, rs := contractFixture(config.ChallengeExternal)
	session := func(ts int64, host, ua, label string) string {
		// Every signed field follows its length as four big-endian bytes.
		var message []byte
		for _, field := range []string{label, strconv.FormatInt(ts, 10), host, ua} {
			message = binary.BigEndian.AppendUint32(message, uint32(len(field)))
			message = append(message, field...)
		}
		return fmt.Sprintf("%d:%s", ts, contractMAC(string(message)))
	}
	verify := func(rs config.RuleSet, v string) bool {
		r := req
		r.ToriiSessionID = v
		return VerifySessionIDCookie(r, rs)
	}
	const label = "EXTERNAL-SESSION@shop"
	now := time.Now().Unix()

	issued := string(GenSessionID(req, rs))
	stamp, ok := ExternalSessionTimestamp(issued)
	ts, err := strconv.ParseInt(stamp, 10, 64)
	if !ok || err != nil || ts < now || ts > now+5 {
		t.Fatalf("issued session %q has no current timestamp", issued)
	}
	if want := session(ts, req.Host, req.UserAgent, label); issued != want {
		t.Fatalf("issued session = %q, want %q", issued, want)
	}

	valid := session(now-1, req.Host, req.UserAgent, label)
	// The age of the session is bounded by the link that accompanies it, not by the session.
	if !verify(rs, valid) || !verify(rs, session(now-100000, req.Host, req.UserAgent, label)) {
		t.Fatal("independently built session rejected")
	}
	for name, bad := range map[string]string{
		"empty":             "",
		"no separator":      strings.Replace(valid, ":", "", 1),
		"extra field":       valid + ":x",
		"bad timestamp":     "x" + valid,
		"padded timestamp":  "0" + valid,
		"tampered mac":      valid[:len(valid)-2] + "00",
		"other host":        session(now-1, "other.example", req.UserAgent, label),
		"other user agent":  session(now-1, req.Host, "UA-Y", label),
		"clearance label":   session(now-1, req.Host, req.UserAgent, "EXTERNAL-CLEARANCE@shop"),
		"token of the site": contractCookie(now-1, req.Host, req.UserAgent, label),
	} {
		if verify(rs, bad) {
			t.Errorf("%s session accepted", name)
		}
	}

	other := rs
	other.Challenge = &config.ChallengeRule{Mode: config.ChallengeExternal, CookieKey: "another-key-0123456789"}
	if verify(rs, string(GenSessionID(req, other))) {
		t.Error("session signed with another key accepted")
	}
}

func TestExternalMigrationSignatureContract(t *testing.T) {
	// Reference vectors produced with openssl, see TestCookieFormatContract.
	const (
		wantMigration = "e38171decb66b0433e130991229b1dc0cdcbfb4c3cd619810a4d56f9c0d3980bb8317441cb674f7c63b8b9a3dd0bca66d6d1b8cf6f0f78a4aa6347a471d896e1"
		wantRedirect  = "fd90b467a307bfa2a5e5a60e27ef2b6a0897851790b371f36053542d63054febd961ed3650533fdb3768db6d61291fa85b01125acb1c33c29c173c4b6757c501"
	)
	// Signed message: sessionID + timestamp + originalURI.
	if got := CalculateExternalMigrationHMAC("1700000000:abcdef", "1700000030", "/path?a=1", contractKey); got != wantMigration {
		t.Errorf("CalculateExternalMigrationHMAC = %s", got)
	}
	// Signed message: domain:timestamp:originalURI.
	if got := CalculateRedirectHMAC("example.com", "1700000000", "/path?a=1", contractKey); got != wantRedirect {
		t.Errorf("CalculateRedirectHMAC = %s", got)
	}
}
