package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests pin the cookie and signature formats. Cookies already issued to visitors and
// signatures exchanged with the external mitigation provider must keep verifying after an upgrade,
// so the expected values are computed here independently of the implementation.

const contractKey = "0123456789abcdef"

func contractMAC(message string) string {
	mac := hmac.New(sha512.New, []byte(contractKey))
	mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func contractCookie(ts int64, host, ua, label string) string {
	return fmt.Sprintf("%d:%s", ts, contractMAC(fmt.Sprintf("%d%s%s%s", ts, host, ua, label)))
}

func contractFixture() (request.UserRequest, config.RuleSet) {
	return request.UserRequest{Host: "example.com", UserAgent: "UA-X"},
		config.RuleSet{
			CAPTCHARule:           &config.CaptchaRule{SecretKey: contractKey, CaptchaValidateTime: 600, CaptchaChallengeSessionTimeout: 120},
			ExternalMigrationRule: &config.ExternalMigrationRule{SecretKey: contractKey, SessionTimeout: 300},
		}
}

func TestCookieFormatContract(t *testing.T) {
	// "UA-X" is not a browser user agent, so it is signed verbatim.
	if got := GetClearanceUserAgent("UA-X"); got != "UA-X" {
		t.Fatalf("GetClearanceUserAgent = %q", got)
	}
	// Reference vector produced with: printf '%s' "$msg" | openssl dgst -sha512 -hmac "$key"
	const wantMAC = "d52db683cd3f70018f08ba8778646732e1c5233ec2de95fd142859dcb836543e7e47d3fca6d5d476e680c96a4bd76353f054b43c326818c12fd54c1775f1f759"
	if got := contractMAC("1700000000example.comUA-XCAPTCHA-CLEARANCE"); got != wantMAC {
		t.Fatalf("reference MAC mismatch: %s", got)
	}

	now := time.Now().Unix()
	for _, tc := range []struct {
		name   string
		label  string
		maxAge int64 // 0: the cookie never expires on its own
		gen    func(request.UserRequest, config.RuleSet) []byte
		verify func(request.UserRequest, config.RuleSet, string) bool
	}{
		{"captcha clearance", "CAPTCHA-CLEARANCE", 600, GenClearance,
			func(r request.UserRequest, rs config.RuleSet, v string) bool {
				r.ToriiClearance = v
				return verifyClearanceCookie(r, rs)
			}},
		{"captcha session", "CAPTCHA-SESSION", 120, GenSessionID,
			func(r request.UserRequest, rs config.RuleSet, v string) bool {
				r.ToriiSessionID = v
				return VerifySessionIDCookie(r, rs)
			}},
		{"external clearance", "EXTERNAL-CLEARANCE", 300, GenExternalMigrationClearance,
			func(r request.UserRequest, rs config.RuleSet, v string) bool {
				r.ToriiClearance = v
				return verifyExternalMigrationClearanceCookie(r, rs)
			}},
		{"external session", "EXTERNAL-SESSION", 0, GenExternalMigrationSessionID,
			func(r request.UserRequest, rs config.RuleSet, v string) bool {
				r.ToriiSessionID = v
				return VerifyExternalMigrationSessionIDCookie(r, rs)
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, rs := contractFixture()

			issued := string(tc.gen(req, rs))
			tsText, _, ok := strings.Cut(issued, ":")
			ts, err := strconv.ParseInt(tsText, 10, 64)
			if !ok || err != nil || ts < now || ts > now+5 {
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
				"no separator":     strings.Replace(valid, ":", "", 1),
				"extra field":      valid + ":x",
				"bad timestamp":    "x" + valid,
				"tampered mac":     valid[:len(valid)-1] + "0" + "0",
				"other host":       contractCookie(now-1, "other.example", req.UserAgent, tc.label),
				"other user agent": contractCookie(now-1, req.Host, "UA-Y", tc.label),
				"other label":      contractCookie(now-1, req.Host, req.UserAgent, "OTHER"),
			} {
				if tc.verify(req, rs, bad) {
					t.Errorf("%s cookie accepted", name)
				}
			}

			old := contractCookie(now-100000, req.Host, req.UserAgent, tc.label)
			if tc.maxAge == 0 {
				if !tc.verify(req, rs, old) {
					t.Error("cookie without an expiry rejected for its age")
				}
				return
			}
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
