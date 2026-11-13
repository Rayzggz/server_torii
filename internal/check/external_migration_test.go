package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/state"
	"server_torii/internal/utils"
	"strings"
	"testing"
	"time"
)

func testExternalRuleSet() *config.RuleSet {
	return &config.RuleSet{
		ExternalMigrationRule: &dataType.ExternalMigrationRule{
			Enabled:        true,
			RedirectUrl:    "https://mitigation.invalid/verify",
			SecretKey:      "external-secret-0123456789",
			SessionTimeout: 600,
		},
		CAPTCHARule: &dataType.CaptchaRule{SecretKey: "external-secret-0123456789"},
	}
}

func testExternalRequest() dataType.UserRequest {
	return dataType.UserRequest{
		RemoteIP:       "203.0.113.10",
		Host:           "example.com",
		UserAgent:      "Mozilla/5.0 test-agent",
		Uri:            "/protected",
		FeatureControl: dataType.FeatureExternalMigration,
	}
}

// signExternalClearance builds a clearance with an arbitrary timestamp, so expiry can be tested.
func signExternalClearance(reqData dataType.UserRequest, secret string, ts int64) string {
	mac := hmac.New(sha512.New, []byte(secret))
	mac.Write(fmt.Appendf(nil, "%d%s%sEXTERNAL-CLEARANCE", ts, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent)))
	return fmt.Sprintf("%d:%x", ts, mac.Sum(nil))
}

func runExternalMigration(reqData dataType.UserRequest, ruleSet *config.RuleSet) *action.Decision {
	decision := action.NewDecision()
	ExternalMigration(reqData, ruleSet, decision, &state.Runtime{})
	return decision
}

func TestExternalMigrationFeatureDisabledContinues(t *testing.T) {
	reqData := testExternalRequest()
	reqData.FeatureControl = 0

	decision := runExternalMigration(reqData, testExternalRuleSet())
	if decision.State != action.Continue {
		t.Fatalf("state = %v, want Continue", decision.State)
	}
}

func TestExternalMigrationClearance(t *testing.T) {
	ruleSet := testExternalRuleSet()
	base := testExternalRequest()
	valid := string(GenExternalMigrationClearance(base, *ruleSet))
	now := time.Now().Unix()
	timeout := ruleSet.ExternalMigrationRule.SessionTimeout
	ts, hash, _ := strings.Cut(valid, ":")
	flipped := "0"
	if hash[0] == '0' {
		flipped = "1"
	}

	tests := []struct {
		name      string
		mutate    func(r *dataType.UserRequest)
		wantClear bool
	}{
		{"valid clearance", func(r *dataType.UserRequest) { r.ToriiClearance = valid }, true},
		{"missing clearance", func(r *dataType.UserRequest) {}, false},
		{"no separator", func(r *dataType.UserRequest) { r.ToriiClearance = ts + hash }, false},
		{"extra separator", func(r *dataType.UserRequest) { r.ToriiClearance = valid + ":x" }, false},
		{"non-numeric timestamp", func(r *dataType.UserRequest) { r.ToriiClearance = "abc:" + hash }, false},
		{"tampered hash", func(r *dataType.UserRequest) { r.ToriiClearance = ts + ":" + flipped + hash[1:] }, false},
		{"timestamp moved", func(r *dataType.UserRequest) { r.ToriiClearance = fmt.Sprintf("%d:%s", now-1, hash) }, false},
		{"other host", func(r *dataType.UserRequest) {
			r.ToriiClearance = valid
			r.Host = "other.example.com"
		}, false},
		{"other user agent family", func(r *dataType.UserRequest) {
			r.ToriiClearance = valid
			r.UserAgent = "curl/8.0"
		}, false},
		{"within timeout", func(r *dataType.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, ruleSet.ExternalMigrationRule.SecretKey, now-timeout+5)
		}, true},
		{"expired", func(r *dataType.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, ruleSet.ExternalMigrationRule.SecretKey, now-timeout-5)
		}, false},
		{"signed with another key", func(r *dataType.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, "another-secret-0123456789", now)
		}, false},
		{"CAPTCHA clearance with the same key", func(r *dataType.UserRequest) {
			r.ToriiClearance = string(GenClearance(*r, *ruleSet))
		}, false},
		{"external session id is not a clearance", func(r *dataType.UserRequest) {
			r.ToriiClearance = string(GenExternalMigrationSessionID(*r, *ruleSet))
		}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData := base
			tt.mutate(&reqData)
			decision := runExternalMigration(reqData, ruleSet)
			if tt.wantClear {
				if decision.State != action.Continue {
					t.Fatalf("state = %v, want Continue", decision.State)
				}
				return
			}
			if decision.State != action.Done || decision.Verdict != action.VerdictExternal {
				t.Fatalf("decision = (%v, %q), want (Done, EXTERNAL)", decision.State, decision.Verdict)
			}
		})
	}
}

func TestExternalMigrationSessionID(t *testing.T) {
	ruleSet := testExternalRuleSet()
	base := testExternalRequest()
	valid := string(GenExternalMigrationSessionID(base, *ruleSet))
	ts, hash, _ := strings.Cut(valid, ":")

	tests := []struct {
		name    string
		mutate  func(r *dataType.UserRequest)
		wantOK  bool
		keyOver string
	}{
		{"valid session", func(r *dataType.UserRequest) { r.ToriiSessionID = valid }, true, ""},
		{"missing session", func(r *dataType.UserRequest) {}, false, ""},
		{"malformed session", func(r *dataType.UserRequest) { r.ToriiSessionID = hash }, false, ""},
		{"non-numeric timestamp", func(r *dataType.UserRequest) { r.ToriiSessionID = "x:" + hash }, false, ""},
		{"timestamp moved", func(r *dataType.UserRequest) { r.ToriiSessionID = ts + "1:" + hash }, false, ""},
		{"other host", func(r *dataType.UserRequest) {
			r.ToriiSessionID = valid
			r.Host = "other.example.com"
		}, false, ""},
		{"other key", func(r *dataType.UserRequest) { r.ToriiSessionID = valid }, false, "another-secret-0123456789"},
		{"clearance is not a session", func(r *dataType.UserRequest) {
			r.ToriiSessionID = string(GenExternalMigrationClearance(*r, *ruleSet))
		}, false, ""},
		{"CAPTCHA session is not an external session", func(r *dataType.UserRequest) {
			r.ToriiSessionID = string(GenSessionID(*r, *ruleSet))
		}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData := base
			tt.mutate(&reqData)
			rs := *ruleSet
			if tt.keyOver != "" {
				rule := *ruleSet.ExternalMigrationRule
				rule.SecretKey = tt.keyOver
				rs.ExternalMigrationRule = &rule
			}
			if got := VerifyExternalMigrationSessionIDCookie(reqData, rs); got != tt.wantOK {
				t.Fatalf("VerifyExternalMigrationSessionIDCookie = %v, want %v", got, tt.wantOK)
			}
		})
	}
}

func TestExternalMigrationHMACsBindEveryInput(t *testing.T) {
	const key = "external-secret-0123456789"

	redirect := CalculateRedirectHMAC("example.com", "1700000000", "/a", key)
	if redirect != CalculateRedirectHMAC("example.com", "1700000000", "/a", key) {
		t.Fatal("redirect HMAC is not deterministic")
	}
	if len(redirect) != sha512.Size*2 {
		t.Fatalf("redirect HMAC length = %d, want %d hex chars", len(redirect), sha512.Size*2)
	}
	for name, other := range map[string]string{
		"domain":    CalculateRedirectHMAC("other.com", "1700000000", "/a", key),
		"timestamp": CalculateRedirectHMAC("example.com", "1700000001", "/a", key),
		"uri":       CalculateRedirectHMAC("example.com", "1700000000", "/b", key),
		"key":       CalculateRedirectHMAC("example.com", "1700000000", "/a", key+"x"),
		// The separator keeps field boundaries from shifting into each other.
		"boundary": CalculateRedirectHMAC("example.com:1700000000", "", "/a", key),
	} {
		if other == redirect {
			t.Errorf("redirect HMAC ignores %s", name)
		}
	}

	migration := CalculateExternalMigrationHMAC("1700000000:abc", "1700000000", "/a", key)
	if migration != CalculateExternalMigrationHMAC("1700000000:abc", "1700000000", "/a", key) {
		t.Fatal("migration HMAC is not deterministic")
	}
	for name, other := range map[string]string{
		"session":   CalculateExternalMigrationHMAC("1700000000:abd", "1700000000", "/a", key),
		"timestamp": CalculateExternalMigrationHMAC("1700000000:abc", "1700000001", "/a", key),
		"uri":       CalculateExternalMigrationHMAC("1700000000:abc", "1700000000", "/b", key),
		"key":       CalculateExternalMigrationHMAC("1700000000:abc", "1700000000", "/a", key+"x"),
	} {
		if other == migration {
			t.Errorf("migration HMAC ignores %s", name)
		}
	}
}
