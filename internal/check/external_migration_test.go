package check

import (
	"crypto/sha512"
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/token"
	"strings"
	"testing"
	"time"
)

func testExternalRuleSet() *config.RuleSet {
	return &config.RuleSet{
		Challenge: &config.ChallengeRule{Mode: config.ChallengeExternal,
			Enabled:        true,
			RedirectURL:    "https://mitigation.invalid/verify",
			CookieKey:      "cookie-key-0123456789",
			ExternalSecret: "external-secret-0123456789",
			ClearanceTTL:   600 * time.Second,
		},
	}
}

// captchaTwin is the same site with the same key, challenging with a CAPTCHA instead.
func captchaTwin(ruleSet *config.RuleSet) config.RuleSet {
	twin := *ruleSet
	rule := *ruleSet.Challenge
	rule.Mode = config.ChallengeHCaptcha
	rule.SessionTTL = 120 * time.Second
	twin.Challenge = &rule
	return twin
}

func testExternalRequest() request.UserRequest {
	return request.UserRequest{
		RemoteIP:       "203.0.113.10",
		Host:           "example.com",
		UserAgent:      "Mozilla/5.0 test-agent",
		Uri:            "/protected",
		FeatureControl: feature.Challenge.ControlMask(),
	}
}

// signExternalClearance builds a clearance with an arbitrary timestamp, so expiry can be tested.
func signExternalClearance(reqData request.UserRequest, secret string, ts int64) string {
	signer := token.Signer{Key: secret, Label: "EXTERNAL-CLEARANCE@"}
	return signer.Sign(reqData.Host, GetClearanceUserAgent(reqData.UserAgent), reqData.ClientKey(), time.Unix(ts, 0))
}

// splitToken returns "v3.", the timestamp and the signature of a token.
func splitToken(t *testing.T, value string) (prefix, ts, sig string) {
	t.Helper()
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		t.Fatalf("token %q does not have three parts", value)
	}
	return parts[0] + ".", parts[1], parts[2]
}

func runExternalMigration(reqData request.UserRequest, ruleSet *config.RuleSet) *action.Decision {
	decision := action.NewDecision()
	Challenge(reqData, ruleSet, decision, &state.Runtime{})
	return decision
}

func TestExternalMigrationClearance(t *testing.T) {
	ruleSet := testExternalRuleSet()
	base := testExternalRequest()
	valid := string(GenClearance(base, *ruleSet))
	now := time.Now().Unix()
	timeout := int64(ruleSet.Challenge.ClearanceTTL / time.Second)
	prefix, ts, hash := splitToken(t, valid)
	flipped := "A"
	if hash[0] == 'A' {
		flipped = "B"
	}

	tests := []struct {
		name      string
		mutate    func(r *request.UserRequest)
		wantClear bool
	}{
		{"valid clearance", func(r *request.UserRequest) { r.ToriiClearance = valid }, true},
		{"missing clearance", func(r *request.UserRequest) {}, false},
		{"no separator", func(r *request.UserRequest) { r.ToriiClearance = strings.ReplaceAll(valid, ".", "") }, false},
		{"extra separator", func(r *request.UserRequest) { r.ToriiClearance = valid + ".x" }, false},
		{"non-numeric timestamp", func(r *request.UserRequest) { r.ToriiClearance = prefix + "abc." + hash }, false},
		{"tampered hash", func(r *request.UserRequest) { r.ToriiClearance = prefix + ts + "." + flipped + hash[1:] }, false},
		{"timestamp moved", func(r *request.UserRequest) { r.ToriiClearance = fmt.Sprintf("%s%d.%s", prefix, now-1, hash) }, false},
		{"other host", func(r *request.UserRequest) {
			r.ToriiClearance = valid
			r.Host = "other.example.com"
		}, false},
		{"other user agent family", func(r *request.UserRequest) {
			r.ToriiClearance = valid
			r.UserAgent = "curl/8.0"
		}, false},
		{"other address", func(r *request.UserRequest) {
			r.ToriiClearance = valid
			r.RemoteIP = "203.0.113.11"
		}, false},
		{"within timeout", func(r *request.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, ruleSet.Challenge.CookieKey, now-timeout+5)
		}, true},
		{"expired", func(r *request.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, ruleSet.Challenge.CookieKey, now-timeout-5)
		}, false},
		{"signed with another key", func(r *request.UserRequest) {
			r.ToriiClearance = signExternalClearance(*r, "another-secret-0123456789", now)
		}, false},
		{"CAPTCHA clearance with the same key", func(r *request.UserRequest) {
			r.ToriiClearance = string(GenClearance(*r, captchaTwin(ruleSet)))
		}, false},
		{"external session id is not a clearance", func(r *request.UserRequest) {
			r.ToriiClearance = string(GenSessionID(*r, *ruleSet))
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
			if decision.State != action.Done || decision.Verdict != action.VerdictChallenge {
				t.Fatalf("decision = (%v, %q), want (Done, challenge)", decision.State, decision.Verdict)
			}
		})
	}
}

func TestExternalMigrationSessionID(t *testing.T) {
	ruleSet := testExternalRuleSet()
	base := testExternalRequest()
	valid := string(GenSessionID(base, *ruleSet))
	ts, hash, _ := strings.Cut(valid, ":")

	tests := []struct {
		name    string
		mutate  func(r *request.UserRequest)
		wantOK  bool
		keyOver string
	}{
		{"valid session", func(r *request.UserRequest) { r.ToriiSessionID = valid }, true, ""},
		{"missing session", func(r *request.UserRequest) {}, false, ""},
		{"malformed session", func(r *request.UserRequest) { r.ToriiSessionID = hash }, false, ""},
		{"non-numeric timestamp", func(r *request.UserRequest) { r.ToriiSessionID = "x:" + hash }, false, ""},
		{"timestamp moved", func(r *request.UserRequest) { r.ToriiSessionID = ts + "1:" + hash }, false, ""},
		{"other host", func(r *request.UserRequest) {
			r.ToriiSessionID = valid
			r.Host = "other.example.com"
		}, false, ""},
		{"other address", func(r *request.UserRequest) {
			r.ToriiSessionID = valid
			r.RemoteIP = "203.0.113.11"
		}, false, ""},
		{"other key", func(r *request.UserRequest) { r.ToriiSessionID = valid }, false, "another-secret-0123456789"},
		{"clearance is not a session", func(r *request.UserRequest) {
			r.ToriiSessionID = string(GenClearance(*r, *ruleSet))
		}, false, ""},
		{"CAPTCHA session is not an external session", func(r *request.UserRequest) {
			r.ToriiSessionID = string(GenSessionID(*r, captchaTwin(ruleSet)))
		}, false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData := base
			tt.mutate(&reqData)
			rs := *ruleSet
			if tt.keyOver != "" {
				rule := *ruleSet.Challenge
				rule.CookieKey = tt.keyOver
				rs.Challenge = &rule
			}
			if got := VerifySessionIDCookie(reqData, rs); got != tt.wantOK {
				t.Fatalf("VerifySessionIDCookie = %v, want %v", got, tt.wantOK)
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
