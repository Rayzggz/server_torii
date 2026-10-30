package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"
)

type fakeBrowserEvidence map[string]bool

func (f fakeBrowserEvidence) HasBrowserEvidence(ip string) bool { return f[ip] }

func TestActionRuleCaptchaUnverified(t *testing.T) {
	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	engine.AddURIRule("/members/:id", action.ActionCaptchaUnverified, time.Minute)
	rules := &config.RuleSet{CAPTCHARule: &dataType.CaptchaRule{
		SecretKey: "1234567890abcdef", CaptchaValidateTime: 60, CaptchaChallengeSessionTimeout: 120, CaptchaFailureLimit: map[int64]int64{},
	}}
	for _, tc := range []struct {
		name     string
		analyzer any
		ip       string
		wantDone bool
	}{
		{"browser evidence passes", fakeBrowserEvidence{"8.8.8.8": true}, "8.8.8.8", false},
		{"no evidence is challenged", fakeBrowserEvidence{}, "8.8.8.8", true},
		{"no analyzer is challenged", nil, "8.8.8.8", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := &dataType.SharedMemory{ActionRuleEngine: engine, AdaptiveTrafficAnalyzer: tc.analyzer}
			shared.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
			decision := action.NewDecision()
			ActionRule(dataType.UserRequest{RemoteIP: tc.ip, Uri: "/members/42/"}, rules, decision, shared)
			if done := decision.State == action.Done; done != tc.wantDone {
				t.Fatalf("done = %v (code %s), want %v", done, decision.HTTPCode, tc.wantDone)
			}
			if tc.wantDone && string(decision.HTTPCode) != "CAPTCHA" {
				t.Fatalf("code = %s, want CAPTCHA", decision.HTTPCode)
			}
		})
	}
}
