package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
	"time"
)

type fakeBrowserEvidence map[string]bool

func (f fakeBrowserEvidence) HasBrowserEvidence(ip string) bool { return f[ip] }

func TestActionRuleCaptchaUnverified(t *testing.T) {
	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	engine.AddURIRule("/members/:id", action.ActionCaptchaUnverified, time.Minute)
	rules := &config.RuleSet{CAPTCHARule: &config.CaptchaRule{
		SecretKey: "1234567890abcdef", CaptchaValidateTime: 60, CaptchaChallengeSessionTimeout: 120, CaptchaFailureLimit: map[int64]int64{},
	}}
	for _, tc := range []struct {
		name     string
		analyzer state.BrowserEvidence
		ip       string
		wantDone bool
	}{
		{"browser evidence passes", fakeBrowserEvidence{"8.8.8.8": true}, "8.8.8.8", false},
		{"no evidence is challenged", fakeBrowserEvidence{}, "8.8.8.8", true},
		{"no analyzer is challenged", nil, "8.8.8.8", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := &state.Runtime{ActionRuleEngine: engine, BrowserEvidence: tc.analyzer}
			shared.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
			decision := action.NewDecision()
			ActionRule(request.UserRequest{RemoteIP: tc.ip, Uri: "/members/42/"}, rules, decision, shared)
			if done := decision.State == action.Done; done != tc.wantDone {
				t.Fatalf("done = %v (code %s), want %v", done, decision.Verdict, tc.wantDone)
			}
			if tc.wantDone && decision.Verdict != action.VerdictCaptcha {
				t.Fatalf("code = %s, want CAPTCHA", decision.Verdict)
			}
		})
	}
}
