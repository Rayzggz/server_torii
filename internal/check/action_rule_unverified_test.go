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

func (f fakeBrowserEvidence) HasBrowserEvidence(_, ip string) bool { return f[ip] }

func TestActionRuleCaptchaUnverified(t *testing.T) {
	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	engine.AddURIRule("", "/members/:id", action.ActionChallengeUnverified, time.Minute)
	rules := &config.RuleSet{Challenge: &config.ChallengeRule{
		CookieKey: "1234567890abcdef", ClearanceTTL: 60, SessionTTL: 120, FailureLimit: map[int64]int64{},
	}}
	for _, tc := range []struct {
		name          string
		analyzer      state.BrowserEvidence
		ip            string
		wantChallenge bool
	}{
		{"browser evidence passes", fakeBrowserEvidence{"8.8.8.8": true}, "8.8.8.8", false},
		{"no evidence is challenged", fakeBrowserEvidence{}, "8.8.8.8", true},
		{"no analyzer is challenged", nil, "8.8.8.8", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			shared := &state.Runtime{ActionRuleEngine: engine, BrowserEvidence: tc.analyzer}
			shared.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
			decision := action.NewDecision()
			ActionRule(request.UserRequest{RemoteIP: tc.ip, Uri: "/members/42/"}, rules, decision, shared)
			// The rule only marks the request; the Challenge check at the end of the pipeline answers it.
			if decision.State != action.Continue || decision.RequireChallenge != tc.wantChallenge {
				t.Fatalf("decision = %+v, want a challenge required: %v", decision, tc.wantChallenge)
			}
		})
	}
}
