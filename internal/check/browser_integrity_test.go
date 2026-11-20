package check

import (
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/integrity"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

// chromeWithoutClientHints is a request that names Chrome and, over HTTPS, sends everything
// Chrome sends but Sec-CH-UA.
func chromeWithoutClientHints() request.UserRequest {
	h := http.Header{}
	h.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
	h.Set("Accept", "text/html,*/*;q=0.8")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set("Torii-Scheme", "https")
	return request.UserRequest{RemoteIP: "8.8.8.8", UserAgent: h.Get("User-Agent"), Headers: h}
}

func integrityRuleSet(act action.Action, rules ...string) *config.RuleSet {
	on := make(map[string]bool)
	for _, name := range rules {
		on[name] = true
	}
	return &config.RuleSet{
		BrowserIntegrity: &config.BrowserIntegrityRule{Enabled: true, Action: act, Rules: on},
		Challenge:        &config.ChallengeRule{},
	}
}

func TestBrowserIntegrity(t *testing.T) {
	run := func(ruleSet *config.RuleSet) *action.Decision {
		decision := action.NewDecision()
		BrowserIntegrity(chromeWithoutClientHints(), ruleSet, decision, &state.Runtime{})
		return decision
	}

	// The rule that found the request is the detail of the decision.
	decision := run(integrityRuleSet(action.ActionBlock, integrity.Rules...))
	if decision.Verdict != action.VerdictBlock || decision.State != action.Done ||
		decision.Detail != integrity.NoClientHints || decision.Note != "chromium 135 without Sec-CH-UA" {
		t.Fatalf("block: decision = %+v", decision)
	}

	// A challenge is left to the Challenge check, which a client with a clearance passes.
	decision = run(integrityRuleSet(action.ActionChallenge, integrity.Rules...))
	if !decision.RequireChallenge || decision.State != action.Continue || decision.Detail != integrity.NoClientHints {
		t.Fatalf("challenge: decision = %+v", decision)
	}

	// Observe decides nothing.
	if decision = run(integrityRuleSet(action.ActionObserve, integrity.Rules...)); *decision != *action.NewDecision() {
		t.Fatalf("observe: decision = %+v", decision)
	}

	// Only the rules the site lists are applied.
	if decision = run(integrityRuleSet(action.ActionBlock, integrity.NoFetchMetadata, integrity.TLS)); *decision != *action.NewDecision() {
		t.Fatalf("rule not listed: decision = %+v", decision)
	}
	if decision = run(integrityRuleSet(action.ActionBlock)); *decision != *action.NewDecision() {
		t.Fatalf("no rules: decision = %+v", decision)
	}
}
