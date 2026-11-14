package check

import (
	"errors"
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/geoip"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

type fakeCountryResolver struct {
	country string
	err     error
	calls   int
}

func (r *fakeCountryResolver) Country(netip.Addr) (string, error) { r.calls++; return r.country, r.err }

func countryTestRuleSet() *config.RuleSet {
	return &config.RuleSet{
		CountryRule: &config.CountryRule{DefaultAction: action.ActionContinue, UnknownAction: action.ActionContinue, Countries: map[string]action.Action{}},
		Challenge:   &config.ChallengeRule{SecretKey: "1234567890abcdef", ClearanceTTL: 60, SessionTTL: 120, FailureLimit: map[int64]int64{}},
	}
}

func TestCountryRulePolicies(t *testing.T) {
	for _, policy := range []action.Action{action.ActionContinue, action.ActionBlock, action.ActionChallenge} {
		for _, source := range []string{"override", "default", "invalid", "private", "loopback", "link_local", "empty", "error", "missing", "missing_database"} {
			t.Run(string(policy)+"/"+source, func(t *testing.T) {
				rules := countryTestRuleSet()
				resolver := &fakeCountryResolver{country: "us"}
				shared := &state.Runtime{CountryResolver: resolver}
				shared.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
				req := request.UserRequest{RemoteIP: "8.8.8.8", FeatureControl: feature.CountryRule.ControlMask()}
				rules.CountryRule.UnknownAction = policy
				switch source {
				case "override":
					rules.CountryRule.DefaultAction = action.ActionBlock
					rules.CountryRule.Countries["US"] = policy
				case "default":
					rules.CountryRule.DefaultAction = policy
				case "invalid":
					req.RemoteIP = "bad"
				case "private":
					req.RemoteIP = "192.168.1.1"
				case "loopback":
					req.RemoteIP = "::1"
				case "link_local":
					req.RemoteIP = "fe80::1"
				case "missing_database":
					shared.CountryResolver = &geoip.CountryDatabase{}
				case "empty":
					resolver.country = ""
				case "error":
					resolver.err = errors.New("lookup failed")
				case "missing":
					shared.CountryResolver = nil
				}
				req.ResolveCountry(shared.CountryResolver)
				decision := action.NewDecision()
				CountryRule(req, rules, decision, shared)
				// A block ends the pipeline; a challenge only marks the request for the Challenge check.
				wantBlock, wantChallenge := policy == action.ActionBlock, policy == action.ActionChallenge
				if (decision.State == action.Done) != wantBlock || (decision.Verdict == action.VerdictBlock) != wantBlock ||
					decision.RequireChallenge != wantChallenge {
					t.Fatalf("decision = %#v, want policy %s", decision, policy)
				}
				if (source == "invalid" || source == "private" || source == "loopback" || source == "missing") && resolver.calls != 0 {
					t.Fatal("unexpected lookup")
				}
			})
		}
	}
}

func TestCountryRuleWithoutRuleContinues(t *testing.T) {
	rules := countryTestRuleSet()
	rules.CountryRule = nil
	req := request.UserRequest{RemoteIP: "8.8.8.8"}
	req.ResolveCountry(&fakeCountryResolver{country: "US"})
	decision := action.NewDecision()
	CountryRule(req, rules, decision, &state.Runtime{})
	if decision.State != action.Continue {
		t.Fatalf("unexpected decision: %#v", decision)
	}
}

func TestCountryRuleCaptchaClearanceContinues(t *testing.T) {
	rules := countryTestRuleSet()
	rules.CountryRule.DefaultAction = action.ActionChallenge
	req := request.UserRequest{RemoteIP: "8.8.8.8", Host: "example.com", FeatureControl: feature.CountryRule.ControlMask()}
	req.ToriiClearance = string(GenClearance(req, *rules))
	req.ResolveCountry(&fakeCountryResolver{country: "US"})
	shared := &state.Runtime{}
	shared.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
	decision := action.NewDecision()
	CountryRule(req, rules, decision, shared)
	if decision.State != action.Continue {
		t.Fatalf("valid clearance challenged: %#v", decision)
	}
}
