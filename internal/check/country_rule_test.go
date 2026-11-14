package check

import (
	"errors"
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
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
		CountryRule: &config.CountryRule{DefaultAction: config.CountryContinue, UnknownAction: config.CountryContinue, Countries: map[string]config.CountryAction{}},
		CAPTCHARule: &config.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60, CaptchaChallengeSessionTimeout: 120, CaptchaFailureLimit: map[int64]int64{}},
	}
}

func TestCountryRulePolicies(t *testing.T) {
	for _, policy := range []config.CountryAction{config.CountryContinue, config.CountryBlock, config.CountryCaptcha} {
		for _, source := range []string{"override", "default", "invalid", "private", "loopback", "link_local", "empty", "error", "missing", "missing_database"} {
			t.Run(string(policy)+"/"+source, func(t *testing.T) {
				rules := countryTestRuleSet()
				resolver := &fakeCountryResolver{country: "us"}
				shared := &state.Runtime{CountryResolver: resolver}
				shared.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
				req := request.UserRequest{RemoteIP: "8.8.8.8", FeatureControl: request.FeatureCountryRule}
				rules.CountryRule.UnknownAction = policy
				switch source {
				case "override":
					rules.CountryRule.DefaultAction = config.CountryBlock
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
				decision := action.NewDecision()
				CountryRule(req, rules, decision, shared)
				want := map[config.CountryAction]string{config.CountryContinue: "pass", config.CountryBlock: "block", config.CountryCaptcha: "captcha"}[policy]
				if decision.Verdict.String() != want || (decision.State == action.Done) != (policy != config.CountryContinue) {
					t.Fatalf("decision = %#v, want %s", decision, want)
				}
				if (source == "invalid" || source == "private" || source == "loopback" || source == "missing") && resolver.calls != 0 {
					t.Fatal("unexpected lookup")
				}
			})
		}
	}
}

func TestCountryRuleSkipsLookup(t *testing.T) {
	for _, absent := range []bool{false, true} {
		rules := countryTestRuleSet()
		req := request.UserRequest{RemoteIP: "8.8.8.8"}
		if absent {
			rules.CountryRule = nil
			req.FeatureControl = request.FeatureCountryRule
		}
		resolver := &fakeCountryResolver{country: "US"}
		decision := action.NewDecision()
		CountryRule(req, rules, decision, &state.Runtime{CountryResolver: resolver})
		if resolver.calls != 0 || decision.State != action.Continue {
			t.Fatalf("unexpected lookup or decision: %#v", decision)
		}
	}
}

func TestCountryRuleCaptchaClearanceContinues(t *testing.T) {
	rules := countryTestRuleSet()
	rules.CountryRule.DefaultAction = config.CountryCaptcha
	req := request.UserRequest{RemoteIP: "8.8.8.8", Host: "example.com", FeatureControl: request.FeatureCountryRule}
	req.ToriiClearance = string(GenClearance(req, *rules))
	shared := &state.Runtime{CountryResolver: &fakeCountryResolver{country: "US"}}
	shared.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
	decision := action.NewDecision()
	CountryRule(req, rules, decision, shared)
	if decision.State != action.Continue {
		t.Fatalf("valid clearance challenged: %#v", decision)
	}
}
