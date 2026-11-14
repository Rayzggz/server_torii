package server

import (
	"net/http"
	"net/http/httptest"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/rules"
	"server_torii/internal/state"
	"testing"
)

func customRule(t *testing.T, id string, act action.Action, expr string, skip ...string) *rules.Rule {
	t.Helper()
	prog, err := rules.Compile(expr, nil)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	mask, err := feature.ParseSkipTargets(skip)
	if err != nil {
		t.Fatal(err)
	}
	return &rules.Rule{ID: id, Action: act, SkipMask: mask, Program: prog}
}

func TestCheckMainCustomRules(t *testing.T) {
	floodLimited := func(rs *config.RuleSet, shared *state.Runtime) {
		rs.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{1: 0}
		shared.HTTPFloodSpeedLimitCounter.Store(ratelimit.NewCounter(16, 1))
		shared.HTTPFloodSameURILimitCounter.Store(ratelimit.NewCounter(16, 1))
		shared.HTTPFloodFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
	}
	for _, tc := range []struct {
		name  string
		rules func(t *testing.T) []*rules.Rule
		setup func(rs *config.RuleSet, req *request.UserRequest, shared *state.Runtime)
		want  string
	}{
		{
			name: "no match continues",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionBlock, `http.referer contains "spam"`)}
			},
			want: "pass",
		},
		{
			name: "block on referer",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionBlock, `http.referer wildcard "https://evil.example/*"`)}
			},
			want: "block",
		},
		{
			name: "block on method header",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionBlock, `http.request.method eq "POST" and http.request.uri.path eq "/login"`)}
			},
			want: "block",
		},
		{
			name: "captcha",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionChallenge, `ip.src in {192.0.2.0/24}`)}
			},
			want: "challenge",
		},
		{
			name: "captcha with clearance continues",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionChallenge, `ip.src in {192.0.2.0/24}`)}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, _ *state.Runtime) {
				req.ToriiClearance = string(check.GenClearance(*req, *rs))
			},
			want: "pass",
		},
		{
			name: "external",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionChallenge, `http.host eq "example.com"`)}
			},
			want: "challenge",
		},
		{
			name: "allow bypasses later flood and country",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionAllow, `http.user_agent contains "Monitor"`)}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, shared *state.Runtime) {
				floodLimited(rs, shared)
				req.FeatureControl |= feature.HTTPFlood.ControlMask() | feature.CountryRule.ControlMask()
				rs.CountryRule.UnknownAction = action.ActionBlock
			},
			want: "pass",
		},
		{
			name: "skip HTTPFlood",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionSkip, `starts_with(http.request.uri.path, "/login")`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, shared *state.Runtime) {
				floodLimited(rs, shared)
				req.FeatureControl |= feature.HTTPFlood.ControlMask()
			},
			want: "pass",
		},
		{
			name: "skip HTTPFlood keeps country",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionSkip, `true`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, shared *state.Runtime) {
				floodLimited(rs, shared)
				req.FeatureControl |= feature.HTTPFlood.ControlMask() | feature.CountryRule.ControlMask()
				rs.CountryRule.UnknownAction = action.ActionBlock
			},
			want: "block",
		},
		{
			name: "flood still applies without skip",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionSkip, `http.request.uri.path eq "/other"`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, shared *state.Runtime) {
				floodLimited(rs, shared)
				req.FeatureControl |= feature.HTTPFlood.ControlMask()
			},
			want: "rate_limit",
		},
		{
			name: "skip continues to next rule",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", action.ActionSkip, `true`, "HTTPFlood"),
					customRule(t, "b", action.ActionBlock, `true`),
				}
			},
			want: "block",
		},
		{
			name: "skip CustomRules stops rule evaluation",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", action.ActionSkip, `true`, "CustomRules"),
					customRule(t, "b", action.ActionBlock, `true`),
				}
			},
			want: "pass",
		},
		{
			name: "log continues to next rule",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", action.ActionLog, `true`),
					customRule(t, "b", action.ActionBlock, `true`),
				}
			},
			want: "block",
		},
		{
			name: "continue stops rule evaluation",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", action.ActionContinue, `true`),
					customRule(t, "b", action.ActionBlock, `true`),
				}
			},
			want: "pass",
		},
		{
			name: "continue does not bypass later checks",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "a", action.ActionContinue, `true`)}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, _ *state.Runtime) {
				req.FeatureControl |= feature.CountryRule.ControlMask()
				rs.CountryRule.UnknownAction = action.ActionBlock
			},
			want: "block",
		},
		{
			name: "URL allow list runs before custom rules",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionBlock, `true`)}
			},
			setup: func(rs *config.RuleSet, req *request.UserRequest, _ *state.Runtime) {
				rs.Lists = config.NewListSet(config.MustNewList("url_allow", config.ListURL, action.ActionAllow, "/login?next=/"))
			},
			want: "pass",
		},
		{
			name: "feature bit off disables rules",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", action.ActionBlock, `true`)}
			},
			setup: func(_ *config.RuleSet, req *request.UserRequest, _ *state.Runtime) {
				req.FeatureControl &^= feature.CustomRules.ControlMask()
			},
			want: "pass",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := featureControlRuleSet()
			rs.Challenge = &config.ChallengeRule{Keys: []string{"1234567890abcdef"}, ClearanceTTL: 60}
			rs.Challenge = &config.ChallengeRule{Mode: config.ChallengeExternal, Keys: []string{"1234567890abcdef"}, ClearanceTTL: 60}
			rs.CustomRules = &rules.CustomRules{Enabled: true, Rules: tc.rules(t)}
			headers := http.Header{}
			headers.Set("Referer", "https://evil.example/landing")
			req := request.UserRequest{
				RemoteIP:       "192.0.2.10",
				Host:           "example.com",
				Uri:            "/login?next=/",
				Method:         "POST",
				UserAgent:      "Uptime Monitor/1.0",
				Headers:        headers,
				FeatureControl: feature.CustomRules.ControlMask(),
			}
			shared := &state.Runtime{}
			shared.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
			if tc.setup != nil {
				tc.setup(rs, &req, shared)
			}
			if got := decide(shared, req, rs); got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFeatureOverridesCustomRulesBit(t *testing.T) {
	rs := featureControlRuleSet()
	rs.CustomRules = &rules.CustomRules{Enabled: true}

	if featureBits(rs, "")&feature.CustomRules.ControlMask() == 0 {
		t.Fatal("CustomRules baseline bit is disabled, want enabled")
	}
	if featureBits(rs, "-custom_rules")&feature.CustomRules.ControlMask() != 0 {
		t.Fatal("CustomRules bit remains enabled after the override")
	}
}

// Nginx subrequests are always GET, so the connector reports the original method in a header.
func TestV1RequestMethod(t *testing.T) {
	s := newV1Server(t)
	r := httptest.NewRequest("GET", v1CheckPath, nil)
	r.Header.Set(headerClientIP, "203.0.113.5")
	r.Header.Set(headerURI, "/")
	if data, _, _, ok := s.v1Request(httptest.NewRecorder(), r); !ok || data.Method != "GET" {
		t.Fatalf("Method without header = %q, want GET", data.Method)
	}
	r.Header.Set(headerMethod, "DELETE")
	r.Header.Set("Referer", "https://a.example/")
	data, _, _, ok := s.v1Request(httptest.NewRecorder(), r)
	if !ok || data.Method != "DELETE" || data.Headers.Get("Referer") != "https://a.example/" {
		t.Fatalf("got method %q referer %q", data.Method, data.Headers.Get("Referer"))
	}
}
