package server

import (
	"net/http"
	"net/http/httptest"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/rules"
	"testing"
)

func customRule(t *testing.T, id string, act rules.Action, expr string, skip ...string) *rules.Rule {
	t.Helper()
	prog, err := rules.Compile(expr)
	if err != nil {
		t.Fatalf("Compile(%q): %v", expr, err)
	}
	mask, err := rules.ParseSkipTargets(skip)
	if err != nil {
		t.Fatal(err)
	}
	return &rules.Rule{ID: id, Action: act, SkipMask: mask, Program: prog}
}

func TestCheckMainCustomRules(t *testing.T) {
	floodLimited := func(rs *config.RuleSet, shared *dataType.SharedMemory) {
		rs.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{1: 0}
		shared.HTTPFloodSpeedLimitCounter.Store(dataType.NewCounter(16, 1))
		shared.HTTPFloodSameURILimitCounter.Store(dataType.NewCounter(16, 1))
		shared.HTTPFloodFailureLimitCounter.Store(dataType.NewCounter(16, 1))
	}
	for _, tc := range []struct {
		name       string
		rules      func(t *testing.T) []*rules.Rule
		setup      func(rs *config.RuleSet, req *dataType.UserRequest, shared *dataType.SharedMemory)
		wantStatus int
		wantAction string
	}{
		{
			name: "no match continues",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionBlock, `http.referer contains "spam"`)}
			},
			wantStatus: 200,
		},
		{
			name: "block on referer",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionBlock, `http.referer wildcard "https://evil.example/*"`)}
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "block on method header",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionBlock, `http.request.method eq "POST" and http.request.uri.path eq "/login"`)}
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "captcha",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionCaptcha, `ip.src in {192.0.2.0/24}`)}
			},
			wantStatus: 445, wantAction: "CAPTCHA",
		},
		{
			name: "captcha with clearance continues",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionCaptcha, `ip.src in {192.0.2.0/24}`)}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, _ *dataType.SharedMemory) {
				req.ToriiClearance = string(check.GenClearance(*req, *rs))
			},
			wantStatus: 200,
		},
		{
			name: "external",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionExternal, `http.host eq "example.com"`)}
			},
			wantStatus: 445, wantAction: "EXTERNAL",
		},
		{
			name: "allow bypasses later flood and country",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionAllow, `http.user_agent contains "Monitor"`)}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, shared *dataType.SharedMemory) {
				floodLimited(rs, shared)
				req.FeatureControl |= dataType.FeatureHTTPFlood | dataType.FeatureCountryRule
				rs.CountryRule.UnknownAction = dataType.CountryBlock
			},
			wantStatus: 200,
		},
		{
			name: "skip HTTPFlood",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionSkip, `starts_with(http.request.uri.path, "/login")`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, shared *dataType.SharedMemory) {
				floodLimited(rs, shared)
				req.FeatureControl |= dataType.FeatureHTTPFlood
			},
			wantStatus: 200,
		},
		{
			name: "skip HTTPFlood keeps country",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionSkip, `true`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, shared *dataType.SharedMemory) {
				floodLimited(rs, shared)
				req.FeatureControl |= dataType.FeatureHTTPFlood | dataType.FeatureCountryRule
				rs.CountryRule.UnknownAction = dataType.CountryBlock
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "flood still applies without skip",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionSkip, `http.request.uri.path eq "/other"`, "HTTPFlood")}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, shared *dataType.SharedMemory) {
				floodLimited(rs, shared)
				req.FeatureControl |= dataType.FeatureHTTPFlood
			},
			wantStatus: 445, wantAction: "429",
		},
		{
			name: "skip continues to next rule",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", rules.ActionSkip, `true`, "HTTPFlood"),
					customRule(t, "b", rules.ActionBlock, `true`),
				}
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "skip CustomRules stops rule evaluation",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", rules.ActionSkip, `true`, "CustomRules"),
					customRule(t, "b", rules.ActionBlock, `true`),
				}
			},
			wantStatus: 200,
		},
		{
			name: "log continues to next rule",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", rules.ActionLog, `true`),
					customRule(t, "b", rules.ActionBlock, `true`),
				}
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "continue stops rule evaluation",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{
					customRule(t, "a", rules.ActionContinue, `true`),
					customRule(t, "b", rules.ActionBlock, `true`),
				}
			},
			wantStatus: 200,
		},
		{
			name: "continue does not bypass later checks",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "a", rules.ActionContinue, `true`)}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, _ *dataType.SharedMemory) {
				req.FeatureControl |= dataType.FeatureCountryRule
				rs.CountryRule.UnknownAction = dataType.CountryBlock
			},
			wantStatus: 445, wantAction: "403",
		},
		{
			name: "URL allow list runs before custom rules",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionBlock, `true`)}
			},
			setup: func(rs *config.RuleSet, req *dataType.UserRequest, _ *dataType.SharedMemory) {
				rs.URLAllowRule.List = &dataType.URLRuleList{}
				rs.URLAllowRule.List.Append(&dataType.URLRule{Pattern: "/login?next=/"})
				req.FeatureControl |= dataType.FeatureURLAllow
			},
			wantStatus: 200,
		},
		{
			name: "feature bit off disables rules",
			rules: func(t *testing.T) []*rules.Rule {
				return []*rules.Rule{customRule(t, "r", rules.ActionBlock, `true`)}
			},
			setup: func(_ *config.RuleSet, req *dataType.UserRequest, _ *dataType.SharedMemory) {
				req.FeatureControl &^= dataType.FeatureCustomRules
			},
			wantStatus: 200,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rs := featureControlRuleSet()
			rs.CAPTCHARule = &dataType.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60}
			rs.ExternalMigrationRule = &dataType.ExternalMigrationRule{SecretKey: "1234567890abcdef", SessionTimeout: 60}
			rs.CustomRules = &rules.CustomRules{Enabled: true, Rules: tc.rules(t)}
			headers := http.Header{}
			headers.Set("Referer", "https://evil.example/landing")
			req := dataType.UserRequest{
				RemoteIP:       "192.0.2.10",
				Host:           "example.com",
				Uri:            "/login?next=/",
				Method:         "POST",
				UserAgent:      "Uptime Monitor/1.0",
				Headers:        headers,
				FeatureControl: dataType.FeatureCustomRules,
			}
			shared := &dataType.SharedMemory{}
			shared.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
			if tc.setup != nil {
				tc.setup(rs, &req, shared)
			}
			recorder := httptest.NewRecorder()
			CheckMain(recorder, req, rs, &config.MainConfig{}, shared)
			if recorder.Code != tc.wantStatus || recorder.Header().Get("Torii-Action") != tc.wantAction {
				t.Fatalf("got %d %q, want %d %q", recorder.Code, recorder.Header().Get("Torii-Action"), tc.wantStatus, tc.wantAction)
			}
		})
	}
}

func TestProcessFeatureControlCustomRulesBit(t *testing.T) {
	rs := featureControlRuleSet()
	rs.CustomRules = &rules.CustomRules{Enabled: true}
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}

	if processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), rs)&dataType.FeatureCustomRules == 0 {
		t.Fatal("CustomRules baseline bit is disabled, want enabled")
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Set("X-Features", "___________0")
	if processFeatureControl(cfg, r, rs)&dataType.FeatureCustomRules != 0 {
		t.Fatal("CustomRules bit remains enabled after position 11 override")
	}
}

func TestProcessRequestDataMethod(t *testing.T) {
	cfg := config.DefaultMainConfig()
	r := httptest.NewRequest("GET", "/torii/checker", nil)
	if got := processRequestData(cfg, r).Method; got != "GET" {
		t.Fatalf("Method without header = %q, want GET", got)
	}
	r.Header.Set("Torii-Original-Method", "DELETE")
	r.Header.Set("Referer", "https://a.example/")
	data := processRequestData(cfg, r)
	if data.Method != "DELETE" || data.Headers.Get("Referer") != "https://a.example/" {
		t.Fatalf("got method %q referer %q", data.Method, data.Headers.Get("Referer"))
	}
}
