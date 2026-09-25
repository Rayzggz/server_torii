package server

import (
	"net"
	"net/http/httptest"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"
)

func TestIPCaptchaFeatureControl(t *testing.T) {
	rules := featureControlRuleSet()
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}
	for _, tt := range []struct {
		header        string
		enabled, want bool
	}{
		{"", true, true}, {"_________0", true, false}, {"_________1", false, true}, {"__________", true, true}, {"________", true, true},
	} {
		rules.IPCAPTCHARule = &dataType.IPCAPTCHARule{Enabled: tt.enabled}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Features", tt.header)
		got := processFeatureControl(cfg, req, rules)
		if (got&dataType.FeatureIPCAPTCHA != 0) != tt.want || got&dataType.FeatureCountryRule == 0 {
			t.Fatalf("header %q: bits %b", tt.header, got)
		}
	}
	rules.IPCAPTCHARule = nil
	if got := processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), rules); got&dataType.FeatureIPCAPTCHA != 0 {
		t.Fatal("absent rule enabled")
	}
}

func TestIPCaptchaRequestFlow(t *testing.T) {
	for _, scenario := range []string{"challenge", "clearance", "nonmatch", "disabled", "absent", "ip allow", "url allow", "ip block", "url block", "dynamic block", "country block", "later flood"} {
		t.Run(scenario, func(t *testing.T) {
			rules := featureControlRuleSet()
			trie := &dataType.TrieNode{}
			_, network, _ := net.ParseCIDR("192.0.2.0/24")
			trie.Insert(network)
			rules.IPCAPTCHARule = &dataType.IPCAPTCHARule{Enabled: true, Trie: trie}
			rules.CAPTCHARule = &dataType.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60}
			req := dataType.UserRequest{RemoteIP: "192.0.2.10", Host: "example.com", Uri: "/test", FeatureControl: dataType.FeatureIPCAPTCHA}
			shared := &dataType.SharedMemory{}
			shared.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
			wantStatus, wantAction := 200, ""
			switch scenario {
			case "challenge":
				wantStatus, wantAction = 445, "CAPTCHA"
			case "clearance":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
			case "nonmatch":
				req.RemoteIP = "198.51.100.1"
			case "disabled":
				req.FeatureControl = 0
			case "absent":
				rules.IPCAPTCHARule = nil
			case "ip allow":
				rules.IPAllowRule.Trie = trie
				req.FeatureControl |= dataType.FeatureIPAllow
			case "ip block":
				rules.IPBlockRule.Trie = trie
				req.FeatureControl |= dataType.FeatureIPBlock
				wantStatus, wantAction = 445, "403"
			case "url allow":
				rules.URLAllowRule.List = &dataType.URLRuleList{}
				rules.URLAllowRule.List.Append(&dataType.URLRule{Pattern: "/test"})
				req.FeatureControl |= dataType.FeatureURLAllow
			case "url block":
				rules.URLBlockRule.List = &dataType.URLRuleList{}
				rules.URLBlockRule.List.Append(&dataType.URLRule{Pattern: "/test"})
				req.FeatureControl |= dataType.FeatureURLBlock
				wantStatus, wantAction = 445, "403"
			case "dynamic block":
				engine := action.NewActionRuleEngine(time.Minute)
				t.Cleanup(engine.Stop)
				engine.AddIPRule(req.RemoteIP, action.ActionBlock, time.Minute)
				shared.ActionRuleEngine = engine
				wantStatus, wantAction = 445, "403"
			case "country block":
				rules.CountryRule.UnknownAction = dataType.CountryBlock
				req.FeatureControl |= dataType.FeatureCountryRule
				wantStatus, wantAction = 445, "403"
			case "later flood":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				req.FeatureControl |= dataType.FeatureHTTPFlood
				rules.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{1: 0}
				shared.HTTPFloodSpeedLimitCounter.Store(dataType.NewCounter(16, 1))
				shared.HTTPFloodSameURILimitCounter.Store(dataType.NewCounter(16, 1))
				shared.HTTPFloodFailureLimitCounter.Store(dataType.NewCounter(16, 1))
				wantStatus, wantAction = 445, "429"
			}
			recorder := httptest.NewRecorder()
			CheckMain(recorder, req, rules, &config.MainConfig{}, shared)
			if recorder.Code != wantStatus || recorder.Header().Get("Torii-Action") != wantAction {
				t.Fatalf("got %d %q, want %d %q", recorder.Code, recorder.Header().Get("Torii-Action"), wantStatus, wantAction)
			}
		})
	}
}
