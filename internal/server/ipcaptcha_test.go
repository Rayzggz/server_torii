package server

import (
	"net"
	"net/http/httptest"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/iptrie"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/urllist"
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
		rules.IPCAPTCHARule = &config.IPListRule{Enabled: tt.enabled}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Features", tt.header)
		got := processFeatureControl(cfg, req, rules)
		if (got&request.FeatureIPCAPTCHA != 0) != tt.want || got&request.FeatureCountryRule == 0 {
			t.Fatalf("header %q: bits %b", tt.header, got)
		}
	}
	rules.IPCAPTCHARule = nil
	if got := processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), rules); got&request.FeatureIPCAPTCHA != 0 {
		t.Fatal("absent rule enabled")
	}
}

func TestIPCaptchaRequestFlow(t *testing.T) {
	for _, scenario := range []string{"challenge", "clearance", "nonmatch", "disabled", "absent", "ip allow", "url allow", "ip block", "url block", "dynamic block", "clearance dynamic block", "country block", "clearance country block", "later flood"} {
		t.Run(scenario, func(t *testing.T) {
			rules := featureControlRuleSet()
			trie := &iptrie.TrieNode{}
			_, network, _ := net.ParseCIDR("192.0.2.0/24")
			trie.Insert(network)
			rules.IPCAPTCHARule = &config.IPListRule{Enabled: true, Trie: trie}
			rules.CAPTCHARule = &config.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60}
			req := request.UserRequest{RemoteIP: "192.0.2.10", Host: "example.com", Uri: "/test", FeatureControl: request.FeatureIPCAPTCHA}
			shared := &state.Runtime{}
			shared.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
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
				req.FeatureControl |= request.FeatureIPAllow
			case "ip block":
				rules.IPBlockRule.Trie = trie
				req.FeatureControl |= request.FeatureIPBlock
				wantStatus, wantAction = 445, "403"
			case "url allow":
				rules.URLAllowRule.List = &urllist.URLRuleList{}
				rules.URLAllowRule.List.Append(&urllist.URLRule{Pattern: "/test"})
				req.FeatureControl |= request.FeatureURLAllow
			case "url block":
				rules.URLBlockRule.List = &urllist.URLRuleList{}
				rules.URLBlockRule.List.Append(&urllist.URLRule{Pattern: "/test"})
				req.FeatureControl |= request.FeatureURLBlock
				wantStatus, wantAction = 445, "403"
			// IPCAPTCHA precedes country and dynamic action checks; valid clearance lets them run.
			case "dynamic block", "clearance dynamic block":
				engine := action.NewActionRuleEngine(time.Minute)
				t.Cleanup(engine.Stop)
				engine.AddIPRule(req.RemoteIP, action.ActionBlock, time.Minute)
				shared.ActionRuleEngine = engine
				wantStatus, wantAction = 445, "CAPTCHA"
				if scenario == "clearance dynamic block" {
					req.ToriiClearance = string(check.GenClearance(req, *rules))
					wantAction = "403"
				}
			case "country block", "clearance country block":
				rules.CountryRule.UnknownAction = config.CountryBlock
				req.FeatureControl |= request.FeatureCountryRule
				wantStatus, wantAction = 445, "CAPTCHA"
				if scenario == "clearance country block" {
					req.ToriiClearance = string(check.GenClearance(req, *rules))
					wantAction = "403"
				}
			case "later flood":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				req.FeatureControl |= request.FeatureHTTPFlood
				rules.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{1: 0}
				shared.HTTPFloodSpeedLimitCounter.Store(ratelimit.NewCounter(16, 1))
				shared.HTTPFloodSameURILimitCounter.Store(ratelimit.NewCounter(16, 1))
				shared.HTTPFloodFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
				wantStatus, wantAction = 445, "429"
			}
			recorder := httptest.NewRecorder()
			NewServer(&config.MainConfig{}, nil, shared, nil).CheckMain(recorder, req, rules)
			if recorder.Code != wantStatus || recorder.Header().Get("Torii-Action") != wantAction {
				t.Fatalf("got %d %q, want %d %q", recorder.Code, recorder.Header().Get("Torii-Action"), wantStatus, wantAction)
			}
		})
	}
}
