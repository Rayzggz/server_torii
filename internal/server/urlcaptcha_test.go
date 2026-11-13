package server

import (
	"net"
	"net/http/httptest"
	"regexp"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/iptrie"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/urllist"
	"testing"
)

func TestURLCaptchaFeatureControl(t *testing.T) {
	rules := featureControlRuleSet()
	rules.IPCAPTCHARule = &config.IPListRule{Enabled: true}
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}
	for _, tt := range []struct {
		header        string
		enabled, want bool
	}{
		{"", true, true}, {"__________0", true, false}, {"__________1", false, true}, {"___________", true, true}, {"__________", true, true},
	} {
		rules.URLCAPTCHARule = &config.URLListRule{Enabled: tt.enabled}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Features", tt.header)
		got := processFeatureControl(cfg, req, rules)
		want := uint16(request.FeatureCountryRule | request.FeatureIPCAPTCHA)
		if tt.want {
			want |= request.FeatureURLCAPTCHA
		}
		if got != want {
			t.Fatalf("header %q: got %b, want %b", tt.header, got, want)
		}
	}
	rules.URLCAPTCHARule = nil
	if got := processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), rules); got&request.FeatureURLCAPTCHA != 0 {
		t.Fatal("absent rule enabled")
	}
}

func TestURLCaptchaRequestFlow(t *testing.T) {
	for _, scenario := range []string{"challenge", "regex", "clearance", "nonmatch", "query", "disabled", "absent", "empty", "ip allow", "url allow", "ip block", "url block", "country precedence", "clearance later block", "failure limit"} {
		t.Run(scenario, func(t *testing.T) {
			rules := featureControlRuleSet()
			list := &urllist.URLRuleList{}
			list.Append(&urllist.URLRule{Pattern: "/login"})
			list.Append(&urllist.URLRule{IsRegex: true, Regex: regexp.MustCompile("^/admin(/|$)")})
			rules.URLCAPTCHARule = &config.URLListRule{Enabled: true, List: list}
			rules.CAPTCHARule = &config.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60}
			req := request.UserRequest{RemoteIP: "192.0.2.10", Host: "example.com", Uri: "/login", FeatureControl: request.FeatureURLCAPTCHA}
			shared := &state.Runtime{}
			shared.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
			trie := &iptrie.TrieNode{}
			_, network, _ := net.ParseCIDR("192.0.2.0/24")
			trie.Insert(network)
			wantStatus, wantAction := 200, ""
			switch scenario {
			case "challenge":
				wantStatus, wantAction = 445, "CAPTCHA"
			case "regex":
				req.Uri = "/admin/users?a=1"
				wantStatus, wantAction = 445, "CAPTCHA"
			case "clearance":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
			case "nonmatch":
				req.Uri = "/other"
			case "query":
				req.Uri = "/login?next=/"
			case "disabled":
				req.FeatureControl = 0
			case "absent":
				rules.URLCAPTCHARule = nil
			case "empty":
				rules.URLCAPTCHARule.List = &urllist.URLRuleList{}
			case "ip allow":
				rules.IPAllowRule.Trie = trie
				req.FeatureControl |= request.FeatureIPAllow
			case "url allow":
				rules.URLAllowRule.List = list
				req.FeatureControl |= request.FeatureURLAllow
			case "ip block":
				rules.IPBlockRule.Trie = trie
				req.FeatureControl |= request.FeatureIPBlock
				wantStatus, wantAction = 445, "403"
			case "url block":
				rules.URLBlockRule.List = list
				req.FeatureControl |= request.FeatureURLBlock
				wantStatus, wantAction = 445, "403"
			case "country precedence":
				rules.CountryRule.UnknownAction = config.CountryBlock
				req.FeatureControl |= request.FeatureCountryRule
				wantStatus, wantAction = 445, "CAPTCHA"
			case "clearance later block":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				rules.CountryRule.UnknownAction = config.CountryBlock
				req.FeatureControl |= request.FeatureCountryRule
				wantStatus, wantAction = 445, "403"
			case "failure limit":
				rules.CAPTCHARule.CaptchaFailureLimit = map[int64]int64{1: 1}
				rules.CAPTCHARule.FailureBlockDuration = 60
				shared.CaptchaFailureLimitCounter.Load().Add(req.RemoteIP, 2)
				wantStatus, wantAction = 445, "403"
			}
			recorder := httptest.NewRecorder()
			NewServer(&config.MainConfig{}, nil, shared, nil).CheckMain(recorder, req, rules)
			if recorder.Code != wantStatus || recorder.Header().Get("Torii-Action") != wantAction {
				t.Fatalf("got %d %q, want %d %q", recorder.Code, recorder.Header().Get("Torii-Action"), wantStatus, wantAction)
			}
		})
	}
}
