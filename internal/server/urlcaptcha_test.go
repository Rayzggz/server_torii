package server

import (
	"net"
	"net/http/httptest"
	"regexp"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
)

func TestURLCaptchaFeatureControl(t *testing.T) {
	rules := featureControlRuleSet()
	rules.IPCAPTCHARule = &dataType.IPCAPTCHARule{Enabled: true}
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}
	for _, tt := range []struct {
		header        string
		enabled, want bool
	}{
		{"", true, true}, {"__________0", true, false}, {"__________1", false, true}, {"___________", true, true}, {"__________", true, true},
	} {
		rules.URLCAPTCHARule = &dataType.URLCAPTCHARule{Enabled: tt.enabled}
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Features", tt.header)
		got := processFeatureControl(cfg, req, rules)
		want := uint16(dataType.FeatureCountryRule | dataType.FeatureIPCAPTCHA)
		if tt.want {
			want |= dataType.FeatureURLCAPTCHA
		}
		if got != want {
			t.Fatalf("header %q: got %b, want %b", tt.header, got, want)
		}
	}
	rules.URLCAPTCHARule = nil
	if got := processFeatureControl(cfg, httptest.NewRequest("GET", "/", nil), rules); got&dataType.FeatureURLCAPTCHA != 0 {
		t.Fatal("absent rule enabled")
	}
}

func TestURLCaptchaRequestFlow(t *testing.T) {
	for _, scenario := range []string{"challenge", "regex", "clearance", "nonmatch", "query", "disabled", "absent", "empty", "ip allow", "url allow", "ip block", "url block", "country precedence", "clearance later block", "failure limit"} {
		t.Run(scenario, func(t *testing.T) {
			rules := featureControlRuleSet()
			list := &dataType.URLRuleList{}
			list.Append(&dataType.URLRule{Pattern: "/login"})
			list.Append(&dataType.URLRule{IsRegex: true, Regex: regexp.MustCompile("^/admin(/|$)")})
			rules.URLCAPTCHARule = &dataType.URLCAPTCHARule{Enabled: true, List: list}
			rules.CAPTCHARule = &dataType.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60}
			req := dataType.UserRequest{RemoteIP: "192.0.2.10", Host: "example.com", Uri: "/login", FeatureControl: dataType.FeatureURLCAPTCHA}
			shared := &dataType.SharedMemory{}
			shared.CaptchaFailureLimitCounter.Store(dataType.NewCounter(16, 1))
			trie := &dataType.TrieNode{}
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
				rules.URLCAPTCHARule.List = &dataType.URLRuleList{}
			case "ip allow":
				rules.IPAllowRule.Trie = trie
				req.FeatureControl |= dataType.FeatureIPAllow
			case "url allow":
				rules.URLAllowRule.List = list
				req.FeatureControl |= dataType.FeatureURLAllow
			case "ip block":
				rules.IPBlockRule.Trie = trie
				req.FeatureControl |= dataType.FeatureIPBlock
				wantStatus, wantAction = 445, "403"
			case "url block":
				rules.URLBlockRule.List = list
				req.FeatureControl |= dataType.FeatureURLBlock
				wantStatus, wantAction = 445, "403"
			case "country precedence":
				rules.CountryRule.UnknownAction = dataType.CountryBlock
				req.FeatureControl |= dataType.FeatureCountryRule
				wantStatus, wantAction = 445, "CAPTCHA"
			case "clearance later block":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				rules.CountryRule.UnknownAction = dataType.CountryBlock
				req.FeatureControl |= dataType.FeatureCountryRule
				wantStatus, wantAction = 445, "403"
			case "failure limit":
				rules.CAPTCHARule.CaptchaFailureLimit = map[int64]int64{1: 1}
				rules.CAPTCHARule.FailureBlockDuration = 60
				shared.CaptchaFailureLimitCounter.Load().Add(req.RemoteIP, 2)
				wantStatus, wantAction = 445, "403"
			}
			recorder := httptest.NewRecorder()
			CheckMain(recorder, req, rules, &config.MainConfig{}, shared)
			if recorder.Code != wantStatus || recorder.Header().Get("Torii-Action") != wantAction {
				t.Fatalf("got %d %q, want %d %q", recorder.Code, recorder.Header().Get("Torii-Action"), wantStatus, wantAction)
			}
		})
	}
}
