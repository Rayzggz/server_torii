package server

import (
	"net"
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
	for _, tt := range []struct {
		header        string
		enabled, want bool
	}{
		{"", true, true}, {"-url_captcha", true, false}, {"+url_captcha", false, true}, {"-captcha", true, true}, {"+url_captcha", true, true},
	} {
		rules.URLCAPTCHARule = &config.URLListRule{Enabled: tt.enabled}
		got := featureBits(rules, tt.header)
		want := uint16(request.FeatureCountryRule | request.FeatureIPCAPTCHA)
		if tt.want {
			want |= request.FeatureURLCAPTCHA
		}
		if got != want {
			t.Fatalf("header %q: got %b, want %b", tt.header, got, want)
		}
	}
	rules.URLCAPTCHARule = nil
	if got := featureBits(rules, ""); got&request.FeatureURLCAPTCHA != 0 {
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
			want := "pass"
			switch scenario {
			case "challenge":
				want = "captcha"
			case "regex":
				req.Uri = "/admin/users?a=1"
				want = "captcha"
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
				want = "block"
			case "url block":
				rules.URLBlockRule.List = list
				req.FeatureControl |= request.FeatureURLBlock
				want = "block"
			case "country precedence":
				rules.CountryRule.UnknownAction = config.CountryBlock
				req.FeatureControl |= request.FeatureCountryRule
				want = "captcha"
			case "clearance later block":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				rules.CountryRule.UnknownAction = config.CountryBlock
				req.FeatureControl |= request.FeatureCountryRule
				want = "block"
			case "failure limit":
				rules.CAPTCHARule.CaptchaFailureLimit = map[int64]int64{1: 1}
				rules.CAPTCHARule.FailureBlockDuration = 60
				shared.CaptchaFailureLimitCounter.Load().Add(req.RemoteIP, 2)
				want = "block"
			}
			if got := decide(shared, req, rules); got != want {
				t.Fatalf("decision = %q, want %q", got, want)
			}
		})
	}
}
