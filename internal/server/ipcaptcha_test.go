package server

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/feature"
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
	for _, tt := range []struct {
		header        string
		enabled, want bool
	}{
		{"", true, true}, {"-ip_captcha", true, false}, {"+ip_captcha", false, true}, {"-url_captcha", true, true}, {"+ip_captcha", true, true},
	} {
		rules.IPCAPTCHARule = &config.IPListRule{Enabled: tt.enabled}
		got := featureBits(rules, tt.header)
		if (got&feature.IPCAPTCHA.ControlMask() != 0) != tt.want || got&feature.CountryRule.ControlMask() == 0 {
			t.Fatalf("header %q: bits %b", tt.header, got)
		}
	}
	rules.IPCAPTCHARule = nil
	if got := featureBits(rules, ""); got&feature.IPCAPTCHA.ControlMask() != 0 {
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
			rules.Challenge = &config.ChallengeRule{SecretKey: "1234567890abcdef", ClearanceTTL: 60}
			req := request.UserRequest{RemoteIP: "192.0.2.10", Host: "example.com", Uri: "/test", FeatureControl: feature.IPCAPTCHA.ControlMask()}
			shared := &state.Runtime{}
			shared.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
			want := "pass"
			switch scenario {
			case "challenge":
				want = "challenge"
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
				req.FeatureControl |= feature.IPAllow.ControlMask()
			case "ip block":
				rules.IPBlockRule.Trie = trie
				req.FeatureControl |= feature.IPBlock.ControlMask()
				want = "block"
			case "url allow":
				rules.URLAllowRule.List = &urllist.URLRuleList{}
				rules.URLAllowRule.List.Append(&urllist.URLRule{Pattern: "/test"})
				req.FeatureControl |= feature.URLAllow.ControlMask()
			case "url block":
				rules.URLBlockRule.List = &urllist.URLRuleList{}
				rules.URLBlockRule.List.Append(&urllist.URLRule{Pattern: "/test"})
				req.FeatureControl |= feature.URLBlock.ControlMask()
				want = "block"
			// IPCAPTCHA only marks the request: a later check that blocks wins over the challenge.
			case "dynamic block", "clearance dynamic block":
				engine := action.NewActionRuleEngine(time.Minute)
				t.Cleanup(engine.Stop)
				engine.AddIPRule("", req.RemoteIP, action.ActionBlock, time.Minute)
				shared.ActionRuleEngine = engine
				want = "block"
				if scenario == "clearance dynamic block" {
					req.ToriiClearance = string(check.GenClearance(req, *rules))
				}
			case "country block", "clearance country block":
				rules.CountryRule.UnknownAction = action.ActionBlock
				req.FeatureControl |= feature.CountryRule.ControlMask()
				want = "block"
				if scenario == "clearance country block" {
					req.ToriiClearance = string(check.GenClearance(req, *rules))
				}
			case "later flood":
				req.ToriiClearance = string(check.GenClearance(req, *rules))
				req.FeatureControl |= feature.HTTPFlood.ControlMask()
				rules.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{1: 0}
				shared.HTTPFloodSpeedLimitCounter.Store(ratelimit.NewCounter(16, 1))
				shared.HTTPFloodSameURILimitCounter.Store(ratelimit.NewCounter(16, 1))
				shared.HTTPFloodFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
				want = "rate_limit"
			}
			if got := decide(shared, req, rules); got != want {
				t.Fatalf("decision = %q, want %q", got, want)
			}
		})
	}
}
