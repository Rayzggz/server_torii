package check

import (
	"net"
	"regexp"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/iptrie"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/urllist"
	"testing"
)

func TestIPListRules(t *testing.T) {
	trie := &iptrie.TrieNode{}
	_, network, err := net.ParseCIDR("192.0.2.0/24")
	if err != nil {
		t.Fatal(err)
	}
	trie.Insert(network)
	rules := &config.RuleSet{
		IPAllowRule: &config.IPAllowRule{Trie: trie},
		IPBlockRule: &config.IPBlockRule{Trie: trie},
	}
	for _, checker := range []struct {
		name    string
		feature uint16
		code    string
		run     func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)
	}{
		{"allow", request.FeatureIPAllow, "200", IPAllowList},
		{"block", request.FeatureIPBlock, "403", IPBlockList},
	} {
		for _, tc := range []struct {
			name, ip        string
			disabled, match bool
		}{
			{"match", "192.0.2.42", false, true},
			{"miss", "198.51.100.1", false, false},
			{"invalid", "not-an-ip", false, false},
			{"ipv6", "2001:db8::1", false, false},
			{"disabled", "192.0.2.42", true, false},
		} {
			t.Run(checker.name+"/"+tc.name, func(t *testing.T) {
				req := request.UserRequest{RemoteIP: tc.ip, FeatureControl: checker.feature}
				if tc.disabled {
					req.FeatureControl = request.FeatureVerifyBot
				}
				decision := action.NewDecision()
				checker.run(req, rules, decision, nil)
				wantCode := "200"
				if tc.match {
					wantCode = checker.code
				}
				if (decision.State == action.Done) != tc.match || decision.Verdict.String() != wantCode {
					t.Fatalf("decision = %+v, want done=%v code=%s", decision, tc.match, wantCode)
				}
			})
		}
	}
}

func TestURLListRules(t *testing.T) {
	list := &urllist.URLRuleList{}
	list.Append(&urllist.URLRule{Pattern: "/admin"})
	list.Append(&urllist.URLRule{IsRegex: true, Regex: regexp.MustCompile(`^/private/.*$`)})
	rules := &config.RuleSet{
		URLAllowRule: &config.URLAllowRule{List: list},
		URLBlockRule: &config.URLBlockRule{List: list},
	}
	for _, checker := range []struct {
		name    string
		feature uint16
		code    string
		run     func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)
	}{
		{"allow", request.FeatureURLAllow, "200", URLAllowList},
		{"block", request.FeatureURLBlock, "403", URLBlockList},
	} {
		for _, tc := range []struct {
			name, uri       string
			disabled, match bool
		}{
			{"exact", "/admin", false, true}, {"regex", "/private/file", false, true},
			{"miss", "/public", false, false}, {"prefix", "/admin/settings", false, false},
			{"disabled", "/admin", true, false},
		} {
			t.Run(checker.name+"/"+tc.name, func(t *testing.T) {
				req := request.UserRequest{Uri: tc.uri, FeatureControl: checker.feature}
				if tc.disabled {
					req.FeatureControl = request.FeatureVerifyBot
				}
				decision := action.NewDecision()
				checker.run(req, rules, decision, nil)
				wantCode := "200"
				if tc.match {
					wantCode = checker.code
				}
				if (decision.State == action.Done) != tc.match || decision.Verdict.String() != wantCode {
					t.Fatalf("decision = %+v, want done=%v code=%s", decision, tc.match, wantCode)
				}
			})
		}
	}
}
