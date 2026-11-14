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
		IPAllowRule: &config.IPListRule{Trie: trie},
		IPBlockRule: &config.IPListRule{Trie: trie},
	}
	for _, checker := range []struct {
		name string
		code string
		run  func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)
	}{
		{"allow", "pass", IPAllowList},
		{"block", "block", IPBlockList},
	} {
		for _, tc := range []struct {
			name, ip string
			match    bool
		}{
			{"match", "192.0.2.42", true},
			{"mapped", "::ffff:192.0.2.42", true},
			{"miss", "198.51.100.1", false},
			{"invalid", "not-an-ip", false},
			{"ipv6", "2001:db8::1", false},
		} {
			t.Run(checker.name+"/"+tc.name, func(t *testing.T) {
				req := request.UserRequest{RemoteIP: tc.ip}
				decision := action.NewDecision()
				checker.run(req, rules, decision, nil)
				wantCode := "pass"
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
		URLAllowRule: &config.URLListRule{List: list},
		URLBlockRule: &config.URLListRule{List: list},
	}
	for _, checker := range []struct {
		name string
		code string
		run  func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)
	}{
		{"allow", "pass", URLAllowList},
		{"block", "block", URLBlockList},
	} {
		for _, tc := range []struct {
			name, uri string
			match     bool
		}{
			{"exact", "/admin", true}, {"regex", "/private/file", true},
			{"miss", "/public", false}, {"prefix", "/admin/settings", false},
		} {
			t.Run(checker.name+"/"+tc.name, func(t *testing.T) {
				req := request.UserRequest{Uri: tc.uri}
				decision := action.NewDecision()
				checker.run(req, rules, decision, nil)
				wantCode := "pass"
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
