package server

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/rules"
	"server_torii/internal/state"
	"testing"
	"time"
)

// listsRuleSet is a site with one list of every kind, in the usual order: allow before block
// before challenge, plus a list that only rules refer to.
func listsRuleSet() *config.RuleSet {
	rs := config.NewRuleSet()
	rs.ID = "shop"
	rs.Lists = config.NewListSet(
		config.MustNewList("ip_allow", config.ListIP, action.ActionAllow, "192.0.2.0/24", "2001:db8:1::/48"),
		config.MustNewList("ip_block", config.ListIP, action.ActionBlock, "192.0.2.66", "198.51.100.0/24", "2001:db8:2::/48"),
		config.MustNewList("url_allow", config.ListURL, action.ActionAllow, "/health"),
		config.MustNewList("url_block", config.ListURL, action.ActionBlock, "/admin", `regex:^/private/`),
		config.MustNewList("ip_challenge", config.ListIP, action.ActionChallenge, "203.0.113.0/24"),
		config.MustNewList("url_challenge", config.ListURL, action.ActionChallenge, "/login"),
		config.MustNewList("partners", config.ListIP, action.ActionNone, "203.0.113.50"),
	)
	rs.Challenge = &config.ChallengeRule{Mode: config.ChallengeAltcha, Keys: []string{"1234567890abcdef"}, ClearanceTTL: 60, SessionTTL: 120}
	return rs
}

func listsRuntime() *state.Runtime {
	rt := &state.Runtime{}
	rt.ChallengeFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
	return rt
}

func TestListsDecide(t *testing.T) {
	for name, tt := range map[string]struct {
		ip, uri    string
		overrides  map[string]bool
		want       string
		wantReason string
	}{
		"on no list":                       {"8.8.8.8", "/", nil, "pass", ""},
		"allowed address":                  {"192.0.2.10", "/", nil, "pass", "Lists:ip_allow"},
		"allowed address on a blocked URL": {"192.0.2.10", "/admin", nil, "pass", "Lists:ip_allow"},
		// 192.0.2.66 is on both lists: the allow list comes first and decides.
		"first list wins":              {"192.0.2.66", "/", nil, "pass", "Lists:ip_allow"},
		"blocked address":              {"198.51.100.7", "/", nil, "block", "Lists:ip_block"},
		"blocked address, allowed URL": {"198.51.100.7", "/health", nil, "block", "Lists:ip_block"},
		"allowed URL":                  {"8.8.8.8", "/health", nil, "pass", "Lists:url_allow"},
		"blocked URL":                  {"8.8.8.8", "/admin", nil, "block", "Lists:url_block"},
		"blocked URL by regex":         {"8.8.8.8", "/private/x", nil, "block", "Lists:url_block"},
		"URL is matched exactly":       {"8.8.8.8", "/admin/x", nil, "pass", ""},
		"challenged address":           {"203.0.113.9", "/", nil, "challenge", "Lists:ip_challenge"},
		"challenged URL":               {"8.8.8.8", "/login", nil, "challenge", "Lists:url_challenge"},
		"a list without an action":     {"203.0.113.50", "/", map[string]bool{"ip_challenge": false}, "pass", ""},
		"IPv6 allowed":                 {"2001:db8:1::42", "/admin", nil, "pass", "Lists:ip_allow"},
		"IPv6 blocked":                 {"2001:db8:2::42", "/", nil, "block", "Lists:ip_block"},
		"IPv6 on no list":              {"2001:db8:3::42", "/", nil, "pass", ""},
		"IPv4-mapped address":          {"::ffff:198.51.100.7", "/", nil, "block", "Lists:ip_block"},
		// The connector switches lists per request.
		"block list switched off":                {"198.51.100.7", "/", map[string]bool{"ip_block": false}, "pass", ""},
		"allow list switched off, block applies": {"192.0.2.66", "/", map[string]bool{"ip_allow": false}, "block", "Lists:ip_block"},
	} {
		t.Run(name, func(t *testing.T) {
			req := request.UserRequest{Site: "shop", RemoteIP: tt.ip, Uri: tt.uri, Host: "example.com", ListOverrides: tt.overrides}
			decision, _ := NewServer(&config.MainConfig{}, nil, listsRuntime(), nil).runChecks(req, listsRuleSet())
			if got := decision.Verdict.String(); got != tt.want || decision.Reason != tt.wantReason {
				t.Fatalf("decision = %s, reason %q, want %s, %q", got, decision.Reason, tt.want, tt.wantReason)
			}
		})
	}
}

// A list that is switched off in the site configuration can be switched on for a request.
func TestListsDisabledAndForcedOn(t *testing.T) {
	rs := listsRuleSet()
	rs.Lists.ByName("ip_block").Enabled = false
	req := request.UserRequest{Site: "shop", RemoteIP: "198.51.100.7", Uri: "/"}
	if got := decide(listsRuntime(), req, rs); got != "pass" {
		t.Fatalf("disabled list: decision = %s, want pass", got)
	}
	req.ListOverrides = map[string]bool{"ip_block": true}
	if got := decide(listsRuntime(), req, rs); got != "block" {
		t.Fatalf("list forced on: decision = %s, want block", got)
	}
}

// A challenge list only marks the request: a later check that blocks wins, and a client that
// holds a clearance passes.
func TestListsChallengeFollowsThePipeline(t *testing.T) {
	rs := listsRuleSet()
	req := request.UserRequest{Site: "shop", RemoteIP: "203.0.113.9", Uri: "/", Host: "example.com"}

	rt := listsRuntime()
	engine := action.NewActionRuleEngine(time.Minute)
	t.Cleanup(engine.Stop)
	engine.AddIPRule("shop", "203.0.113.9", action.ActionBlock, time.Minute)
	rt.ActionRuleEngine = engine
	decision, _ := NewServer(&config.MainConfig{}, nil, rt, nil).runChecks(req, rs)
	if decision.Verdict != action.VerdictBlock || decision.Reason != "ActionRule" {
		t.Fatalf("with a temporary block: %s, reason %q", decision.Verdict, decision.Reason)
	}

	cleared := req
	cleared.ToriiClearance = string(checkClearance(cleared, rs))
	if got := decide(listsRuntime(), cleared, rs); got != "pass" {
		t.Fatalf("with a clearance: decision = %s, want pass", got)
	}
}

// Custom rules run after the lists and refer to them by name, also to the ones that are
// switched off or have no action.
func TestCustomRulesUseLists(t *testing.T) {
	rs := listsRuleSet()
	rs.Lists.ByName("ip_challenge").Enabled = false
	compile := func(id, expr string) *rules.Rule {
		prog, err := rules.Compile(expr, rs.Lists)
		if err != nil {
			t.Fatalf("%s: %v", expr, err)
		}
		return &rules.Rule{ID: id, Action: action.ActionBlock, Program: prog}
	}
	rs.CustomRules = &rules.CustomRules{Enabled: true, Rules: []*rules.Rule{
		compile("partners-only", `http.request.uri.path eq "/partner-api" and not ip.src in $partners`),
		compile("challenge-net-api", `ip.src in $ip_challenge and http.request.uri.path in $url_challenge`),
	}}
	on := feature.CustomRules.ControlMask()
	for name, tt := range map[string]struct {
		ip, uri, want, reason string
	}{
		"partner":       {"203.0.113.50", "/partner-api", "pass", ""},
		"not a partner": {"8.8.8.8", "/partner-api", "block", "CustomRules:partners-only"},
		// The URL list marks the request for a challenge; the block of the rule that follows wins.
		"both lists":                  {"203.0.113.9", "/login", "block", "CustomRules:challenge-net-api"},
		"address list only":           {"203.0.113.9", "/", "pass", ""},
		"an allow list decides first": {"192.0.2.10", "/partner-api", "pass", "Lists:ip_allow"},
	} {
		t.Run(name, func(t *testing.T) {
			req := request.UserRequest{Site: "shop", RemoteIP: tt.ip, Uri: tt.uri, Host: "example.com", FeatureControl: on}
			decision, _ := NewServer(&config.MainConfig{}, nil, listsRuntime(), nil).runChecks(req, rs)
			if got := decision.Verdict.String(); got != tt.want || decision.Reason != tt.reason {
				t.Fatalf("decision = %s, reason %q, want %s, %q", got, decision.Reason, tt.want, tt.reason)
			}
		})
	}

	// With the URL challenge list switched off for the request, the rule that refers to it
	// still sees its entries.
	req := request.UserRequest{Site: "shop", RemoteIP: "203.0.113.9", Uri: "/login", Host: "example.com", FeatureControl: on,
		ListOverrides: map[string]bool{"url_challenge": false}}
	decision, _ := NewServer(&config.MainConfig{}, nil, listsRuntime(), nil).runChecks(req, rs)
	if decision.Verdict != action.VerdictBlock || decision.Reason != "CustomRules:challenge-net-api" {
		t.Fatalf("list switched off: %s, reason %q", decision.Verdict, decision.Reason)
	}
}

func TestListOverrides(t *testing.T) {
	lists := listsRuleSet().Lists
	overrides, unknown := listOverrides(lists, []string{"-ip_block", "+URL_Challenge", "+nope", "partners", "-partners"})
	if len(overrides) != 3 || overrides["ip_block"] || !overrides["url_challenge"] || overrides["partners"] {
		t.Errorf("overrides = %v", overrides)
	}
	if len(unknown) != 2 || unknown[0] != "+nope" || unknown[1] != "partners" {
		t.Errorf("unknown = %v", unknown)
	}
	if overrides, unknown := listOverrides(lists, nil); overrides != nil || unknown != nil {
		t.Errorf("nothing asked for: %v, %v", overrides, unknown)
	}
}
