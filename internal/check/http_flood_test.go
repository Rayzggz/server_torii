package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

// The same-URI limit counts two requests together when the key of the site says they are for
// one URI: a changing query string gets past the full URI, and past nothing else.
func TestHTTPFloodSameURIKey(t *testing.T) {
	for _, tc := range []struct {
		name    string
		key     config.SameURIKey
		uris    []string
		limited bool // whether the last request runs into the limit
	}{
		{"full, same URI", config.SameURIKeyFull, []string{"/search?x=1", "/search?x=1", "/search?x=1"}, true},
		{"full, changing query", config.SameURIKeyFull, []string{"/search?x=1", "/search?x=2", "/search?x=3"}, false},
		{"unset counts the full URI", "", []string{"/search?x=1", "/search?x=2", "/search?x=3"}, false},
		{"path, changing query", config.SameURIKeyPath, []string{"/search?x=1", "/search?x=2", "/search?x=3"}, true},
		{"path, respelled path", config.SameURIKeyPath, []string{"/search", "//search/", "/./search?x=1"}, true},
		{"path, different IDs", config.SameURIKeyPath, []string{"/post/1", "/post/2", "/post/3"}, false},
		{"canonical, changing query", config.SameURIKeyCanonical, []string{"/search?x=1", "/search?x=2", "/search?x=3"}, true},
		{"canonical, different IDs", config.SameURIKeyCanonical, []string{"/post/1", "/post/2", "/post/3?x=1"}, true},
		{"canonical, different pages", config.SameURIKeyCanonical, []string{"/post/1", "/user/1", "/tag/1"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &state.Runtime{}
			rt.HTTPFloodSpeedLimitCounter.Store(ratelimit.NewCounter(16, 10))
			rt.HTTPFloodSameURILimitCounter.Store(ratelimit.NewCounter(16, 10))
			rt.HTTPFloodFailureLimitCounter.Store(ratelimit.NewCounter(16, 10))
			ruleSet := &config.RuleSet{HTTPFloodRule: &config.HTTPFloodRule{
				SpeedLimit:   ratelimit.Rates{{Limit: 100, Window: 10}},
				SameURILimit: ratelimit.Rates{{Limit: 2, Window: 10}},
				SameURIKey:   tc.key,
				FailureLimit: ratelimit.Rates{{Limit: 100, Window: 10}},
			}}

			var decision *action.Decision
			for i, uri := range tc.uris {
				decision = action.NewDecision()
				HTTPFlood(request.UserRequest{RemoteIP: "203.0.113.7", Uri: uri}, ruleSet, decision, rt)
				if i < len(tc.uris)-1 && decision.State != action.Continue {
					t.Fatalf("request %d for %s was stopped: %+v", i+1, uri, decision)
				}
			}
			if limited := decision.State == action.Done && decision.Verdict == action.VerdictRateLimit; limited != tc.limited {
				t.Fatalf("last request limited = %v, want %v: %+v", limited, tc.limited, decision)
			}

			// Another client is not held to what this one sent.
			other := action.NewDecision()
			HTTPFlood(request.UserRequest{RemoteIP: "203.0.113.8", Uri: tc.uris[0]}, ruleSet, other, rt)
			if other.State != action.Continue {
				t.Fatalf("another client was stopped: %+v", other)
			}
		})
	}
}
