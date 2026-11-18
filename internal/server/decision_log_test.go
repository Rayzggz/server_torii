package server

import (
	"bytes"
	"log/slog"
	"server_torii/internal/action"
	"server_torii/internal/logx"
	"server_torii/internal/rules"
	"strings"
	"testing"
)

// Every request that is not let through gets one line in the events of its site, written by
// the pipeline and not by the check that decided.
func TestDecisionLog(t *testing.T) {
	var out bytes.Buffer
	s := newV1Server(t)
	s.rt.Logs = logx.To(&out)
	headers := func(uri string) map[string]string {
		return map[string]string{
			headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: uri, headerHost: "shop.example",
			headerMethod: "POST", "User-Agent": "test-agent",
		}
	}

	v1Get(s, v1CheckPath, headers("/ok"))
	if out.Len() != 0 {
		t.Fatalf("a request that was let through was logged: %s", out.String())
	}

	v1Get(s, v1CheckPath, headers("/blocked"))
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 1 {
		t.Fatalf("lines = %q, want one", lines)
	}
	const want = `[info] decision site=shop ip=203.0.113.5 verdict=block reason=Lists:url_block ` +
		`method=POST host=shop.example uri=/blocked ua=test-agent`
	if !strings.HasSuffix(lines[0], " "+want) {
		t.Fatalf("line = %q, want the time and %q", lines[0], want)
	}
}

// A log rule decides nothing; its line is written and the request goes on.
func TestLogRuleWritesALine(t *testing.T) {
	var out bytes.Buffer
	s := newV1Server(t)
	s.rt.Logs = logx.To(&out)
	shop := s.configs.Get().Site("shop")
	shop.CustomRules = &rules.CustomRules{Enabled: true, Rules: []*rules.Rule{customRule(t, "watch-login", action.ActionLog, `true`)}}

	rec := v1Get(s, v1CheckPath, map[string]string{
		headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/login", headerHost: "shop.example",
		headerFeatures: "+custom_rules",
	})
	if got := rec.Header().Get(headerDecision); got != "pass" {
		t.Fatalf("decision = %q, want pass", got)
	}
	if got := out.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "[info] custom rule matched site=shop ip=203.0.113.5 rule=watch-login ") ||
		!strings.Contains(got, " uri=/login ") {
		t.Fatalf("events = %s", got)
	}
}

// At the debug level every request has a line, with what each check did. Below it a request
// that was let through has none.
func TestDebugLevelTracesEveryCheck(t *testing.T) {
	var out bytes.Buffer
	s := newV1Server(t)
	s.rt.Logs = logx.To(&out)
	s.rt.Logs.SetLevel(slog.LevelDebug)
	headers := func(uri string) map[string]string {
		return map[string]string{headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: uri, headerHost: "shop.example"}
	}

	v1Get(s, v1CheckPath, headers("/ok"))
	if got := out.String(); strings.Count(got, "\n") != 1 || !strings.Contains(got, "[debug] decision site=shop ip=203.0.113.5 verdict=pass checks=\"Lists:continue ") ||
		!strings.Contains(got, " HTTPFlood:off ") {
		t.Fatalf("line of a request that was let through = %s", got)
	}

	out.Reset()
	v1Get(s, v1CheckPath, headers("/blocked"))
	if got := out.String(); !strings.Contains(got, "[info] decision site=shop ip=203.0.113.5 verdict=block reason=Lists:url_block checks=Lists:block ") {
		t.Fatalf("line of a blocked request = %s", got)
	}

	out.Reset()
	s.rt.Logs.SetLevel(slog.LevelError)
	v1Get(s, v1CheckPath, headers("/blocked"))
	if out.Len() != 0 {
		t.Fatalf("a decision was logged at the error level: %s", out.String())
	}
}
