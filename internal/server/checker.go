package server

import (
	"context"
	"log/slog"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
)

type CheckFunc func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)

// checkFuncs implements each step of feature.Pipeline.
var checkFuncs = [feature.Count]CheckFunc{
	feature.Lists:            check.Lists,
	feature.CustomRules:      check.CustomRules,
	feature.CountryRule:      check.CountryRule,
	feature.VerifyBot:        check.VerifyBot,
	feature.BrowserIntegrity: check.BrowserIntegrity,
	feature.ActionRule:       check.ActionRule,
	feature.HTTPFlood:        check.HTTPFlood,
	feature.Challenge:        check.Challenge,
}

// runChecks runs the checks that are switched on for the request and that no custom rule
// skipped, in pipeline order, until one of them ends the pipeline.
//
// It also returns the check behind the decision, or feature.Count when every check let the
// request continue, and sets Decision.Reason to that check's name and detail. For a challenge
// that is the check whose rule asked for it, not the Challenge check that carried it out,
// unless the site challenges every client.
func (s *Server) runChecks(userRequestData request.UserRequest, ruleSet *config.RuleSet) (*action.Decision, feature.Check) {
	decision := action.NewDecision()
	requiredBy, requiredReason := feature.Count, ""
	// At the debug level the line of the request says what every check did.
	var trace []string
	debug := s.rt.SiteLog(userRequestData.Site).Enabled(context.Background(), slog.LevelDebug)
	for _, c := range feature.Pipeline() {
		// A challenge an earlier check asked for is not optional: neither the switch of the
		// Challenge check nor a skip rule takes it back.
		required := c == feature.Challenge && decision.RequireChallenge
		if !required && (!c.Enabled(userRequestData.FeatureControl) || decision.SkipMask&c.SkipMask() != 0) {
			if debug {
				outcome := "off"
				if c.Enabled(userRequestData.FeatureControl) {
					outcome = "skipped"
				}
				trace = append(trace, c.String()+":"+outcome)
			}
			continue
		}
		before := *decision
		checkFuncs[c](userRequestData, ruleSet, decision, s.rt)
		if debug {
			trace = append(trace, c.String()+":"+outcome(&before, decision))
		}

		reason := c.String()
		if decision.Detail != "" {
			reason += ":" + decision.Detail
			decision.Detail = ""
		}
		if decision.RequireChallenge && requiredBy == feature.Count {
			requiredBy, requiredReason = c, reason
		}
		if decision.State == action.Done {
			// Only the challenge belongs to the check that asked for it: a block for failing
			// it too often is the doing of the Challenge check.
			if c == feature.Challenge && decision.Verdict == action.VerdictChallenge && requiredBy != feature.Count {
				c, reason = requiredBy, requiredReason
			}
			decision.Reason = reason
			s.logDecision(userRequestData, decision, trace)
			return decision, c
		}
	}
	s.logDecision(userRequestData, decision, trace)
	return decision, feature.Count
}

// outcome names what one check did to the decision, for the debug line of the request.
func outcome(before, after *action.Decision) string {
	switch {
	case after.State == action.Done:
		return after.Verdict.String()
	case after.RequireChallenge && !before.RequireChallenge:
		return "challenge"
	case after.SkipMask != before.SkipMask:
		return "skip"
	}
	return "continue"
}

// logDecision writes the request to the events of its site: at the info level when it was not
// let through, at the debug level when it was. It is the one place decisions are logged: the
// checks only decide. trace is what every check did; it is nil unless the debug level is on.
func (s *Server) logDecision(req request.UserRequest, decision *action.Decision, trace []string) {
	level := slog.LevelInfo
	if decision.Verdict == action.VerdictAllow {
		level = slog.LevelDebug
	}
	attrs := []slog.Attr{slog.String("verdict", decision.Verdict.String())}
	if decision.Reason != "" {
		attrs = append(attrs, slog.String("reason", decision.Reason))
	}
	if decision.Note != "" {
		attrs = append(attrs, slog.String("note", decision.Note))
	}
	if len(trace) > 0 {
		attrs = append(attrs, slog.String("checks", strings.Join(trace, " ")))
	}
	s.rt.Event(req, level, "decision", attrs...)
}
