package server

import (
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

type CheckFunc func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)

// checkFuncs implements each step of feature.Pipeline.
var checkFuncs = [feature.Count]CheckFunc{
	feature.Lists:       check.Lists,
	feature.CustomRules: check.CustomRules,
	feature.CountryRule: check.CountryRule,
	feature.VerifyBot:   check.VerifyBot,
	feature.ActionRule:  check.ActionRule,
	feature.HTTPFlood:   check.HTTPFlood,
	feature.Challenge:   check.Challenge,
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
	for _, c := range feature.Pipeline() {
		// A challenge an earlier check asked for is not optional: neither the switch of the
		// Challenge check nor a skip rule takes it back.
		required := c == feature.Challenge && decision.RequireChallenge
		if !required && (!c.Enabled(userRequestData.FeatureControl) || decision.SkipMask&c.SkipMask() != 0) {
			continue
		}
		checkFuncs[c](userRequestData, ruleSet, decision, s.rt)

		reason := c.String()
		if decision.Detail != "" {
			reason += ":" + decision.Detail
			decision.Detail = ""
		}
		if decision.RequireChallenge && requiredBy == feature.Count {
			requiredBy, requiredReason = c, reason
		}
		if decision.State == action.Done {
			if c == feature.Challenge && requiredBy != feature.Count {
				c, reason = requiredBy, requiredReason
			}
			decision.Reason = reason
			return decision, c
		}
	}
	return decision, feature.Count
}
