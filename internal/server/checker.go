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
	feature.IPAllow:     check.IPAllowList,
	feature.IPBlock:     check.IPBlockList,
	feature.URLAllow:    check.URLAllowList,
	feature.URLBlock:    check.URLBlockList,
	feature.CustomRules: check.CustomRules,
	feature.IPCAPTCHA:   check.IPCAPTCHA,
	feature.URLCAPTCHA:  check.URLCAPTCHA,
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
// request continue. For a challenge that is the check whose rule asked for it, not the Challenge
// check that carried it out, unless the site challenges every client.
func (s *Server) runChecks(userRequestData request.UserRequest, ruleSet *config.RuleSet) (*action.Decision, feature.Check) {
	decision := action.NewDecision()
	requiredBy := feature.Count
	for _, c := range feature.Pipeline() {
		// A challenge an earlier check asked for is not optional: neither the switch of the
		// Challenge check nor a skip rule takes it back.
		required := c == feature.Challenge && decision.RequireChallenge
		if !required && (!c.Enabled(userRequestData.FeatureControl) || decision.SkipMask&c.SkipMask() != 0) {
			continue
		}
		checkFuncs[c](userRequestData, ruleSet, decision, s.rt)
		if decision.RequireChallenge && requiredBy == feature.Count {
			requiredBy = c
		}
		if decision.State == action.Done {
			if c == feature.Challenge && requiredBy != feature.Count {
				return decision, requiredBy
			}
			return decision, c
		}
	}
	return decision, feature.Count
}
