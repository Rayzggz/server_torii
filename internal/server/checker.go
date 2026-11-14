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
	feature.IPAllow:           check.IPAllowList,
	feature.IPBlock:           check.IPBlockList,
	feature.URLAllow:          check.URLAllowList,
	feature.URLBlock:          check.URLBlockList,
	feature.CustomRules:       check.CustomRules,
	feature.IPCAPTCHA:         check.IPCAPTCHA,
	feature.URLCAPTCHA:        check.URLCAPTCHA,
	feature.CountryRule:       check.CountryRule,
	feature.VerifyBot:         check.VerifyBot,
	feature.ActionRule:        check.ActionRule,
	feature.HTTPFlood:         check.HTTPFlood,
	feature.ExternalMigration: check.ExternalMigration,
	feature.Captcha:           check.Captcha,
}

// runChecks runs the check pipeline. It also returns the check that ended the pipeline, or
// feature.Count when every check let the request continue.
func (s *Server) runChecks(userRequestData request.UserRequest, ruleSet *config.RuleSet) (*action.Decision, feature.Check) {
	decision := action.NewDecision()
	for _, c := range feature.Pipeline() {
		if decision.SkipMask&c.SkipMask() != 0 {
			continue
		}
		checkFuncs[c](userRequestData, ruleSet, decision, s.rt)
		if decision.State == action.Done {
			return decision, c
		}
	}
	return decision, feature.Count
}
