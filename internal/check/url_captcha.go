package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// URLCAPTCHA marks the URLs in the site's list for a challenge.
func URLCAPTCHA(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.URLCAPTCHARule
	if rule == nil || rule.List == nil || !rule.List.Match(reqData.Uri) {
		return
	}
	logx.Info(reqData, "", "URLCAPTCHA")
	decision.RequireChallenge = true
}
