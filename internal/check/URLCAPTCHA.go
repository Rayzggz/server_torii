package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// URLCAPTCHA uses the URLAllow matcher and the existing CAPTCHA flow.
func URLCAPTCHA(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	decision.Set(action.Continue)
	rule := ruleSet.URLCAPTCHARule
	if reqData.FeatureControl&request.FeatureURLCAPTCHA == 0 || rule == nil || rule.List == nil || !rule.List.Match(reqData.Uri) {
		return
	}
	logx.LogInfo(reqData, "", "URLCAPTCHA")
	requireCaptcha(reqData, ruleSet, decision, rt)
}
