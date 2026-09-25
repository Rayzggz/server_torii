package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

// URLCAPTCHA uses the URLAllow matcher and the existing CAPTCHA flow.
func URLCAPTCHA(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	decision.Set(action.Continue)
	rule := ruleSet.URLCAPTCHARule
	if reqData.FeatureControl&dataType.FeatureURLCAPTCHA == 0 || rule == nil || rule.List == nil || !rule.List.Match(reqData.Uri) {
		return
	}
	utils.LogInfo(reqData, "", "URLCAPTCHA")
	reqData.FeatureControl |= dataType.FeatureCaptcha
	Captcha(reqData, ruleSet, decision, sharedMem)
}
