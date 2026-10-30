package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/rules"
	"server_torii/internal/utils"
)

// CustomRules evaluates the site's expression rules in order and applies the first terminating action.
func CustomRules(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	customRules := ruleSet.CustomRules
	if reqData.FeatureControl&dataType.FeatureCustomRules == 0 || customRules == nil || len(customRules.Rules) == 0 {
		decision.Set(action.Continue)
		return
	}
	ctx := rules.NewContext(&reqData, sharedMem)
	for _, rule := range customRules.Rules {
		if !rule.Program.Eval(ctx) {
			continue
		}
		utils.LogInfo(reqData, "", "CustomRule "+rule.String())
		switch rule.Action {
		case rules.ActionAllow:
			decision.SetCode(action.Done, []byte("200"))
			return
		case rules.ActionBlock:
			decision.SetCode(action.Done, []byte("403"))
			return
		case rules.ActionCaptcha:
			reqData.FeatureControl |= dataType.FeatureCaptcha
			Captcha(reqData, ruleSet, decision, sharedMem)
			return
		case rules.ActionExternal:
			reqData.FeatureControl |= dataType.FeatureExternalMigration
			ExternalMigration(reqData, ruleSet, decision, sharedMem)
			return
		case rules.ActionContinue:
			decision.Set(action.Continue)
			return
		case rules.ActionSkip:
			decision.SkipMask |= rule.SkipMask
			if decision.SkipMask&rules.SkipCustomRules != 0 {
				decision.Set(action.Continue)
				return
			}
		}
		// ActionLog and non-terminal skips fall through to the next rule.
	}
	decision.Set(action.Continue)
}
