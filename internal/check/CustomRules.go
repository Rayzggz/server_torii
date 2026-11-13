package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/rules"
	"server_torii/internal/state"
)

// CustomRules evaluates the site's expression rules in order and applies the first terminating action.
func CustomRules(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	customRules := ruleSet.CustomRules
	if reqData.FeatureControl&request.FeatureCustomRules == 0 || customRules == nil || len(customRules.Rules) == 0 {
		decision.Set(action.Continue)
		return
	}
	ctx := rules.NewContext(&reqData, rt.CountryResolver, rt.BrowserEvidence)
	for _, rule := range customRules.Rules {
		if !rule.Program.Eval(ctx) {
			continue
		}
		logx.LogInfo(reqData, "", "CustomRule "+rule.String())
		switch rule.Action {
		case rules.ActionAllow:
			decision.SetVerdict(action.Done, action.VerdictAllow)
			return
		case rules.ActionBlock:
			decision.SetVerdict(action.Done, action.VerdictBlock)
			return
		case rules.ActionCaptcha:
			requireCaptcha(reqData, ruleSet, decision, rt)
			return
		case rules.ActionExternal:
			requireExternalMigration(reqData, ruleSet, decision, rt)
			return
		case rules.ActionContinue:
			decision.Set(action.Continue)
			return
		case rules.ActionSkip:
			decision.SkipMask |= rule.SkipMask
			if decision.SkipMask&feature.CustomRules.SkipMask() != 0 {
				decision.Set(action.Continue)
				return
			}
		}
		// ActionLog and non-terminal skips fall through to the next rule.
	}
	decision.Set(action.Continue)
}
