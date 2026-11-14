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
	if customRules == nil || len(customRules.Rules) == 0 {
		return
	}
	ctx := rules.NewContext(&reqData, rt.BrowserEvidence)
	for _, rule := range customRules.Rules {
		if !rule.Program.Eval(ctx) {
			continue
		}
		logx.Info(reqData, "", "CustomRule "+rule.String())
		switch rule.Action {
		case action.ActionAllow, action.ActionBlock, action.ActionChallenge:
			// A challenge ends the rule list like continue does; the Challenge check answers it.
			applyAction(reqData, decision, rt, rule.Action)
			return
		case action.ActionContinue:
			return
		case action.ActionSkip:
			decision.SkipMask |= rule.SkipMask
			if decision.SkipMask&feature.CustomRules.SkipMask() != 0 {
				return
			}
		}
		// ActionLog and non-terminal skips fall through to the next rule.
	}
}
