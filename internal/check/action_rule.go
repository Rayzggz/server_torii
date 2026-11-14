package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func ActionRule(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	engine := rt.ActionRuleEngine
	if engine == nil {
		return
	}

	act := engine.CheckRequest(reqData)

	switch act {
	case action.ActionBlock:
		decision.SetVerdict(action.Done, action.VerdictBlock)
	case action.ActionCaptcha:
		requireCaptcha(reqData, ruleSet, decision, rt)
	case action.ActionCaptchaUnverified:
		if !reqData.HasBrowserEvidence(rt.BrowserEvidence) {
			requireCaptcha(reqData, ruleSet, decision, rt)
		}
	}
}
