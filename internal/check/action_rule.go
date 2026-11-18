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

	applyAction(reqData, decision, rt, engine.CheckRequest(reqData))
}
