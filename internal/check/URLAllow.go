package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/state"
)

func URLAllowList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if URLAllow feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureURLAllow) == 0 {
		decision.Set(action.Continue)
		return
	}

	url := reqData.Uri
	list := ruleSet.URLAllowRule.List
	if list.Match(url) {
		decision.SetVerdict(action.Done, action.VerdictAllow)
	} else {
		decision.Set(action.Continue)
	}
}
