package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func URLBlockList(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if URLBlock feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureURLBlock) == 0 {
		decision.Set(action.Continue)
		return
	}

	url := reqData.Uri
	list := ruleSet.URLBlockRule.List
	if list.Match(url) {
		logx.Info(reqData, "", "URLBlockList")
		decision.SetVerdict(action.Done, action.VerdictBlock)
	} else {
		decision.Set(action.Continue)
	}
}
