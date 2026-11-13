package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/state"
	"server_torii/internal/utils"
)

func URLBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if URLBlock feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureURLBlock) == 0 {
		decision.Set(action.Continue)
		return
	}

	url := reqData.Uri
	list := ruleSet.URLBlockRule.List
	if list.Match(url) {
		utils.LogInfo(reqData, "", "URLBlockList")
		decision.SetVerdict(action.Done, action.VerdictBlock)
	} else {
		decision.Set(action.Continue)
	}
}
