package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

func URLBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.URLBlockRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	url := reqData.Uri
	list := ruleSet.URLBlockRule.List
	if list.Match(url) {
		utils.LogInfo(reqData, "", "URLBlockList")
		decision.SetCode(action.Done, []byte("403"))
	} else {
		decision.Set(action.Continue)
	}
}
