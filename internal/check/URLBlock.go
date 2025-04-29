package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

func URLBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	url := reqData.Uri
	list := ruleSet.URLBlockList
	if list.Match(url) {
		utils.LogInfo(reqData, "", "URLBlockList")
		decision.SetCode(action.Done, []byte("403"))
	} else {
		decision.Set(action.Continue)
	}
}
