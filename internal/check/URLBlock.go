package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func URLBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision) {
	url := reqData.Uri
	list := ruleSet.URLBlockList
	if list.Match(url) {
		decision.SetCode(action.Done, []byte("403"))
	} else {
		decision.Set(action.Continue)
	}
}
