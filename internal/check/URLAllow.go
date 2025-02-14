package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func URLAllowList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision) {
	url := reqData.Uri
	list := ruleSet.URLAllowList
	if list.Match(url) {
		decision.SetCode(action.Done, "200")
	} else {
		decision.Set(action.Continue)
	}
}
