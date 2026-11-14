package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// Lists applies the lists of the site that have an action, in the order of its Server.yml. The
// first list the request is on decides, and no later list is looked at: an allow list ahead of a
// block list exempts its entries from it.
func Lists(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	addr := reqData.ClientAddr()
	for _, list := range ruleSet.Lists.All() {
		if list.Action == action.ActionNone || !reqData.ListEnabled(list.Name, list.Enabled) || !list.Matches(addr, reqData.Uri) {
			continue
		}
		decision.Detail = list.Name
		if list.Action != action.ActionAllow {
			logx.Info(reqData, "", "List "+list.Name+" "+string(list.Action))
		}
		applyAction(reqData, decision, rt, list.Action)
		return
	}
}
