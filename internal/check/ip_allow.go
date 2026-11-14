package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func IPAllowList(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	if ruleSet.IPAllowRule.Trie.SearchAddr(reqData.ClientAddr()) {
		decision.SetVerdict(action.Done, action.VerdictAllow)
	}
}
