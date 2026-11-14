package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func IPBlockList(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	if ruleSet.IPBlockRule.Trie.SearchAddr(reqData.ClientAddr()) {
		logx.Info(reqData, "", "IPBlockList")
		decision.SetVerdict(action.Done, action.VerdictBlock)
	}
}
