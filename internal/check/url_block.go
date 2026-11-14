package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func URLBlockList(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	if ruleSet.URLBlockRule.List.Match(reqData.Uri) {
		logx.Info(reqData, "", "URLBlockList")
		decision.SetVerdict(action.Done, action.VerdictBlock)
	}
}
