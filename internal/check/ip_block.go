package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func IPBlockList(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if IPBlock feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureIPBlock) == 0 {
		decision.Set(action.Continue)
		return
	}

	remoteIP := reqData.RemoteIP
	trie := ruleSet.IPBlockRule.Trie
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}
	if trie.Search(ip) {
		logx.Info(reqData, "", "IPBlockList")
		decision.SetVerdict(action.Done, action.VerdictBlock)
	} else {
		decision.Set(action.Continue)
	}
}
