package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func IPAllowList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if !ruleSet.IPAllowRule.Enabled {
		decision.Set(action.Continue)
		return
	}

	remoteIP := reqData.RemoteIP
	trie := ruleSet.IPAllowRule.Trie

	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}
	if trie.Search(ip) {
		decision.SetCode(action.Done, []byte("200"))
	} else {
		decision.Set(action.Continue)
	}
}
