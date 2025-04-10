package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func IPBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	remoteIP := reqData.RemoteIP
	trie := ruleSet.IPBlockTrie
	ip := net.ParseIP(remoteIP)
	if ip == nil {
		return
	}
	if trie.Search(ip) {
		decision.SetCode(action.Done, []byte("403"))
	} else {
		decision.Set(action.Continue)
	}
}
