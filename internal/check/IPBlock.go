package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

func IPBlockList(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	// Check if IPBlock feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureIPBlock) == 0 {
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
		utils.LogInfo(reqData, "", "IPBlockList")
		decision.SetCode(action.Done, []byte("403"))
	} else {
		decision.Set(action.Continue)
	}
}
