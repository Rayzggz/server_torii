package check

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

func HTTPFlood(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	// Check if HTTPFlood feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureHTTPFlood) == 0 {
		decision.Set(action.Continue)
		return
	}
	ipKey := reqData.RemoteIP

	if sharedMem.BlockList.IsBlocked(ipKey) {
		decision.SetCode(action.Done, []byte("403"))
		return
	}
	sharedMem.HTTPFloodSpeedLimitCounter.Add(ipKey, 1)

	uriKey := reqData.RemoteIP + "|" + reqData.Uri
	sharedMem.HTTPFloodSameURILimitCounter.Add(uriKey, 1)

	// Check failure limit
	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodFailureLimit {
		if sharedMem.HTTPFloodFailureLimitCounter.Query(ipKey, window) > limit {
			if ruleSet.HTTPFloodRule.FailureBlockDuration > 0 {
				sharedMem.BlockList.Block(ipKey, ruleSet.HTTPFloodRule.FailureBlockDuration)
				utils.BroadcastBlock(ipKey, ruleSet.HTTPFloodRule.FailureBlockDuration, sharedMem.GossipChan)
				utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood failure rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
				sharedMem.HTTPFloodFailureLimitCounter.Reset(ipKey)
				decision.SetCode(action.Done, []byte("403"))
				return
			}
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit {
		if sharedMem.HTTPFloodSpeedLimitCounter.Query(ipKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			sharedMem.HTTPFloodFailureLimitCounter.Add(ipKey, 1)
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSameURILimit {
		if sharedMem.HTTPFloodSameURILimitCounter.Query(uriKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood URI rate limit exceeded: IP %s URI %s window %d limit %d", ipKey, reqData.Uri, window, limit))
			sharedMem.HTTPFloodFailureLimitCounter.Add(ipKey, 1)
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}
	decision.Set(action.Continue)
}
