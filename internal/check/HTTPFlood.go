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
	sharedMem.HTTPFloodSpeedLimitCounter.Add(ipKey, 1)

	uriKey := reqData.RemoteIP + "|" + reqData.Uri
	sharedMem.HTTPFloodSameURILimitCounter.Add(uriKey, 1)

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit {
		if sharedMem.HTTPFloodSpeedLimitCounter.Query(ipKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSameURILimit {
		if sharedMem.HTTPFloodSameURILimitCounter.Query(uriKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood URI rate limit exceeded: IP %s URI %s window %d limit %d", ipKey, reqData.Uri, window, limit))
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}
	decision.Set(action.Continue)
}
