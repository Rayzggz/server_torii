package check

import (
	"log"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func HTTPFlood(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	ipKey := reqData.RemoteIP
	sharedMem.HTTPFloodSpeedLimitCounter.Add(ipKey, 1)

	uriKey := reqData.RemoteIP + "|" + reqData.Uri
	sharedMem.HTTPFloodSameURILimitCounter.Add(uriKey, 1)

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit {
		if sharedMem.HTTPFloodSpeedLimitCounter.Query(ipKey, window) > limit {
			log.Printf("HTTPFlood rate limit exceeded: IP %s, window %d, limit %d", ipKey, window, limit)
			//decision.SetResponse(action.Done, []byte("403"), nil)
			decision.Set(action.Continue)
			return
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSameURILimit {
		if sharedMem.HTTPFloodSameURILimitCounter.Query(uriKey, window) > limit {
			log.Printf("HTTPFlood URI rate limit exceeded: IP %s, URI %s, window %d, limit %d", ipKey, reqData.Uri, window, limit)
			//decision.SetResponse(action.Done, []byte("403"), nil)
			decision.Set(action.Continue)
			return
		}
	}
	decision.Set(action.Continue)
}
