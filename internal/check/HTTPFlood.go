package check

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"time"
)

func HTTPFlood(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	// Check if HTTPFlood feature is enabled using binary operation
	if (reqData.FeatureControl & dataType.FeatureHTTPFlood) == 0 {
		decision.Set(action.Continue)
		return
	}

	speedCounter := sharedMem.HTTPFloodSpeedLimitCounter.Load()
	sameURICounter := sharedMem.HTTPFloodSameURILimitCounter.Load()
	failureCounter := sharedMem.HTTPFloodFailureLimitCounter.Load()
	if speedCounter == nil || sameURICounter == nil || failureCounter == nil {
		utils.LogError(reqData, "", "HTTPFlood counters are not initialized, skipping HTTPFlood checks")
		decision.Set(action.Continue)
		return
	}
	ipKey := reqData.RemoteIP

	speedCounter.Add(ipKey, 1)

	uriKey := reqData.RemoteIP + "|" + reqData.Uri
	sameURICounter.Add(uriKey, 1)

	// Check failure limit
	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodFailureLimit {
		if failureCounter.Query(ipKey, window) > limit {
			if ruleSet.HTTPFloodRule.FailureBlockDuration > 0 {
				if engine, ok := sharedMem.ActionRuleEngine.(*action.ActionRuleEngine); ok {
					engine.AddIPRule(ipKey, action.ActionBlock, time.Duration(ruleSet.HTTPFloodRule.FailureBlockDuration)*time.Second)
					utils.BroadcastActionRule(config.GlobalConfig.NodeName, "IP", ipKey, string(action.ActionBlock), time.Duration(ruleSet.HTTPFloodRule.FailureBlockDuration)*time.Second, sharedMem.GossipChan)
				} else {
					utils.LogError(reqData, "", "Failed to cast ActionRuleEngine, skipping block and broadcast")
				}
				utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood failure rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
				failureCounter.Reset(ipKey)
				decision.SetCode(action.Done, []byte("403"))
				return
			}
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit {
		if speedCounter.Query(ipKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSameURILimit {
		if sameURICounter.Query(uriKey, window) > limit {
			utils.LogInfo(reqData, "", fmt.Sprintf("HTTPFlood URI rate limit exceeded: IP %s URI %s window %d limit %d", ipKey, reqData.Uri, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetCode(action.Done, []byte("429"))
			return
		}
	}
	decision.Set(action.Continue)
}
