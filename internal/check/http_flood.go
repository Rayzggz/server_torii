package check

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"time"
)

func HTTPFlood(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if HTTPFlood feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureHTTPFlood) == 0 {
		decision.Set(action.Continue)
		return
	}

	speedCounter := rt.HTTPFloodSpeedLimitCounter.Load()
	sameURICounter := rt.HTTPFloodSameURILimitCounter.Load()
	failureCounter := rt.HTTPFloodFailureLimitCounter.Load()
	if speedCounter == nil || sameURICounter == nil || failureCounter == nil {
		logx.Error(reqData, "", "HTTPFlood counters are not initialized, skipping HTTPFlood checks")
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
				if !rt.BlockIP(ipKey, time.Duration(ruleSet.HTTPFloodRule.FailureBlockDuration)*time.Second) {
					logx.Error(reqData, "", "ActionRuleEngine is not running, skipping block and broadcast")
				}
				logx.Info(reqData, "", fmt.Sprintf("HTTPFlood failure rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
				failureCounter.Reset(ipKey)
				decision.SetVerdict(action.Done, action.VerdictBlock)
				return
			}
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSpeedLimit {
		if speedCounter.Query(ipKey, window) > limit {
			logx.Info(reqData, "", fmt.Sprintf("HTTPFlood rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}

	for window, limit := range ruleSet.HTTPFloodRule.HTTPFloodSameURILimit {
		if sameURICounter.Query(uriKey, window) > limit {
			logx.Info(reqData, "", fmt.Sprintf("HTTPFlood URI rate limit exceeded: IP %s URI %s window %d limit %d", ipKey, reqData.Uri, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}
	decision.Set(action.Continue)
}
