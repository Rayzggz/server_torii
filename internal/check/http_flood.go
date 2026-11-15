package check

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

func HTTPFlood(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	limiters := rt.LimitersFor(reqData.Site)
	speedCounter := limiters.HTTPFloodSpeedLimitCounter.Load()
	sameURICounter := limiters.HTTPFloodSameURILimitCounter.Load()
	failureCounter := limiters.HTTPFloodFailureLimitCounter.Load()
	if speedCounter == nil || sameURICounter == nil || failureCounter == nil {
		logx.Error(reqData, "", "HTTPFlood counters are not initialized, skipping HTTPFlood checks")
		return
	}
	ipKey := reqData.ClientKey()

	speedCounter.Add(ipKey, 1)

	uriKey := ipKey + "|" + reqData.Uri
	sameURICounter.Add(uriKey, 1)

	// Check failure limit
	for _, rate := range ruleSet.HTTPFloodRule.FailureLimit {
		window, limit := rate.Window, rate.Limit
		if failureCounter.Query(ipKey, window) > limit {
			if ruleSet.HTTPFloodRule.FailureBlockDuration > 0 {
				if !rt.BlockIP(reqData.Site, ipKey, ruleSet.HTTPFloodRule.FailureBlockDuration) {
					logx.Error(reqData, "", "ActionRuleEngine is not running, skipping block and broadcast")
				}
				logx.Info(reqData, "", fmt.Sprintf("HTTPFlood failure rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
				failureCounter.Reset(ipKey)
				decision.SetVerdict(action.Done, action.VerdictBlock)
				return
			}
		}
	}

	for _, rate := range ruleSet.HTTPFloodRule.SpeedLimit {
		window, limit := rate.Window, rate.Limit
		if speedCounter.Query(ipKey, window) > limit {
			logx.Info(reqData, "", fmt.Sprintf("HTTPFlood rate limit exceeded: IP %s window %d limit %d", ipKey, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}

	for _, rate := range ruleSet.HTTPFloodRule.SameURILimit {
		window, limit := rate.Window, rate.Limit
		if sameURICounter.Query(uriKey, window) > limit {
			logx.Info(reqData, "", fmt.Sprintf("HTTPFlood URI rate limit exceeded: IP %s URI %s window %d limit %d", ipKey, reqData.Uri, window, limit))
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}
}
