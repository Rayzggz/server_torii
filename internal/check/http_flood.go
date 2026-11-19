package check

import (
	"log/slog"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"time"
)

func HTTPFlood(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	limiters := rt.LimitersFor(reqData.Site)
	speedCounter := limiters.HTTPFloodSpeedLimitCounter.Load()
	sameURICounter := limiters.HTTPFloodSameURILimitCounter.Load()
	failureCounter := limiters.HTTPFloodFailureLimitCounter.Load()
	if speedCounter == nil || sameURICounter == nil || failureCounter == nil {
		rt.Error(reqData, "HTTPFlood counters are not initialized; the check is skipped")
		return
	}
	ipKey := reqData.ClientKey()

	speedCounter.Add(ipKey, 1)

	// Check failure limit
	for _, rate := range ruleSet.HTTPFloodRule.FailureLimit {
		window, limit := rate.Window, rate.Limit
		if failureCounter.Query(ipKey, window) > limit {
			if ruleSet.HTTPFloodRule.FailureBlockDuration > 0 {
				blockClient(reqData, rt, "HTTPFlood failure limit", rate, ruleSet.HTTPFloodRule.FailureBlockDuration)
				failureCounter.Reset(ipKey)
				decision.Note = "failure_limit " + rate.String()
				decision.SetVerdict(action.Done, action.VerdictBlock)
				return
			}
		}
	}

	for _, rate := range ruleSet.HTTPFloodRule.SpeedLimit {
		window, limit := rate.Window, rate.Limit
		if speedCounter.Query(ipKey, window) > limit {
			decision.Note = "speed_limit " + rate.String()
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}

	// Counted only now: a request the speed limit turned away does not get a counter for its
	// URI, so a client cannot make one for every request by varying the query string.
	uriKey := ipKey + "|" + ruleSet.HTTPFloodRule.SameURIKey.Of(reqData.Uri)
	sameURICounter.Add(uriKey, 1)

	for _, rate := range ruleSet.HTTPFloodRule.SameURILimit {
		window, limit := rate.Window, rate.Limit
		if sameURICounter.Query(uriKey, window) > limit {
			decision.Note = "same_uri_limit " + rate.String()
			failureCounter.Add(ipKey, 1)
			decision.SetVerdict(action.Done, action.VerdictRateLimit)
			return
		}
	}
}

// blockClient blocks the client of the request on its site, shares the block with the peers and
// writes it to the events of the site.
func blockClient(reqData request.UserRequest, rt *state.Runtime, cause string, rate ratelimit.Rate, duration time.Duration) {
	if !rt.BlockIP(reqData.Site, reqData.ClientKey(), duration) {
		rt.Error(reqData, "no rule engine is running; the client is not blocked", slog.String("cause", cause))
		return
	}
	rt.Event(reqData, slog.LevelInfo, "client blocked", slog.String("client", reqData.ClientKey()),
		slog.String("cause", cause), slog.String("limit", rate.String()), slog.String("duration", duration.String()))
}
