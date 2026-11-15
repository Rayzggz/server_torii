package check

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// Challenge is the last step of the pipeline and the only place a client is challenged. It runs
// for every request when the site challenges all traffic, and for the requests an earlier check
// marked with Decision.RequireChallenge. A client that holds a clearance passes; any other gets
// the challenge of the site, a CAPTCHA page or a redirect to the external provider.
func Challenge(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.Challenge
	failureCounter := rt.LimitersFor(reqData.Site).ChallengeFailureLimitCounter.Load()
	if failureCounter == nil {
		logx.Error(reqData, "", "Challenge failure counter is not initialized, skipping the failure limit")
	}
	ipKey := reqData.ClientKey()

	if failureCounter != nil && rule.FailureBlockDuration > 0 {
		for _, rate := range rule.FailureLimit {
			window, limit := rate.Window, rate.Limit
			if failureCounter.Query(ipKey, window) <= limit {
				continue
			}
			if !rt.BlockIP(reqData.Site, ipKey, rule.FailureBlockDuration) {
				logx.Error(reqData, "", "ActionRuleEngine is not running, skipping block and broadcast")
			}
			logx.Info(reqData, "", fmt.Sprintf("Challenge failure limit exceeded and blocked: IP %s window %d limit %d", ipKey, window, limit))
			failureCounter.Reset(ipKey)
			decision.SetVerdict(action.Done, action.VerdictBlock)
			return
		}
	}

	if verifyClearanceCookie(reqData, *ruleSet) {
		return
	}
	if failureCounter != nil {
		failureCounter.Add(ipKey, 1)
	}
	decision.SetVerdict(action.Done, action.VerdictChallenge)
}

// applyAction carries out the action a rule chose for the request. It reports whether the
// action ended the pipeline.
//
// A challenge does not: it marks the request, the checks that follow still run, and the
// Challenge check at the end of the pipeline decides.
func applyAction(reqData request.UserRequest, decision *action.Decision, rt *state.Runtime, act action.Action) bool {
	switch act {
	case action.ActionAllow:
		decision.SetVerdict(action.Done, action.VerdictAllow)
	case action.ActionBlock:
		decision.SetVerdict(action.Done, action.VerdictBlock)
	case action.ActionChallenge:
		decision.RequireChallenge = true
	case action.ActionChallengeUnverified:
		if !reqData.HasBrowserEvidence(rt.BrowserEvidence) {
			decision.RequireChallenge = true
		}
	}
	return decision.State == action.Done
}
