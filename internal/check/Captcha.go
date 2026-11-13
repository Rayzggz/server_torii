package check

import (
	"fmt"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"time"
)

// Captcha is the pipeline step: it challenges every client without a clearance when the feature is on.
func Captcha(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	// Check if Captcha feature is enabled using binary operation
	if (reqData.FeatureControl & request.FeatureCaptcha) == 0 {
		decision.Set(action.Continue)
		return
	}
	requireCaptcha(reqData, ruleSet, decision, rt)
}

// requireCaptcha challenges a client without a clearance regardless of the Captcha feature switch.
// Other checks call it when their own rule asks for a CAPTCHA.
func requireCaptcha(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	failureCounter := rt.CaptchaFailureLimitCounter.Load()
	if failureCounter == nil {
		logx.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha rate checks")
		decision.Set(action.Continue)
		return
	}

	ipKey := reqData.RemoteIP

	// Check failure limit
	for limitTime, limitCount := range ruleSet.CAPTCHARule.CaptchaFailureLimit {
		count := failureCounter.Query(ipKey, limitTime)
		if count > limitCount {

			if ruleSet.CAPTCHARule.FailureBlockDuration > 0 {
				if !rt.BlockIP(ipKey, time.Duration(ruleSet.CAPTCHARule.FailureBlockDuration)*time.Second) {
					logx.LogError(reqData, "", "ActionRuleEngine is not running, skipping block and broadcast")
				}
				logx.LogInfo(reqData, "", fmt.Sprintf("Captcha failure rate limit exceeded and blocked: IP %s window %d limit %d", ipKey, limitTime, limitCount))
				failureCounter.Reset(ipKey)
				decision.SetVerdict(action.Done, action.VerdictBlock)
				return
			}
		}
	}

	if !verifyClearanceCookie(reqData, *ruleSet) {
		failureCounter.Add(reqData.RemoteIP, 1)
		decision.SetVerdict(action.Done, action.VerdictCaptcha)
		return
	}

	decision.Set(action.Continue)

}

// CaptchaSubmission is the outcome of a client posting a CAPTCHA answer.
type CaptchaSubmission uint8

const (
	// SubmissionRejected: not a POST. The endpoint answers like any other forbidden path.
	SubmissionRejected CaptchaSubmission = iota
	// SubmissionGood: the answer is correct and the client earns a clearance.
	SubmissionGood
	// SubmissionBad: the answer is missing or wrong.
	SubmissionBad
	// SubmissionBadSession: the challenge session is missing, expired, or not the one the answer was made for.
	SubmissionBadSession
	// SubmissionUnavailable: the provider could not verify the answer. Not the client's fault, so it may retry.
	SubmissionUnavailable
)

// String returns the response body the CAPTCHA page's script expects for this outcome.
func (s CaptchaSubmission) String() string {
	switch s {
	case SubmissionGood:
		return "good"
	case SubmissionBad:
		return "bad"
	case SubmissionBadSession:
		return "badSession"
	case SubmissionUnavailable:
		return "error"
	default:
		return ""
	}
}

// CheckCaptcha verifies a submitted CAPTCHA answer and counts failures against the client.
func CheckCaptcha(r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet, rt *state.Runtime) CaptchaSubmission {
	if r.Method != "POST" {
		return SubmissionRejected
	}

	failed := func(outcome CaptchaSubmission) CaptchaSubmission {
		if failureCounter := rt.CaptchaFailureLimitCounter.Load(); failureCounter != nil {
			failureCounter.Add(reqData.RemoteIP, 1)
		} else {
			logx.LogError(reqData, "", "Captcha failure counter is not initialized, skipping captcha failure increment")
		}
		return outcome
	}

	if !hasCaptchaResponse(r, ruleSet) {
		return failed(SubmissionBad)
	}
	if !VerifySessionIDCookie(reqData, *ruleSet) {
		return failed(SubmissionBadSession)
	}

	verificationResult, err := verifyCaptchaResponse(r, reqData, ruleSet)
	if err != nil {
		logx.LogError(reqData, "", err.Error())
		return SubmissionUnavailable
	}
	switch verificationResult {
	case captchaVerificationValid:
		return SubmissionGood
	case captchaVerificationSessionMismatch:
		return failed(SubmissionBadSession)
	default:
		return failed(SubmissionBad)
	}
}
