package check

import (
	"log/slog"
	"net/http"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

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
		if failureCounter := rt.LimitersFor(reqData.Site).ChallengeFailureLimitCounter.Load(); failureCounter != nil {
			failureCounter.Add(reqData.ClientKey(), 1)
		} else {
			rt.Error(reqData, "Challenge failure counter is not initialized; the failed answer is not counted")
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
		rt.Error(reqData, "CAPTCHA answer not verified", slog.String("error", err.Error()))
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
