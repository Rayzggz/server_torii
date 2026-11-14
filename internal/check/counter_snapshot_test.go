package check

import (
	"net/http/httptest"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
)

func TestHTTPFloodNilCountersContinue(t *testing.T) {
	decision := action.NewDecision()
	rt := &state.Runtime{}
	ruleSet := &config.RuleSet{
		HTTPFloodRule: &config.HTTPFloodRule{
			HTTPFloodSpeedLimit:   map[int64]int64{1: 1},
			HTTPFloodSameURILimit: map[int64]int64{1: 1},
			HTTPFloodFailureLimit: map[int64]int64{1: 1},
		},
	}
	reqData := request.UserRequest{
		RemoteIP:       "127.0.0.1",
		Uri:            "/test",
		FeatureControl: feature.HTTPFlood.ControlMask(),
	}

	HTTPFlood(reqData, ruleSet, decision, rt)

	if decision.State != action.Continue {
		t.Fatalf("expected continue decision, got state=%v httpCode=%s", decision.State, decision.Verdict)
	}
}

// Without a failure counter the failure limit cannot be enforced, but the client is still challenged.
func TestChallengeNilCounterStillChallenges(t *testing.T) {
	decision := action.NewDecision()
	rt := &state.Runtime{}
	ruleSet := &config.RuleSet{
		Challenge: &config.ChallengeRule{
			CookieKey:            "1234567890abcdef",
			ClearanceTTL:         60,
			FailureLimit:         map[int64]int64{1: 1},
			FailureBlockDuration: 60,
		},
	}
	reqData := request.UserRequest{RemoteIP: "127.0.0.1"}

	Challenge(reqData, ruleSet, decision, rt)

	if decision.State != action.Done || decision.Verdict != action.VerdictChallenge {
		t.Fatalf("decision = %+v, want a challenge", decision)
	}
}

func TestCheckCaptchaNilCounterStillReturnsBad(t *testing.T) {
	rt := &state.Runtime{}
	ruleSet := &config.RuleSet{
		Challenge: &config.ChallengeRule{},
	}
	reqData := request.UserRequest{
		RemoteIP: "127.0.0.1",
	}
	req := httptest.NewRequest("POST", "/captcha", nil)

	submission := CheckCaptcha(req, reqData, ruleSet, rt)

	if submission != SubmissionBad {
		t.Fatalf("expected response bad, got %s", submission)
	}
}
