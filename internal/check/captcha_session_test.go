package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"testing"
	"time"
)

func TestGenSessionIDReusesValidSessionForEveryProvider(t *testing.T) {
	providers := []config.ChallengeMode{config.ChallengeAltcha, config.ChallengeHCaptcha}

	for _, provider := range providers {
		t.Run(string(provider), func(t *testing.T) {
			ruleSet := testCaptchaSessionRuleSet(provider)
			reqData := testCaptchaSessionRequestData()
			reqData.ToriiSessionID = genSessionIDAt(reqData, *ruleSet, time.Now().Add(-time.Second).Unix())

			got := string(GenSessionID(reqData, *ruleSet))
			if got != reqData.ToriiSessionID {
				t.Fatalf("GenSessionID replaced valid session: got %q, want %q", got, reqData.ToriiSessionID)
			}
		})
	}
}

func TestGenSessionIDReplacesInvalidSession(t *testing.T) {
	ruleSet := testCaptchaSessionRuleSet(config.ChallengeAltcha)
	reqData := testCaptchaSessionRequestData()
	expiredAt := time.Now().Add(-ruleSet.Challenge.SessionTTL - time.Second)

	tests := []struct {
		name      string
		sessionID string
	}{
		{name: "missing"},
		{name: "malformed", sessionID: "invalid"},
		{name: "expired", sessionID: genSessionIDAt(reqData, *ruleSet, expiredAt.Unix())},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testReqData := reqData
			testReqData.ToriiSessionID = tt.sessionID

			got := string(GenSessionID(testReqData, *ruleSet))
			if got == "" || got == tt.sessionID {
				t.Fatalf("GenSessionID did not replace %s session %q", tt.name, tt.sessionID)
			}

			testReqData.ToriiSessionID = got
			if !VerifySessionIDCookie(testReqData, *ruleSet) {
				t.Fatalf("GenSessionID returned an invalid replacement session: %q", got)
			}
		})
	}
}

func testCaptchaSessionRuleSet(mode config.ChallengeMode) *config.RuleSet {
	return &config.RuleSet{
		Challenge: &config.ChallengeRule{
			Mode:       mode,
			CookieKey:  "1234567890abcdef",
			SessionTTL: 120 * time.Second,
		},
	}
}

func testCaptchaSessionRequestData() request.UserRequest {
	return request.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
}

func genSessionIDAt(reqData request.UserRequest, ruleSet config.RuleSet, timestamp int64) string {
	return challengeSigner(ruleSet, "SESSION").Sign(reqData.Host, GetClearanceUserAgent(reqData.UserAgent), time.Unix(timestamp, 0))
}

// A challenge says why a clearance the client did send was refused; a client without one, the
// usual case, gets no note.
func TestChallengeNotesWhyAClearanceWasRefused(t *testing.T) {
	ruleSet := testCaptchaSessionRuleSet(config.ChallengeAltcha)
	reqData := testCaptchaSessionRequestData()
	valid := string(GenClearance(reqData, *ruleSet))
	elsewhere := reqData
	elsewhere.Host = "other.example"

	for _, tt := range []struct {
		name      string
		req       request.UserRequest
		clearance string
		verdict   action.Verdict
		note      string
	}{
		{"valid", reqData, valid, action.VerdictAllow, ""},
		{"none", reqData, "", action.VerdictChallenge, ""},
		{"malformed", reqData, "nonsense", action.VerdictChallenge, "clearance malformed"},
		{"of another host", elsewhere, valid, action.VerdictChallenge, "clearance not signed for this site, host and browser"},
	} {
		tt.req.ToriiClearance = tt.clearance
		decision := action.NewDecision()
		Challenge(tt.req, ruleSet, decision, &state.Runtime{})
		if decision.Verdict != tt.verdict || decision.Note != tt.note {
			t.Errorf("%s: verdict %v note %q, want %v %q", tt.name, decision.Verdict, decision.Note, tt.verdict, tt.note)
		}
	}

	// The note of the check that asked for the challenge is kept.
	reqData.ToriiClearance = "nonsense"
	decision := action.NewDecision()
	decision.Note = "country=US"
	Challenge(reqData, ruleSet, decision, &state.Runtime{})
	if decision.Note != "country=US" {
		t.Errorf("note = %q, want the one of the earlier check", decision.Note)
	}
}
