package check

import (
	"server_torii/internal/config"
	"server_torii/internal/request"
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
	expiredAt := time.Now().Add(-time.Duration(ruleSet.Challenge.SessionTTL+1) * time.Second)

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
			Keys:       []string{"1234567890abcdef"},
			SessionTTL: 120,
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
