package check

import (
	"crypto/hmac"
	"crypto/sha512"
	"fmt"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"testing"
	"time"
)

func TestGenSessionIDReusesValidSessionForEveryProvider(t *testing.T) {
	providers := []string{
		CaptchaProviderAltcha,
		CaptchaProviderHCaptcha,
		"",
		"future-provider",
	}

	for _, provider := range providers {
		t.Run(provider, func(t *testing.T) {
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
	ruleSet := testCaptchaSessionRuleSet(CaptchaProviderAltcha)
	reqData := testCaptchaSessionRequestData()
	expiredAt := time.Now().Add(-time.Duration(ruleSet.CAPTCHARule.CaptchaChallengeSessionTimeout+1) * time.Second)

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

func testCaptchaSessionRuleSet(provider string) *config.RuleSet {
	return &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			Provider:                       provider,
			SecretKey:                      "1234567890abcdef",
			CaptchaChallengeSessionTimeout: 120,
		},
	}
}

func testCaptchaSessionRequestData() dataType.UserRequest {
	return dataType.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
}

func genSessionIDAt(reqData dataType.UserRequest, ruleSet config.RuleSet, timestamp int64) string {
	mac := hmac.New(sha512.New, []byte(ruleSet.CAPTCHARule.SecretKey))
	mac.Write([]byte(fmt.Sprintf("%d%s%sCAPTCHA-SESSION", timestamp, reqData.Host, utils.GetClearanceUserAgent(reqData.UserAgent))))
	return fmt.Sprintf("%d:%x", timestamp, mac.Sum(nil))
}
