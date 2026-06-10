package check

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
	"testing"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func TestCheckCaptchaAltchaGood(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := testCaptchaRequestData(ruleSet)

	challenge, err := GenAltchaChallenge(*ruleSet)
	if err != nil {
		t.Fatalf("GenAltchaChallenge returned unexpected error: %v", err)
	}
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{
		Challenge: challenge,
		DeriveKey: altcha.DeriveKeyPBKDF2(),
	})
	if err != nil {
		t.Fatalf("SolveChallenge returned unexpected error: %v", err)
	}
	if solution == nil {
		t.Fatal("SolveChallenge returned nil solution")
	}

	payloadBytes, err := json.Marshal(altcha.Payload{
		Challenge: challenge,
		Solution:  *solution,
	})
	if err != nil {
		t.Fatalf("Marshal payload returned unexpected error: %v", err)
	}

	form := url.Values{}
	form.Set("altcha", base64.StdEncoding.EncodeToString(payloadBytes))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	decision := action.NewDecision()
	sharedMem := &dataType.SharedMemory{}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(1, 60))

	CheckCaptcha(req, reqData, ruleSet, decision, sharedMem)

	if decision.State != action.Done {
		t.Fatalf("expected done decision, got state=%v", decision.State)
	}
	if string(decision.HTTPCode) != "200" {
		t.Fatalf("expected http code 200, got %s", decision.HTTPCode)
	}
	if string(decision.ResponseData) != "good" {
		t.Fatalf("expected response good, got %s", decision.ResponseData)
	}
}

func TestCheckCaptchaAltchaInvalidPayloadReturnsBadAndIncrementsCounter(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := testCaptchaRequestData(ruleSet)
	form := url.Values{}
	form.Set("altcha", base64.StdEncoding.EncodeToString([]byte(`{"bad":true}`)))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	decision := action.NewDecision()
	counter := dataType.NewCounter(1, 60)
	sharedMem := &dataType.SharedMemory{}
	sharedMem.CaptchaFailureLimitCounter.Store(counter)

	CheckCaptcha(req, reqData, ruleSet, decision, sharedMem)

	if string(decision.ResponseData) != "bad" {
		t.Fatalf("expected response bad, got %s", decision.ResponseData)
	}
	if got := counter.Query(reqData.RemoteIP, 60); got != 1 {
		t.Fatalf("failure counter = %d, want 1", got)
	}
}

func TestCheckCaptchaAltchaBadSession(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := dataType.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	form := url.Values{}
	form.Set("altcha", "payload")
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	decision := action.NewDecision()
	sharedMem := &dataType.SharedMemory{}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(1, 60))

	CheckCaptcha(req, reqData, ruleSet, decision, sharedMem)

	if string(decision.ResponseData) != "badSession" {
		t.Fatalf("expected response badSession, got %s", decision.ResponseData)
	}
}

func testAltchaRuleSet() *config.RuleSet {
	ruleSet := &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			Provider:                       CaptchaProviderAltcha,
			SecretKey:                      "1234567890abcdef",
			CaptchaValidateTime:            60,
			CaptchaChallengeSessionTimeout: 120,
			AltchaHMACSecret:               "altcha-secret",
			AltchaCost:                     1,
			CaptchaFailureLimit:            map[int64]int64{60: 3},
			FailureBlockDuration:           300,
		},
	}
	return ruleSet
}

func testCaptchaRequestData(ruleSet *config.RuleSet) dataType.UserRequest {
	reqData := dataType.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	reqData.ToriiSessionID = string(GenSessionID(reqData, *ruleSet))
	return reqData
}
