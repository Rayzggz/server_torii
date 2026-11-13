package check

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func TestCheckCaptchaAltchaGood(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := testCaptchaRequestData(ruleSet)

	form := url.Values{}
	form.Set("altcha", solveAltchaPayload(t, ruleSet, reqData))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rt := testCaptchaRuntime()

	submission := CheckCaptcha(req, reqData, ruleSet, rt)

	if submission != SubmissionGood {
		t.Fatalf("expected response good, got %s", submission)
	}
}

func TestCheckCaptchaAltchaRejectsFreshSessionReplay(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	sessionTime := time.Now()
	reqData := request.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	reqData.ToriiSessionID = genSessionIDAt(reqData, *ruleSet, sessionTime.Add(-2*time.Second).Unix())
	altchaPayload := solveAltchaPayload(t, ruleSet, reqData)

	replayReqData := reqData
	replayReqData.ToriiSessionID = genSessionIDAt(replayReqData, *ruleSet, sessionTime.Add(-time.Second).Unix())

	form := url.Values{}
	form.Set("altcha", altchaPayload)
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	counter := ratelimit.NewCounter(1, 60)
	rt := &state.Runtime{}
	rt.CaptchaFailureLimitCounter.Store(counter)

	submission := CheckCaptcha(req, replayReqData, ruleSet, rt)

	if submission != SubmissionBadSession {
		t.Fatalf("expected response badSession for fresh-session replay, got %s", submission)
	}
	if got := counter.Query(replayReqData.RemoteIP, 60); got != 1 {
		t.Fatalf("failure counter = %d, want 1", got)
	}
}

func TestCheckCaptchaAltchaRejectsTamperedSessionBinding(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	sessionTime := time.Now()
	reqData := request.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	reqData.ToriiSessionID = genSessionIDAt(reqData, *ruleSet, sessionTime.Add(-2*time.Second).Unix())
	altchaPayload := solveAltchaPayload(t, ruleSet, reqData)

	replayReqData := reqData
	replayReqData.ToriiSessionID = genSessionIDAt(replayReqData, *ruleSet, sessionTime.Add(-time.Second).Unix())

	payload := decodeAltchaPayload(t, altchaPayload)
	payload.Challenge.Parameters.Data[("toriiSession")] = altchaSessionBinding(replayReqData, *ruleSet)
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal tampered payload returned unexpected error: %v", err)
	}

	form := url.Values{}
	form.Set("altcha", base64.StdEncoding.EncodeToString(payloadBytes))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rt := testCaptchaRuntime()

	submission := CheckCaptcha(req, replayReqData, ruleSet, rt)

	if submission != SubmissionBad {
		t.Fatalf("expected response bad for tampered session binding, got %s", submission)
	}
}

func TestCheckCaptchaAltchaRejectsWrongSolution(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := testCaptchaRequestData(ruleSet)
	payload := decodeAltchaPayload(t, solveAltchaPayload(t, ruleSet, reqData))
	payload.Solution.Counter++

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("Marshal payload returned unexpected error: %v", err)
	}

	form := url.Values{}
	form.Set("altcha", base64.StdEncoding.EncodeToString(payloadBytes))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	submission := CheckCaptcha(req, reqData, ruleSet, testCaptchaRuntime())

	if submission != SubmissionBad {
		t.Fatalf("expected response bad for wrong solution, got %s", submission)
	}
}

func TestCheckCaptchaAltchaInvalidPayloadReturnsBadAndIncrementsCounter(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := testCaptchaRequestData(ruleSet)
	form := url.Values{}
	form.Set("altcha", base64.StdEncoding.EncodeToString([]byte(`{"bad":true}`)))
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	counter := ratelimit.NewCounter(1, 60)
	rt := &state.Runtime{}
	rt.CaptchaFailureLimitCounter.Store(counter)

	submission := CheckCaptcha(req, reqData, ruleSet, rt)

	if submission != SubmissionBad {
		t.Fatalf("expected response bad, got %s", submission)
	}
	if got := counter.Query(reqData.RemoteIP, 60); got != 1 {
		t.Fatalf("failure counter = %d, want 1", got)
	}
}

func TestCheckCaptchaAltchaBadSession(t *testing.T) {
	ruleSet := testAltchaRuleSet()
	reqData := request.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	form := url.Values{}
	form.Set("altcha", "payload")
	req := httptest.NewRequest("POST", "/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rt := testCaptchaRuntime()

	submission := CheckCaptcha(req, reqData, ruleSet, rt)

	if submission != SubmissionBadSession {
		t.Fatalf("expected response badSession, got %s", submission)
	}
}

func testAltchaRuleSet() *config.RuleSet {
	ruleSet := &config.RuleSet{
		CAPTCHARule: &config.CaptchaRule{
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

func testCaptchaRequestData(ruleSet *config.RuleSet) request.UserRequest {
	reqData := request.UserRequest{
		RemoteIP:  "127.0.0.1",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	reqData.ToriiSessionID = string(GenSessionID(reqData, *ruleSet))
	return reqData
}

func testCaptchaRuntime() *state.Runtime {
	rt := &state.Runtime{}
	rt.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(1, 60))
	return rt
}

func solveAltchaPayload(t *testing.T, ruleSet *config.RuleSet, reqData request.UserRequest) string {
	t.Helper()

	challenge, err := GenAltchaChallenge(*ruleSet, reqData)
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

	return base64.StdEncoding.EncodeToString(payloadBytes)
}

func decodeAltchaPayload(t *testing.T, encoded string) altcha.Payload {
	t.Helper()

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString returned unexpected error: %v", err)
	}

	var payload altcha.Payload
	if err := json.Unmarshal(decoded, &payload); err != nil {
		t.Fatalf("Unmarshal payload returned unexpected error: %v", err)
	}
	return payload
}
