package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func TestCheckToriiAltchaChallengeEndpoint(t *testing.T) {
	ruleSet := &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			Provider:                       check.CaptchaProviderAltcha,
			SecretKey:                      "1234567890abcdef",
			CaptchaChallengeSessionTimeout: 120,
			AltchaHMACSecret:               "altcha-secret",
			AltchaCost:                     1,
		},
	}
	cfg := &config.MainConfig{WebPath: "/torii"}
	reqData := dataType.UserRequest{
		RemoteIP:  "127.0.0.1",
		Uri:       "/torii/captcha/challenge",
		Host:      "example.com",
		UserAgent: "test-agent",
	}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
	req := httptest.NewRequest(http.MethodGet, "/torii/captcha/challenge", nil)
	rec := httptest.NewRecorder()

	CheckTorii(rec, req, reqData, ruleSet, cfg, &dataType.SharedMemory{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d, body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}

	var challenge altcha.Challenge
	if err := json.Unmarshal(rec.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("challenge response is not valid JSON: %v", err)
	}
	if challenge.Parameters.Algorithm != "PBKDF2/SHA-512" {
		t.Fatalf("challenge algorithm = %q, want PBKDF2/SHA-512", challenge.Parameters.Algorithm)
	}
	if challenge.Parameters.Cost != 1 {
		t.Fatalf("challenge cost = %d, want 1", challenge.Parameters.Cost)
	}
	if challenge.Signature == "" {
		t.Fatal("challenge signature is empty")
	}
	if binding, ok := challenge.Parameters.Data["toriiSession"].(string); !ok || binding == "" {
		t.Fatal("challenge session binding is empty")
	}
}

func TestCheckToriiAltchaChallengeEndpointRejectsMissingSession(t *testing.T) {
	ruleSet := &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			Provider:                       check.CaptchaProviderAltcha,
			SecretKey:                      "1234567890abcdef",
			CaptchaChallengeSessionTimeout: 120,
			AltchaHMACSecret:               "altcha-secret",
			AltchaCost:                     1,
		},
	}
	cfg := &config.MainConfig{WebPath: "/torii"}
	reqData := dataType.UserRequest{
		RemoteIP: "127.0.0.1",
		Uri:      "/torii/captcha/challenge",
	}
	req := httptest.NewRequest(http.MethodGet, "/torii/captcha/challenge", nil)
	rec := httptest.NewRecorder()

	CheckTorii(rec, req, reqData, ruleSet, cfg, &dataType.SharedMemory{})

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
