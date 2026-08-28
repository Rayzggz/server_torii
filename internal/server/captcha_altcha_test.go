package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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

func TestCheckToriiCaptchaPagePreservesValidSessionCookie(t *testing.T) {
	errorPageDir := t.TempDir()
	for _, name := range []string{"CAPTCHA_ALTCHA.html", "CAPTCHA.html"} {
		if err := os.WriteFile(filepath.Join(errorPageDir, name), []byte("captcha"), 0o600); err != nil {
			t.Fatalf("write %s fixture: %v", name, err)
		}
	}

	tests := []struct {
		name        string
		provider    string
		withSession bool
	}{
		{
			name:        "ALTCHA reuses a valid session",
			provider:    check.CaptchaProviderAltcha,
			withSession: true,
		},
		{
			name:     "ALTCHA creates a missing session",
			provider: check.CaptchaProviderAltcha,
		},
		{
			name:        "hCAPTCHA reuses a valid session",
			provider:    check.CaptchaProviderHCaptcha,
			withSession: true,
		},
		{
			name:        "future provider reuses a valid session",
			provider:    "future-provider",
			withSession: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ruleSet := captchaPageRuleSet(tt.provider)
			cfg := &config.MainConfig{WebPath: "/torii", ErrorPage: errorPageDir}
			reqData := dataType.UserRequest{
				RemoteIP:  "127.0.0.1",
				Uri:       "/torii/checker_pages/CAPTCHA",
				Host:      "example.com",
				UserAgent: "test-agent",
			}
			if tt.withSession {
				reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
			}

			req := httptest.NewRequest(http.MethodGet, "/torii/checker_pages/CAPTCHA", nil)
			rec := httptest.NewRecorder()
			CheckTorii(rec, req, reqData, ruleSet, cfg, &dataType.SharedMemory{})

			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
			}
			cookies := rec.Result().Cookies()
			var sessionCookie *http.Cookie
			for _, cookie := range cookies {
				if cookie.Name == "__torii_session_id" {
					sessionCookie = cookie
					break
				}
			}
			if sessionCookie == nil {
				t.Fatal("expected a session Set-Cookie header")
			}
			if tt.withSession && sessionCookie.Value != reqData.ToriiSessionID {
				t.Fatalf("session cookie changed: got %q, want %q", sessionCookie.Value, reqData.ToriiSessionID)
			}
			if !tt.withSession {
				cookieReqData := reqData
				cookieReqData.ToriiSessionID = sessionCookie.Value
				if !check.VerifySessionIDCookie(cookieReqData, *ruleSet) {
					t.Fatalf("new session cookie is invalid: %q", sessionCookie.Value)
				}
			}
		})
	}
}

func captchaPageRuleSet(provider string) *config.RuleSet {
	return &config.RuleSet{
		CAPTCHARule: &dataType.CaptchaRule{
			Provider:                       provider,
			SecretKey:                      "1234567890abcdef",
			CaptchaChallengeSessionTimeout: 120,
		},
	}
}
