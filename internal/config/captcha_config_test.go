package config

import (
	"server_torii/internal/dataType"
	"testing"
)

func TestMapCaptchaRuleProviderDefaults(t *testing.T) {
	dest := &dataType.CaptchaRule{}
	err := mapCaptchaRule(&captchaRuleWrapper{
		Enabled:                        true,
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            60,
		CaptchaChallengeSessionTimeout: 120,
		CaptchaFailureLimit:            []string{"3/1m"},
		FailureBlockDuration:           300,
	}, dest)
	if err != nil {
		t.Fatalf("mapCaptchaRule returned unexpected error: %v", err)
	}

	if dest.Provider != DefaultCaptchaProvider {
		t.Fatalf("Provider = %q, want %q", dest.Provider, DefaultCaptchaProvider)
	}
	if dest.AltchaHMACSecret != "1234567890abcdef" {
		t.Fatalf("AltchaHMACSecret = %q, want fallback secret", dest.AltchaHMACSecret)
	}
	if dest.AltchaCost != DefaultAltchaCost {
		t.Fatalf("AltchaCost = %d, want %d", dest.AltchaCost, DefaultAltchaCost)
	}
}

func TestMapCaptchaRuleAltchaConfig(t *testing.T) {
	dest := &dataType.CaptchaRule{}
	err := mapCaptchaRule(&captchaRuleWrapper{
		Enabled:                        true,
		Provider:                       "altcha",
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            60,
		CaptchaChallengeSessionTimeout: 120,
		AltchaHMACSecret:               "altcha-secret",
		AltchaCost:                     1234,
		CaptchaFailureLimit:            []string{"3/1m"},
		FailureBlockDuration:           300,
	}, dest)
	if err != nil {
		t.Fatalf("mapCaptchaRule returned unexpected error: %v", err)
	}

	if dest.Provider != "altcha" {
		t.Fatalf("Provider = %q, want altcha", dest.Provider)
	}
	if dest.AltchaHMACSecret != "altcha-secret" {
		t.Fatalf("AltchaHMACSecret = %q, want configured secret", dest.AltchaHMACSecret)
	}
	if dest.AltchaCost != 1234 {
		t.Fatalf("AltchaCost = %d, want 1234", dest.AltchaCost)
	}
}
