package config

import (
	"strings"
	"testing"
)

func challengeWrapper(mode ChallengeMode) *challengeRuleWrapper {
	return &challengeRuleWrapper{
		Enabled:              true,
		Mode:                 mode,
		SecretKey:            "1234567890abcdef",
		ClearanceTTL:         60,
		SessionTTL:           120,
		FailureLimit:         []string{"3/1m"},
		FailureBlockDuration: 300,
	}
}

func TestMapChallengeRuleDefaults(t *testing.T) {
	dest := &ChallengeRule{}
	if err := mapChallengeRule(challengeWrapper(ChallengeHCaptcha), dest); err != nil {
		t.Fatalf("mapChallengeRule returned unexpected error: %v", err)
	}
	if !dest.ShowsCaptcha() || dest.Mode != ChallengeHCaptcha {
		t.Fatalf("rule = %+v", dest)
	}
	if dest.AltchaHMACSecret != "1234567890abcdef" {
		t.Fatalf("AltchaHMACSecret = %q, want fallback secret", dest.AltchaHMACSecret)
	}
	if dest.AltchaCost != DefaultAltchaCost {
		t.Fatalf("AltchaCost = %d, want %d", dest.AltchaCost, DefaultAltchaCost)
	}
	if dest.FailureLimit[60] != 3 {
		t.Fatalf("FailureLimit = %v", dest.FailureLimit)
	}
}

func TestMapChallengeRuleAltchaConfig(t *testing.T) {
	wrapper := challengeWrapper(ChallengeAltcha)
	wrapper.AltchaHMACSecret = "altcha-secret"
	wrapper.AltchaCost = 1234
	dest := &ChallengeRule{}
	if err := mapChallengeRule(wrapper, dest); err != nil {
		t.Fatalf("mapChallengeRule returned unexpected error: %v", err)
	}
	if dest.Mode != ChallengeAltcha || dest.AltchaHMACSecret != "altcha-secret" || dest.AltchaCost != 1234 {
		t.Fatalf("rule = %+v", dest)
	}
}

// The external mode needs the address of the provider and has no CAPTCHA session to time out.
func TestMapChallengeRuleExternal(t *testing.T) {
	wrapper := challengeWrapper(ChallengeExternal)
	wrapper.SessionTTL = 0
	wrapper.RedirectURL = "https://provider.example/check"
	dest := &ChallengeRule{}
	if err := mapChallengeRule(wrapper, dest); err != nil {
		t.Fatalf("mapChallengeRule returned unexpected error: %v", err)
	}
	if dest.ShowsCaptcha() || dest.RedirectURL != "https://provider.example/check" {
		t.Fatalf("rule = %+v", dest)
	}
}

func TestMapChallengeRuleRejects(t *testing.T) {
	for name, tt := range map[string]struct {
		change func(*challengeRuleWrapper)
		want   string
	}{
		"no mode":                     {func(w *challengeRuleWrapper) { w.Mode = "" }, "Challenge.mode"},
		"unknown mode":                {func(w *challengeRuleWrapper) { w.Mode = "recaptcha" }, "Challenge.mode"},
		"external without url":        {func(w *challengeRuleWrapper) { w.Mode = ChallengeExternal }, "Challenge.redirect_url"},
		"external with bad url":       {func(w *challengeRuleWrapper) { w.Mode = ChallengeExternal; w.RedirectURL = "provider" }, "Challenge.redirect_url"},
		"captcha without session ttl": {func(w *challengeRuleWrapper) { w.SessionTTL = 0 }, "Challenge.session_ttl"},
		"short secret":                {func(w *challengeRuleWrapper) { w.SecretKey = "short" }, "Challenge.secret_key"},
		"no clearance ttl":            {func(w *challengeRuleWrapper) { w.ClearanceTTL = 0 }, "Challenge.clearance_ttl"},
		"no failure limit":            {func(w *challengeRuleWrapper) { w.FailureLimit = nil }, "Challenge.failure_limit"},
	} {
		t.Run(name, func(t *testing.T) {
			wrapper := challengeWrapper(ChallengeHCaptcha)
			tt.change(wrapper)
			err := mapChallengeRule(wrapper, &ChallengeRule{})
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one about %s", err, tt.want)
			}
		})
	}
}
