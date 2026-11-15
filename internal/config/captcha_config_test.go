package config

import (
	"server_torii/internal/ratelimit"
	"strings"
	"testing"
	"time"
)

func challengeWrapper(mode ChallengeMode) *challengeRuleWrapper {
	return &challengeRuleWrapper{
		Enabled:              true,
		Mode:                 mode,
		HCaptchaSecret:       "test-hcaptcha-secret",
		ClearanceTTL:         60 * time.Second,
		SessionTTL:           120 * time.Second,
		FailureLimit:         []string{"3/1m"},
		FailureBlockDuration: 300 * time.Second,
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
	// A CAPTCHA site configures no key of its own: its cookies are signed with the key that
	// LoadSiteRules derives from the global secret.
	if dest.ExternalSecret != "" || dest.CookieKey != "" {
		t.Fatalf("rule = %+v", dest)
	}
	if dest.AltchaCost != DefaultAltchaCost {
		t.Fatalf("AltchaCost = %d, want %d", dest.AltchaCost, DefaultAltchaCost)
	}
	if len(dest.FailureLimit) != 1 || dest.FailureLimit[0] != (ratelimit.Rate{Limit: 3, Window: 60}) {
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
	wrapper.SessionTTL = 0 * time.Second
	wrapper.RedirectURL = "https://provider.example/check"
	wrapper.ExternalSecret = "provider-secret-0123456789"
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
		"no mode":                     {func(w *challengeRuleWrapper) { w.Mode = "" }, "challenge.mode"},
		"unknown mode":                {func(w *challengeRuleWrapper) { w.Mode = "recaptcha" }, "challenge.mode"},
		"external without url":        {func(w *challengeRuleWrapper) { w.Mode = ChallengeExternal }, "challenge.redirect_url"},
		"external with bad url":       {func(w *challengeRuleWrapper) { w.Mode = ChallengeExternal; w.RedirectURL = "provider" }, "challenge.redirect_url"},
		"negative altcha cost":        {func(w *challengeRuleWrapper) { w.AltchaCost = -1 }, "challenge.altcha_cost: value must be at least 0"},
		"hcaptcha without secret":     {func(w *challengeRuleWrapper) { w.HCaptchaSecret = "" }, "challenge.hcaptcha_secret: field is required with this mode"},
		"external without secret":     {func(w *challengeRuleWrapper) { w.Mode = ChallengeExternal }, "challenge.external_secret: field is required with this mode"},
		"short external secret":       {func(w *challengeRuleWrapper) { w.ExternalSecret = "short" }, "challenge.external_secret: value must be at least 16 characters long"},
		"captcha without session ttl": {func(w *challengeRuleWrapper) { w.SessionTTL = 0 }, "challenge.session_ttl"},
		"no clearance ttl":            {func(w *challengeRuleWrapper) { w.ClearanceTTL = 0 }, "challenge.clearance_ttl"},
		"no failure limit":            {func(w *challengeRuleWrapper) { w.FailureLimit = nil }, "challenge.failure_limit"},
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
