package config

import (
	"strings"
	"testing"
)

func challengeWrapper(mode ChallengeMode) *challengeRuleWrapper {
	return &challengeRuleWrapper{
		Enabled:              true,
		Mode:                 mode,
		Keys:                 []string{"1234567890abcdef"},
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
		"short key":                   {func(w *challengeRuleWrapper) { w.Keys = []string{"short"} }, "Challenge.keys[0]: value must be at least 16 characters long"},
		"short second key":            {func(w *challengeRuleWrapper) { w.Keys = append(w.Keys, "short") }, "Challenge.keys[1]: value must be at least 16 characters long"},
		"no keys":                     {func(w *challengeRuleWrapper) { w.Keys = nil }, "Challenge.keys: field is required"},
		"empty keys":                  {func(w *challengeRuleWrapper) { w.Keys = []string{} }, "Challenge.keys: list needs at least 1 entry"},
		"the same key twice":          {func(w *challengeRuleWrapper) { w.Keys = append(w.Keys, w.Keys[0]) }, "Challenge.keys: entries must differ"},
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

// The first key signs, and with it everything that has a single signing key; the others only
// verify cookies that were signed before the key was replaced.
func TestMapChallengeRuleKeys(t *testing.T) {
	wrapper := challengeWrapper(ChallengeAltcha)
	wrapper.Keys = []string{"new-key-0123456789", "old-key-0123456789"}
	dest := &ChallengeRule{}
	if err := mapChallengeRule(wrapper, dest); err != nil {
		t.Fatal(err)
	}
	if len(dest.Keys) != 2 || dest.SigningKey() != "new-key-0123456789" || dest.AltchaHMACSecret != "new-key-0123456789" {
		t.Fatalf("rule = %+v", dest)
	}
	if (&ChallengeRule{}).SigningKey() != "" {
		t.Error("a rule without keys has a signing key")
	}
}

func TestOldSecretKeyIsRejected(t *testing.T) {
	_, err := LoadRules(siteDirectory(t, `Challenge: {enabled: false, mode: hcaptcha, secret_key: 1234567890abcdef, clearance_ttl: 60, session_ttl: 120, failure_limit: ["3/1m"], failure_block_duration: 60}`))
	if err == nil || !strings.Contains(err.Error(), `unknown field "secret_key"`) {
		t.Fatalf("error = %v", err)
	}
}
