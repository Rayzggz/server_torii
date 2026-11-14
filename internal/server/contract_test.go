package server

import (
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/rules"
	"testing"
)

// The names in the Torii-Features header are part of the nginx-facing interface: each one
// switches the feature below, however it is capitalized or separated.
func TestFeatureNameContract(t *testing.T) {
	features := []struct {
		names  []string
		mask   uint16
		enable func(*config.RuleSet)
	}{
		{[]string{"IPAllow", "ip_allow"}, feature.IPAllow.ControlMask(), func(rs *config.RuleSet) { rs.IPAllowRule.Enabled = true }},
		{[]string{"IPBlock", "ip_block"}, feature.IPBlock.ControlMask(), func(rs *config.RuleSet) { rs.IPBlockRule.Enabled = true }},
		{[]string{"URLAllow", "url_allow"}, feature.URLAllow.ControlMask(), func(rs *config.RuleSet) { rs.URLAllowRule.Enabled = true }},
		{[]string{"URLBlock", "url_block"}, feature.URLBlock.ControlMask(), func(rs *config.RuleSet) { rs.URLBlockRule.Enabled = true }},
		{[]string{"VerifyBot", "verify_bot"}, feature.VerifyBot.ControlMask(), func(rs *config.RuleSet) { rs.VerifyBotRule.Enabled = true }},
		{[]string{"HTTPFlood", "http_flood"}, feature.HTTPFlood.ControlMask(), func(rs *config.RuleSet) { rs.HTTPFloodRule.Enabled = true }},
		{[]string{"Captcha", "CAPTCHA", "captcha"}, feature.Captcha.ControlMask(), func(rs *config.RuleSet) { rs.CAPTCHARule.Enabled = true }},
		{[]string{"ExternalMigration", "external_migration"}, feature.ExternalMigration.ControlMask(), func(rs *config.RuleSet) { rs.ExternalMigrationRule.Enabled = true }},
		{[]string{"CountryRule", "country_rule"}, feature.CountryRule.ControlMask(), func(rs *config.RuleSet) { rs.CountryRule.Enabled = true }},
		{[]string{"IPCAPTCHA", "ip_captcha"}, feature.IPCAPTCHA.ControlMask(), func(rs *config.RuleSet) { rs.IPCAPTCHARule = &config.IPListRule{Enabled: true} }},
		{[]string{"URLCAPTCHA", "url_captcha"}, feature.URLCAPTCHA.ControlMask(), func(rs *config.RuleSet) { rs.URLCAPTCHARule = &config.URLListRule{Enabled: true} }},
		{[]string{"CustomRules", "custom_rules"}, feature.CustomRules.ControlMask(), func(rs *config.RuleSet) { rs.CustomRules = &rules.CustomRules{Enabled: true} }},
	}
	allOff := func() *config.RuleSet {
		rs := featureControlRuleSet()
		rs.CountryRule.Enabled = false
		return rs
	}

	if got := featureBits(allOff(), ""); got != 0 {
		t.Fatalf("nothing enabled: bits %b", got)
	}
	seen := uint16(0)
	for _, f := range features {
		if f.mask == 0 || f.mask&(f.mask-1) != 0 || seen&f.mask != 0 {
			t.Errorf("%s: mask %b is not a distinct single bit", f.names[0], f.mask)
		}
		seen |= f.mask

		// Enabled in the site configuration, no header.
		rs := allOff()
		f.enable(rs)
		if got := featureBits(rs, ""); got != f.mask {
			t.Errorf("%s enabled in config: bits %b, want %b", f.names[0], got, f.mask)
		}
		for _, name := range f.names {
			if got := featureBits(rs, "-"+name); got != 0 {
				t.Errorf("-%s: bits %b, want forced off", name, got)
			}
			if got := featureBits(allOff(), "+"+name); got != f.mask {
				t.Errorf("+%s: bits %b, want %b", name, got, f.mask)
			}
		}
	}
}

// Skip target names are written in each site's Server.yml.
func TestSkipTargetContract(t *testing.T) {
	names := []string{"CustomRules", "IPCAPTCHA", "URLCAPTCHA", "CountryRule", "VerifyBot", "ActionRule", "HTTPFlood", "ExternalMigration", "Captcha"}
	seen := uint32(0)
	for _, name := range names {
		mask, err := feature.ParseSkipTargets([]string{name})
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if mask == 0 || mask&(mask-1) != 0 || seen&mask != 0 {
			t.Errorf("%s: mask %b is not a distinct single bit", name, mask)
		}
		seen |= mask
	}
	// These run before CustomRules, so a custom rule cannot skip them.
	for _, name := range []string{"IPAllow", "IPBlock", "URLAllow", "URLBlock", "captcha", ""} {
		if _, err := feature.ParseSkipTargets([]string{name}); err == nil {
			t.Errorf("%q accepted as a skip target", name)
		}
	}
}

func TestEveryCheckIsImplemented(t *testing.T) {
	for _, c := range feature.Pipeline() {
		if checkFuncs[c] == nil {
			t.Errorf("%s has no check function", c)
		}
	}
}
