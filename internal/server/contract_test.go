package server

import (
	"net/http/httptest"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/request"
	"server_torii/internal/rules"
	"strings"
	"testing"
)

// The feature control header is part of the nginx-facing interface: position N of the header
// switches the feature below, whatever order the checks run in.
func TestFeatureControlContract(t *testing.T) {
	features := []struct {
		name   string
		mask   uint16
		enable func(*config.RuleSet)
	}{
		{"IPAllow", request.FeatureIPAllow, func(rs *config.RuleSet) { rs.IPAllowRule.Enabled = true }},
		{"IPBlock", request.FeatureIPBlock, func(rs *config.RuleSet) { rs.IPBlockRule.Enabled = true }},
		{"URLAllow", request.FeatureURLAllow, func(rs *config.RuleSet) { rs.URLAllowRule.Enabled = true }},
		{"URLBlock", request.FeatureURLBlock, func(rs *config.RuleSet) { rs.URLBlockRule.Enabled = true }},
		{"VerifyBot", request.FeatureVerifyBot, func(rs *config.RuleSet) { rs.VerifyBotRule.Enabled = true }},
		{"HTTPFlood", request.FeatureHTTPFlood, func(rs *config.RuleSet) { rs.HTTPFloodRule.Enabled = true }},
		{"Captcha", request.FeatureCaptcha, func(rs *config.RuleSet) { rs.CAPTCHARule.Enabled = true }},
		{"ExternalMigration", request.FeatureExternalMigration, func(rs *config.RuleSet) { rs.ExternalMigrationRule.Enabled = true }},
		{"CountryRule", request.FeatureCountryRule, func(rs *config.RuleSet) { rs.CountryRule.Enabled = true }},
		{"IPCAPTCHA", request.FeatureIPCAPTCHA, func(rs *config.RuleSet) { rs.IPCAPTCHARule = &config.IPListRule{Enabled: true} }},
		{"URLCAPTCHA", request.FeatureURLCAPTCHA, func(rs *config.RuleSet) { rs.URLCAPTCHARule = &config.URLListRule{Enabled: true} }},
		{"CustomRules", request.FeatureCustomRules, func(rs *config.RuleSet) { rs.CustomRules = &rules.CustomRules{Enabled: true} }},
	}
	cfg := &config.MainConfig{ConnectingFeatureControlHeaders: []string{"X-Features"}}
	allOff := func() *config.RuleSet {
		rs := featureControlRuleSet()
		rs.CountryRule.Enabled = false
		return rs
	}
	control := func(rs *config.RuleSet, header string) uint16 {
		req := httptest.NewRequest("GET", "/", nil)
		if header != "" {
			req.Header.Set("X-Features", header)
		}
		return processFeatureControl(cfg, req, rs)
	}

	if got := control(allOff(), ""); got != 0 {
		t.Fatalf("nothing enabled: bits %b", got)
	}
	all := uint16(0)
	for position, f := range features {
		if f.mask != 1<<position {
			t.Errorf("%s mask = %b, want bit %d", f.name, f.mask, position)
		}
		all |= f.mask

		// Enabled in the site configuration, no header.
		rs := allOff()
		f.enable(rs)
		if got := control(rs, ""); got != f.mask {
			t.Errorf("%s enabled in config: bits %b, want %b", f.name, got, f.mask)
		}
		// Forced off by the header.
		if got := control(rs, strings.Repeat("_", position)+"0"); got != 0 {
			t.Errorf("%s forced off: bits %b", f.name, got)
		}
		// Forced on by the header.
		if got := control(allOff(), strings.Repeat("_", position)+"1"); got != f.mask {
			t.Errorf("%s forced on: bits %b, want %b", f.name, got, f.mask)
		}
	}
	if got := control(allOff(), strings.Repeat("1", 16)); got&all != all {
		t.Errorf("all forced on: bits %b", got)
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
