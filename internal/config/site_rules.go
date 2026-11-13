package config

import (
	"server_torii/internal/feature"
	"server_torii/internal/rules"
	"strings"
)

// RuleSet stores all rules for a single site.
type RuleSet struct {
	IPAllowRule                 *IPAllowRule
	IPBlockRule                 *IPBlockRule
	URLAllowRule                *URLAllowRule
	URLBlockRule                *URLBlockRule
	IPCAPTCHARule               *IPCAPTCHARule
	URLCAPTCHARule              *URLCAPTCHARule
	CAPTCHARule                 *CaptchaRule
	VerifyBotRule               *VerifyBotRule
	HTTPFloodRule               *HTTPFloodRule
	ExternalMigrationRule       *ExternalMigrationRule
	AdaptiveTrafficAnalyzerRule *AdaptiveTrafficAnalyzerRule
	CountryRule                 *CountryRule
	CustomRules                 *rules.CustomRules
}

// GetSiteRules returns the rules for a specific host.
func GetSiteRules(siteRules map[string]*RuleSet, host string) *RuleSet {
	if ruleSet, ok := siteRules[host]; ok {
		return ruleSet
	}

	// Check for wildcard match (e.g., *.example.com)
	parts := strings.Split(host, ".")
	if len(parts) > 1 {
		wildcardHost := "*." + strings.Join(parts[1:], ".")
		if ruleSet, ok := siteRules[wildcardHost]; ok {
			return ruleSet
		}
	}

	// Return default site rules
	if ruleSet, ok := siteRules["default_site"]; ok {
		return ruleSet
	}

	return nil
}

// FeatureEnabled reports whether the site's configuration turns the check on.
// The feature control header can still override it per request.
func (rs *RuleSet) FeatureEnabled(c feature.Check) bool {
	switch c {
	case feature.IPAllow:
		return rs.IPAllowRule != nil && rs.IPAllowRule.Enabled
	case feature.IPBlock:
		return rs.IPBlockRule != nil && rs.IPBlockRule.Enabled
	case feature.URLAllow:
		return rs.URLAllowRule != nil && rs.URLAllowRule.Enabled
	case feature.URLBlock:
		return rs.URLBlockRule != nil && rs.URLBlockRule.Enabled
	case feature.CustomRules:
		return rs.CustomRules != nil && rs.CustomRules.Enabled
	case feature.IPCAPTCHA:
		return rs.IPCAPTCHARule != nil && rs.IPCAPTCHARule.Enabled
	case feature.URLCAPTCHA:
		return rs.URLCAPTCHARule != nil && rs.URLCAPTCHARule.Enabled
	case feature.CountryRule:
		return rs.CountryRule != nil && rs.CountryRule.Enabled
	case feature.VerifyBot:
		return rs.VerifyBotRule != nil && rs.VerifyBotRule.Enabled
	case feature.HTTPFlood:
		return rs.HTTPFloodRule != nil && rs.HTTPFloodRule.Enabled
	case feature.ExternalMigration:
		return rs.ExternalMigrationRule != nil && rs.ExternalMigrationRule.Enabled
	case feature.Captcha:
		return rs.CAPTCHARule != nil && rs.CAPTCHARule.Enabled
	default:
		// ActionRule has no switch: it is driven by the rules other components install at runtime.
		return false
	}
}
