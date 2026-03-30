package config

import (
	"server_torii/internal/dataType"
	"strings"
)

// RuleSet stores all rules for a single site.
type RuleSet struct {
	IPAllowRule                 *dataType.IPAllowRule
	IPBlockRule                 *dataType.IPBlockRule
	URLAllowRule                *dataType.URLAllowRule
	URLBlockRule                *dataType.URLBlockRule
	CAPTCHARule                 *dataType.CaptchaRule
	VerifyBotRule               *dataType.VerifyBotRule
	HTTPFloodRule               *dataType.HTTPFloodRule
	ExternalMigrationRule       *dataType.ExternalMigrationRule
	AdaptiveTrafficAnalyzerRule *dataType.AdaptiveTrafficAnalyzerRule
}

// GetSiteRules returns the rules for a specific host.
func GetSiteRules(siteRules map[string]*RuleSet, host string) *RuleSet {
	if rules, ok := siteRules[host]; ok {
		return rules
	}

	// Check for wildcard match (e.g., *.example.com)
	parts := strings.Split(host, ".")
	if len(parts) > 1 {
		wildcardHost := "*." + strings.Join(parts[1:], ".")
		if rules, ok := siteRules[wildcardHost]; ok {
			return rules
		}
	}

	// Return default site rules
	if rules, ok := siteRules["default_site"]; ok {
		return rules
	}

	return nil
}
