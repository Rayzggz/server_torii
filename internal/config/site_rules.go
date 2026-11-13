package config

import (
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
