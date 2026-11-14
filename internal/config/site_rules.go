package config

import (
	"server_torii/internal/feature"
	"server_torii/internal/iptrie"
	"server_torii/internal/rules"
	"server_torii/internal/urllist"
)

// RuleSet stores all rules for a single site.
type RuleSet struct {
	// ID is the site's ID from torii.yml. Runtime state that belongs to the site (rate counters,
	// temporary action rules, log files, traffic analysis) is kept under it.
	ID string

	IPAllowRule                 *IPListRule
	IPBlockRule                 *IPListRule
	URLAllowRule                *URLListRule
	URLBlockRule                *URLListRule
	IPCAPTCHARule               *IPListRule
	URLCAPTCHARule              *URLListRule
	CAPTCHARule                 *CaptchaRule
	VerifyBotRule               *VerifyBotRule
	HTTPFloodRule               *HTTPFloodRule
	ExternalMigrationRule       *ExternalMigrationRule
	AdaptiveTrafficAnalyzerRule *AdaptiveTrafficAnalyzerRule
	CountryRule                 *CountryRule
	CustomRules                 *rules.CustomRules
}

// NewRuleSet returns a rule set with every rule present, disabled and empty, so code that reads
// a loaded site never meets a nil rule.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		IPAllowRule:                 &IPListRule{Trie: &iptrie.TrieNode{}},
		IPBlockRule:                 &IPListRule{Trie: &iptrie.TrieNode{}},
		IPCAPTCHARule:               &IPListRule{Trie: &iptrie.TrieNode{}},
		URLAllowRule:                &URLListRule{List: &urllist.URLRuleList{}},
		URLBlockRule:                &URLListRule{List: &urllist.URLRuleList{}},
		URLCAPTCHARule:              &URLListRule{List: &urllist.URLRuleList{}},
		CAPTCHARule:                 &CaptchaRule{},
		VerifyBotRule:               &VerifyBotRule{},
		HTTPFloodRule:               &HTTPFloodRule{},
		ExternalMigrationRule:       &ExternalMigrationRule{},
		AdaptiveTrafficAnalyzerRule: &AdaptiveTrafficAnalyzerRule{},
		CountryRule:                 &CountryRule{DefaultAction: CountryContinue, UnknownAction: CountryContinue, Countries: make(map[string]CountryAction)},
		CustomRules:                 &rules.CustomRules{},
	}
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
