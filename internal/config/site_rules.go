package config

import (
	"server_torii/internal/action"
	"server_torii/internal/feature"
	"server_torii/internal/rules"
)

// RuleSet stores all rules for a single site.
type RuleSet struct {
	// ID is the site's ID from torii.yml. Runtime state that belongs to the site (rate counters,
	// temporary action rules, log files, traffic analysis) is kept under it.
	ID string

	Lists                       *ListSet
	Challenge                   *ChallengeRule
	VerifyBotRule               *VerifyBotRule
	BrowserIntegrity            *BrowserIntegrityRule
	HTTPFloodRule               *HTTPFloodRule
	AdaptiveTrafficAnalyzerRule *AdaptiveTrafficAnalyzerRule
	CountryRule                 *CountryRule
	CustomRules                 *rules.CustomRules
}

// NewRuleSet returns a rule set with every rule present, disabled and empty, for the loader to
// fill from the site's files. Code that reads a loaded site never meets a nil rule.
func NewRuleSet() *RuleSet {
	return &RuleSet{
		Lists:                       NewListSet(),
		Challenge:                   &ChallengeRule{},
		VerifyBotRule:               &VerifyBotRule{},
		BrowserIntegrity:            &BrowserIntegrityRule{Action: action.ActionObserve},
		HTTPFloodRule:               &HTTPFloodRule{},
		AdaptiveTrafficAnalyzerRule: &AdaptiveTrafficAnalyzerRule{},
		CountryRule:                 &CountryRule{DefaultAction: action.ActionContinue, UnknownAction: action.ActionContinue, Countries: make(map[string]action.Action)},
		CustomRules:                 &rules.CustomRules{},
	}
}

// FeatureEnabled reports whether the site's configuration turns the check on.
// The feature control header can still override it per request.
func (rs *RuleSet) FeatureEnabled(c feature.Check) bool {
	switch c {
	case feature.CustomRules:
		return rs.CustomRules != nil && rs.CustomRules.Enabled
	case feature.CountryRule:
		return rs.CountryRule != nil && rs.CountryRule.Enabled
	case feature.VerifyBot:
		return rs.VerifyBotRule != nil && rs.VerifyBotRule.Enabled
	case feature.BrowserIntegrity:
		return rs.BrowserIntegrity != nil && rs.BrowserIntegrity.Enabled
	case feature.HTTPFlood:
		return rs.HTTPFloodRule != nil && rs.HTTPFloodRule.Enabled
	case feature.Challenge:
		return rs.Challenge != nil && rs.Challenge.Enabled
	default:
		// Lists and ActionRule have no switch: every list has its own, and ActionRule is driven
		// by the rules other components install at runtime.
		return false
	}
}
