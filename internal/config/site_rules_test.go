package config

import (
	"server_torii/internal/dataType"
	"testing"
)

func TestGetSiteRules_ExactMatch(t *testing.T) {
	rs := &RuleSet{IPAllowRule: &dataType.IPAllowRule{Enabled: true}}
	siteRules := map[string]*RuleSet{
		"example.com":  rs,
		"default_site": {IPAllowRule: &dataType.IPAllowRule{Enabled: false}},
	}

	got := GetSiteRules(siteRules, "example.com")
	if got != rs {
		t.Error("expected exact match for example.com")
	}
}

func TestGetSiteRules_WildcardMatch(t *testing.T) {
	wildcard := &RuleSet{IPAllowRule: &dataType.IPAllowRule{Enabled: true}}
	siteRules := map[string]*RuleSet{
		"*.example.com": wildcard,
		"default_site":  {IPAllowRule: &dataType.IPAllowRule{Enabled: false}},
	}

	got := GetSiteRules(siteRules, "sub.example.com")
	if got != wildcard {
		t.Error("expected wildcard match for sub.example.com")
	}
}

func TestGetSiteRules_DefaultFallback(t *testing.T) {
	def := &RuleSet{IPAllowRule: &dataType.IPAllowRule{Enabled: true}}
	siteRules := map[string]*RuleSet{
		"default_site": def,
	}

	got := GetSiteRules(siteRules, "unknown.com")
	if got != def {
		t.Error("expected default_site fallback for unknown.com")
	}
}

func TestGetSiteRules_NoMatch(t *testing.T) {
	siteRules := map[string]*RuleSet{
		"example.com": {},
	}

	got := GetSiteRules(siteRules, "unknown.com")
	if got != nil {
		t.Error("expected nil when no match and no default_site")
	}
}

func TestGetSiteRules_WildcardPriority(t *testing.T) {
	exact := &RuleSet{IPAllowRule: &dataType.IPAllowRule{Enabled: true}}
	wildcard := &RuleSet{IPAllowRule: &dataType.IPAllowRule{Enabled: false}}
	siteRules := map[string]*RuleSet{
		"sub.example.com": exact,
		"*.example.com":   wildcard,
		"default_site":    {},
	}

	got := GetSiteRules(siteRules, "sub.example.com")
	if got != exact {
		t.Error("exact match should take priority over wildcard")
	}
}
