package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// LoadRules loads the rules of a site from its directory: Server.yml and the list files it names.
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := NewRuleSet()
	if err := loadServerRules(filepath.Join(rulePath, "Server.yml"), rs); err != nil {
		return nil, err
	}
	return rs, nil
}

// loadServerRules fills rs, which must come from NewRuleSet, from the site's Server.yml.
//
// Every section must be present, complete and valid, also the ones that are disabled: the
// connector can enable a check per request, and a rule another node shares may need a check
// this site keeps switched off. Nothing is repaired or skipped: any problem rejects the file.
func loadServerRules(YAMLFile string, rs *RuleSet) error {
	yamlData, err := os.ReadFile(YAMLFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("rules file %s does not exist: %w", YAMLFile, err)
		} else {
			return fmt.Errorf("failed to read rules file %s: %w", YAMLFile, err)
		}
	}

	var wrapper ruleSetWrapper
	if err := decodeStrict(yamlData, &wrapper); err != nil {
		return fmt.Errorf("failed to parse rules file %s: %w", YAMLFile, err)
	}
	if err := mapServerRules(&wrapper, rs, filepath.Dir(YAMLFile)); err != nil {
		return fmt.Errorf("invalid rules file %s:\n%w", YAMLFile, err)
	}
	return nil
}

// mapServerRules fills rs from a decoded Server.yml; dir is where the list files it names are.
func mapServerRules(wrapper *ruleSetWrapper, rs *RuleSet, dir string) error {
	if missing := wrapper.missingSections(); len(missing) > 0 {
		return fmt.Errorf("missing sections: %s. Every section is required; switch a check off with `enabled: false`",
			strings.Join(missing, ", "))
	}

	*rs.VerifyBotRule = *wrapper.VerifyBotRule

	// Custom rules refer to the lists, so the lists come first; without them the rules cannot
	// be checked. Everything else is checked regardless, so one load reports every problem.
	lists, listsErr := mapLists(*wrapper.Lists, dir)
	problems := []error{
		listsErr,
		mapChallengeRule(wrapper.Challenge, rs.Challenge),
		mapAdaptiveTrafficAnalyzerRule(wrapper.AdaptiveTrafficAnalyzerRule, rs.AdaptiveTrafficAnalyzerRule),
		mapCountryRule(wrapper.CountryRule, rs.CountryRule),
		mapHTTPFloodRule(wrapper.HTTPFloodRule, rs.HTTPFloodRule),
	}
	if listsErr == nil {
		rs.Lists = lists
		problems = append(problems, mapCustomRules(wrapper.CustomRules, rs.CustomRules, lists))
	}
	return errors.Join(problems...)
}

// LoadSiteRules loads the rules of every configured site, keyed by site ID.
func LoadSiteRules(cfg *MainConfig) (map[string]*RuleSet, error) {
	siteRules := make(map[string]*RuleSet)

	// Check if any sites are configured
	if len(cfg.Sites) == 0 {
		return nil, fmt.Errorf("no sites configured in torii.yml")
	}

	// Load rules for each configured site
	for i, site := range cfg.Sites {
		if !ValidSiteID(site.ID) {
			return nil, fmt.Errorf("sites[%d]: invalid id %q: use letters, digits and underscores, at most %d characters", i, site.ID, MaxSiteIDLength)
		}
		if _, exists := siteRules[site.ID]; exists {
			return nil, fmt.Errorf("sites[%d]: duplicate id %q", i, site.ID)
		}
		ruleSet, err := LoadRules(site.RulePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules for site %s: %w", site.ID, err)
		}
		ruleSet.ID = site.ID
		ruleSet.Challenge.CookieKey = cfg.CookieKey()
		if ruleSet.Challenge.AltchaHMACSecret == "" {
			ruleSet.Challenge.AltchaHMACSecret = ruleSet.Challenge.CookieKey
		}
		siteRules[site.ID] = ruleSet
	}

	if cfg.DefaultSite != "" {
		if _, exists := siteRules[cfg.DefaultSite]; !exists {
			return nil, fmt.Errorf("default_site %q is not one of the configured sites", cfg.DefaultSite)
		}
	}

	return siteRules, nil
}
