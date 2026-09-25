package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"server_torii/internal/dataType"
	"strings"

	"gopkg.in/yaml.v3"
)

// decodeServerRules keeps YAML decoding at the configuration loading boundary.
func decodeServerRules(data []byte) (ruleSetWrapper, error) {
	var wrapper ruleSetWrapper
	err := yaml.Unmarshal(data, &wrapper)
	return wrapper, err
}

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := RuleSet{
		IPAllowRule:                 &dataType.IPAllowRule{Trie: &dataType.TrieNode{}},
		IPBlockRule:                 &dataType.IPBlockRule{Trie: &dataType.TrieNode{}},
		IPCAPTCHARule:               &dataType.IPCAPTCHARule{Trie: &dataType.TrieNode{}},
		URLAllowRule:                &dataType.URLAllowRule{List: &dataType.URLRuleList{}},
		URLBlockRule:                &dataType.URLBlockRule{List: &dataType.URLRuleList{}},
		URLCAPTCHARule:              &dataType.URLCAPTCHARule{List: &dataType.URLRuleList{}},
		CAPTCHARule:                 &dataType.CaptchaRule{},
		VerifyBotRule:               &dataType.VerifyBotRule{},
		HTTPFloodRule:               &dataType.HTTPFloodRule{},
		ExternalMigrationRule:       &dataType.ExternalMigrationRule{},
		AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{},
		CountryRule:                 &dataType.CountryRule{DefaultAction: dataType.CountryContinue, UnknownAction: dataType.CountryContinue, Countries: make(map[string]dataType.CountryAction)},
	}

	// Load IP Allow List
	ipAllowFile := filepath.Join(rulePath, "IP_AllowList.conf")
	if err := loadIPRules(ipAllowFile, rs.IPAllowRule.Trie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := filepath.Join(rulePath, "IP_BlockList.conf")
	if err := loadIPRules(ipBlockFile, rs.IPBlockRule.Trie); err != nil {
		return nil, err
	}

	// Load IP CAPTCHA List (optional when disabled).
	ipCaptchaFile := filepath.Join(rulePath, "IP_CAPTCHAList.conf")
	ipCaptchaErr := loadIPRules(ipCaptchaFile, rs.IPCAPTCHARule.Trie)
	if ipCaptchaErr != nil && !os.IsNotExist(ipCaptchaErr) {
		return nil, fmt.Errorf("IPCAPTCHA list: %w", ipCaptchaErr)
	}

	// Load URL Allow List
	urlAllowFile := filepath.Join(rulePath, "URL_AllowList.conf")
	if err := loadURLRules(urlAllowFile, rs.URLAllowRule.List); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := filepath.Join(rulePath, "URL_BlockList.conf")
	if err := loadURLRules(urlBlockFile, rs.URLBlockRule.List); err != nil {
		return nil, err
	}

	// Load URL CAPTCHA List (optional when disabled).
	urlCaptchaFile := filepath.Join(rulePath, "URL_CAPTCHAList.conf")
	urlCaptchaErr := loadURLRules(urlCaptchaFile, rs.URLCAPTCHARule.List)
	if urlCaptchaErr != nil && !os.IsNotExist(urlCaptchaErr) {
		return nil, fmt.Errorf("URLCAPTCHA list: %w", urlCaptchaErr)
	}

	YAMLFile := filepath.Join(rulePath, "Server.yml")
	if err := loadServerRules(YAMLFile, &rs); err != nil {
		return nil, err
	}
	if ipCaptchaErr != nil && rs.IPCAPTCHARule.Enabled {
		return nil, fmt.Errorf("IPCAPTCHA list: %w", ipCaptchaErr)
	}
	if urlCaptchaErr != nil && rs.URLCAPTCHARule.Enabled {
		return nil, fmt.Errorf("URLCAPTCHA list: %w", urlCaptchaErr)
	}

	return &rs, nil
}

func loadServerRules(YAMLFile string, rs *RuleSet) error {
	yamlData, err := os.ReadFile(YAMLFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("[ERROR] rules file %s does not exist: %w", YAMLFile, err)
		} else {
			return fmt.Errorf("[ERROR] failed to read rules file %s: %w", YAMLFile, err)
		}
	}

	wrapper, err := decodeServerRules(yamlData)
	if err != nil {
		return fmt.Errorf("[ERROR] failed to parse rules file %s: %w", YAMLFile, err)
	}

	if rs.IPCAPTCHARule == nil {
		rs.IPCAPTCHARule = &dataType.IPCAPTCHARule{Trie: &dataType.TrieNode{}}
	}
	if rs.URLCAPTCHARule == nil {
		rs.URLCAPTCHARule = &dataType.URLCAPTCHARule{List: &dataType.URLRuleList{}}
	}

	if wrapper.IPAllowRule != nil {
		validateConfiguration(wrapper.IPAllowRule, "IPAllowRule")
		rs.IPAllowRule.Enabled = wrapper.IPAllowRule.Enabled
	}
	if wrapper.IPBlockRule != nil {
		validateConfiguration(wrapper.IPBlockRule, "IPBlockRule")
		rs.IPBlockRule.Enabled = wrapper.IPBlockRule.Enabled
	}
	if wrapper.IPCAPTCHARule != nil {
		rs.IPCAPTCHARule.Enabled = wrapper.IPCAPTCHARule.Enabled
	}
	if wrapper.URLAllowRule != nil {
		validateConfiguration(wrapper.URLAllowRule, "URLAllowRule")
		rs.URLAllowRule.Enabled = wrapper.URLAllowRule.Enabled
	}
	if wrapper.URLCAPTCHARule != nil {
		rs.URLCAPTCHARule.Enabled = wrapper.URLCAPTCHARule.Enabled
	}
	if wrapper.URLBlockRule != nil {
		validateConfiguration(wrapper.URLBlockRule, "URLBlockRule")
		rs.URLBlockRule.Enabled = wrapper.URLBlockRule.Enabled
	}
	if err := validateListCaptchaDependencies(wrapper.CAPTCHARule, rs); err != nil {
		return err
	}
	if wrapper.CAPTCHARule != nil {
		if err := mapCaptchaRule(wrapper.CAPTCHARule, rs.CAPTCHARule); err != nil {
			return err
		}
	}
	if wrapper.VerifyBotRule != nil {
		validateConfiguration(wrapper.VerifyBotRule, "VerifyBotRule")
		*rs.VerifyBotRule = *wrapper.VerifyBotRule
	}
	if wrapper.ExternalMigrationRule != nil {
		validateConfiguration(wrapper.ExternalMigrationRule, "ExternalMigrationRule")
		*rs.ExternalMigrationRule = *wrapper.ExternalMigrationRule
	}
	if wrapper.AdaptiveTrafficAnalyzerRule != nil {
		mapAdaptiveTrafficAnalyzerRule(wrapper.AdaptiveTrafficAnalyzerRule, rs.AdaptiveTrafficAnalyzerRule)
	}
	if wrapper.CountryRule != nil {
		if err := mapCountryRule(wrapper.CountryRule, rs.CountryRule); err != nil {
			return err
		}
	}

	if countryRequiresCaptcha(rs.CountryRule) {
		if wrapper.CAPTCHARule == nil {
			return fmt.Errorf("CountryRule captcha action requires CAPTCHA configuration")
		}
		if err := validate.Struct(wrapper.CAPTCHARule); err != nil {
			return fmt.Errorf("CountryRule requires valid CAPTCHA configuration: %w", err)
		}
	}

	if err := mapHTTPFloodRule(&wrapper.HTTPFloodRule, rs.HTTPFloodRule); err != nil {
		return err
	}
	return nil
}

// validateListCaptchaDependencies keeps dependency checks separate from rule mapping.
func validateListCaptchaDependencies(captcha *captchaRuleWrapper, rs *RuleSet) error {
	for _, dependency := range []struct {
		name     string
		required bool
	}{
		{"IPCAPTCHA", rs.IPCAPTCHARule.Enabled || !rs.IPCAPTCHARule.Trie.IsEmpty()},
		{"URLCAPTCHA", rs.URLCAPTCHARule.Enabled || (rs.URLCAPTCHARule.List != nil && rs.URLCAPTCHARule.List.Head != nil)},
	} {
		if !dependency.required {
			continue
		}
		if captcha == nil {
			return fmt.Errorf("%s requires CAPTCHA configuration", dependency.name)
		}
		if err := validate.Struct(captcha); err != nil {
			return fmt.Errorf("%s requires valid CAPTCHA configuration: %w", dependency.name, err)
		}
	}
	return nil
}

// loadIPRules read the IP rule file and insert the rules into the trie
func loadIPRules(filePath string, trie *dataType.TrieNode) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		var err = file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		if !strings.Contains(line, "/") {
			line = line + "/32"
		}
		_, ipNet, err := net.ParseCIDR(line)
		if err != nil {
			continue
		}
		trie.Insert(ipNet)
	}

	return scanner.Err()
}

// loadURLRules Load URL rules from the specified file
func loadURLRules(filePath string, list *dataType.URLRuleList) error {
	file, err := os.Open(filePath)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		var err = file.Close()
		if err != nil {

		}
	}(file)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		// check if the line is a regex
		isRegex := false
		if strings.HasPrefix(line, "^") || strings.HasSuffix(line, "$") || strings.ContainsAny(line, ".*+?()[]{}|\\") {
			isRegex = true
		}
		var compiled *regexp.Regexp
		if isRegex {
			compiled, err = regexp.Compile(line)
			if err != nil {
				// skip invalid regex
				continue
			}
		}
		rule := &dataType.URLRule{
			Pattern: line,
			IsRegex: isRegex,
			Regex:   compiled,
		}
		list.Append(rule)
	}

	return scanner.Err()
}

// LoadSiteRules loads all site-specific rules and returns a map
func LoadSiteRules(cfg *MainConfig) (map[string]*RuleSet, error) {
	siteRules := make(map[string]*RuleSet)

	// Check if any sites are configured
	if len(cfg.Sites) == 0 {
		return nil, fmt.Errorf("no sites configured in torii.yml")
	}

	// Load rules for each configured site
	for _, site := range cfg.Sites {
		rules, err := LoadRules(site.RulePath)
		if err != nil {
			return nil, fmt.Errorf("failed to load rules for site %s: %w", site.Host, err)
		}
		siteRules[site.Host] = rules
	}

	// Check if default_site exists
	if _, exists := siteRules["default_site"]; !exists {
		return nil, fmt.Errorf("default_site is required but not found in configuration")
	}

	return siteRules, nil
}
