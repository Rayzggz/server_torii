package config

import (
	"bufio"
	"fmt"
	"gopkg.in/yaml.v3"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
)

type MainConfig struct {
	Port                            string           `yaml:"port"`
	WebPath                         string           `yaml:"web_path"`
	ErrorPage                       string           `yaml:"error_page"`
	LogPath                         string           `yaml:"log_path"`
	NodeName                        string           `yaml:"node_name"`
	ConnectingHostHeaders           []string         `yaml:"connecting_host_headers"`
	ConnectingIPHeaders             []string         `yaml:"connecting_ip_headers"`
	ConnectingURIHeaders            []string         `yaml:"connecting_uri_headers"`
	ConnectingFeatureControlHeaders []string         `yaml:"connecting_feature_control_headers"`
	Sites                           []AllSiteRuleSet `yaml:"sites"`
}

// LoadMainConfig Read the configuration file and return the configuration object
func LoadMainConfig(basePath string) (*MainConfig, error) {

	defaultCfg := MainConfig{
		Port:                            "25555",
		WebPath:                         "/torii",
		ErrorPage:                       "/www/server_torii/config/error_page",
		LogPath:                         "/www/server_torii/log/",
		NodeName:                        "Server Torii",
		ConnectingHostHeaders:           []string{"Torii-Real-Host"},
		ConnectingIPHeaders:             []string{"Torii-Real-IP"},
		ConnectingURIHeaders:            []string{"Torii-Original-URI"},
		ConnectingFeatureControlHeaders: []string{"Torii-Feature-Control"},
		Sites: []AllSiteRuleSet{
			{
				Host:     "default_site",
				RulePath: "/www/server_torii/config/rules",
			},
		},
	}

	var configPath string
	var err error

	if basePath != "" {
		if strings.HasSuffix(basePath, "torii.yml") {
			configPath = basePath
		} else {
			configPath = filepath.Join(basePath, "torii.yml")
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				configPath = filepath.Join(basePath, "config", "torii.yml")
			}
		}
	} else {
		cwd, _ := os.Getwd()
		configPath = filepath.Join(cwd, "config", "torii.yml")
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return &defaultCfg, err
	}

	var cfg MainConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return &defaultCfg, err
	}

	return &cfg, nil
}

type AllSiteRuleSet struct {
	Host     string `yaml:"host"`
	RulePath string `yaml:"rule_path"`
}

// RuleSet stores all rules
type RuleSet struct {
	IPAllowTrie           *dataType.TrieNode
	IPBlockTrie           *dataType.TrieNode
	URLAllowList          *dataType.URLRuleList
	URLBlockList          *dataType.URLRuleList
	CAPTCHARule           *dataType.CaptchaRule
	VerifyBotRule         *dataType.VerifyBotRule
	HTTPFloodRule         *dataType.HTTPFloodRule
	ExternalMigrationRule *dataType.ExternalMigrationRule
}

// ruleSetWrapper
type ruleSetWrapper struct {
	CAPTCHARule           *dataType.CaptchaRule           `yaml:"CAPTCHA"`
	VerifyBotRule         *dataType.VerifyBotRule         `yaml:"VerifyBot"`
	HTTPFloodRule         httpFloodRuleWrapper            `yaml:"HTTPFlood"`
	ExternalMigrationRule *dataType.ExternalMigrationRule `yaml:"ExternalMigration"`
}

type httpFloodRuleWrapper struct {
	HTTPFloodSpeedLimit   []string `yaml:"HTTPFloodSpeedLimit"`
	HTTPFloodSameURILimit []string `yaml:"HTTPFloodSameURILimit"`
}

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := RuleSet{
		IPAllowTrie:           &dataType.TrieNode{},
		IPBlockTrie:           &dataType.TrieNode{},
		URLAllowList:          &dataType.URLRuleList{},
		URLBlockList:          &dataType.URLRuleList{},
		CAPTCHARule:           &dataType.CaptchaRule{},
		VerifyBotRule:         &dataType.VerifyBotRule{},
		HTTPFloodRule:         &dataType.HTTPFloodRule{},
		ExternalMigrationRule: &dataType.ExternalMigrationRule{},
	}

	// Load IP Allow List
	ipAllowFile := filepath.Join(rulePath, "/IP_AllowList.conf")
	if err := loadIPRules(ipAllowFile, rs.IPAllowTrie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := filepath.Join(rulePath, "/IP_BlockList.conf")
	if err := loadIPRules(ipBlockFile, rs.IPBlockTrie); err != nil {
		return nil, err
	}

	// Load URL Allow List
	urlAllowFile := filepath.Join(rulePath, "/URL_AllowList.conf")
	if err := loadURLRules(urlAllowFile, rs.URLAllowList); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := filepath.Join(rulePath, "/URL_BlockList.conf")
	if err := loadURLRules(urlBlockFile, rs.URLBlockList); err != nil {
		return nil, err
	}

	YAMLFile := filepath.Join(rulePath, "Server.yml")
	if err := loadServerRules(YAMLFile, &rs); err != nil {
		return nil, err
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

	var wrapper ruleSetWrapper
	if err := yaml.Unmarshal(yamlData, &wrapper); err != nil {
		return fmt.Errorf("[ERROR] failed to parse rules file %s: %w", YAMLFile, err)
	}

	*rs.CAPTCHARule = *wrapper.CAPTCHARule
	*rs.VerifyBotRule = *wrapper.VerifyBotRule
	if wrapper.ExternalMigrationRule != nil {
		*rs.ExternalMigrationRule = *wrapper.ExternalMigrationRule
	}

	rs.HTTPFloodRule.HTTPFloodSpeedLimit = make(map[int64]int64)
	rs.HTTPFloodRule.HTTPFloodSameURILimit = make(map[int64]int64)

	for _, s := range wrapper.HTTPFloodRule.HTTPFloodSpeedLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rs.HTTPFloodRule.HTTPFloodSpeedLimit[seconds] = limit
	}

	for _, s := range wrapper.HTTPFloodRule.HTTPFloodSameURILimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rs.HTTPFloodRule.HTTPFloodSameURILimit[seconds] = limit
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

// GetSiteRules returns the rules for a specific host
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
