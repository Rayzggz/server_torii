package config

import (
	"bufio"
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
	Port                           string   `yaml:"port"`
	WebPath                        string   `yaml:"web_path"`
	RulePath                       string   `yaml:"rule_path"`
	ErrorPage                      string   `yaml:"error_page"`
	LogPath                        string   `yaml:"log_path"`
	NodeName                       string   `yaml:"node_name"`
	ConnectingHostHeaders          []string `yaml:"connecting_host_headers"`
	ConnectingIPHeaders            []string `yaml:"connecting_ip_headers"`
	ConnectingURIHeaders           []string `yaml:"connecting_uri_headers"`
	ConnectingCaptchaStatusHeaders []string `yaml:"connecting_captcha_status_headers"`
}

// LoadMainConfig Read the configuration file and return the configuration object
func LoadMainConfig(basePath string) (*MainConfig, error) {

	defaultCfg := MainConfig{
		Port:                           "25555",
		WebPath:                        "/torii",
		RulePath:                       "/www/server_torii/config/rules",
		ErrorPage:                      "/www/server_torii/config/error_page",
		LogPath:                        "/www/server_torii/log/",
		NodeName:                       "Server Torii",
		ConnectingHostHeaders:          []string{"Torii-Real-Host"},
		ConnectingIPHeaders:            []string{"Torii-Real-IP"},
		ConnectingURIHeaders:           []string{"Torii-Original-URI"},
		ConnectingCaptchaStatusHeaders: []string{"Torii-Captcha-Status"},
	}

	exePath, err := os.Executable()
	if err != nil {
		return nil, err
	}
	if basePath == "" {
		basePath = filepath.Dir(exePath)
	}
	configPath := filepath.Join(basePath, "config", "torii.yml")

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

// RuleSet stores all rules
type RuleSet struct {
	IPAllowTrie   *dataType.TrieNode
	IPBlockTrie   *dataType.TrieNode
	URLAllowList  *dataType.URLRuleList
	URLBlockList  *dataType.URLRuleList
	CAPTCHARule   *dataType.CaptchaRule
	VerifyBotRule *dataType.VerifyBotRule
	HTTPFloodRule *dataType.HTTPFloodRule
}

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := RuleSet{
		IPAllowTrie:   &dataType.TrieNode{},
		IPBlockTrie:   &dataType.TrieNode{},
		URLAllowList:  &dataType.URLRuleList{},
		URLBlockList:  &dataType.URLRuleList{},
		CAPTCHARule:   &dataType.CaptchaRule{},
		VerifyBotRule: &dataType.VerifyBotRule{},
		HTTPFloodRule: &dataType.HTTPFloodRule{},
	}

	// Load IP Allow List
	ipAllowFile := rulePath + "/IP_AllowList.conf"
	if err := loadIPRules(ipAllowFile, rs.IPAllowTrie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := rulePath + "/IP_BlockList.conf"
	if err := loadIPRules(ipBlockFile, rs.IPBlockTrie); err != nil {
		return nil, err
	}

	// Load URL Allow List
	urlAllowFile := rulePath + "/URL_AllowList.conf"
	if err := loadURLRules(urlAllowFile, rs.URLAllowList); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := rulePath + "/URL_BlockList.conf"
	if err := loadURLRules(urlBlockFile, rs.URLBlockList); err != nil {
		return nil, err
	}

	// Load CAPTCHA Rule
	captchaFile := rulePath + "/CAPTCHA.yml"
	if err := loadCAPTCHARule(captchaFile, rs.CAPTCHARule); err != nil {
		return nil, err
	}

	// Load Verify Bot Rule
	verifyBotFile := rulePath + "/VerifyBot.yml"
	if err := loadVerifyBotRule(verifyBotFile, rs.VerifyBotRule); err != nil {
		return nil, err
	}

	// Load HTTP Flood Rule
	httpFloodFile := rulePath + "/HTTPFlood.yml"
	if err := loadHTTPFloodRule(httpFloodFile, rs.HTTPFloodRule); err != nil {
		return nil, err
	}

	return &rs, nil
}

func loadCAPTCHARule(file string, rule *dataType.CaptchaRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	if err := yaml.Unmarshal(data, &rule); err != nil {
		return err
	}

	return nil

}

func loadVerifyBotRule(file string, rule *dataType.VerifyBotRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return err
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

func loadHTTPFloodRule(file string, rule *dataType.HTTPFloodRule) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}

	type httpFloodRuleYAML struct {
		HTTPFloodSpeedLimit   []string `yaml:"HTTPFloodSpeedLimit"`
		HTTPFloodSameURILimit []string `yaml:"HTTPFloodSameURILimit"`
	}

	var ymlRule httpFloodRuleYAML
	err = yaml.Unmarshal(data, &ymlRule)
	if err != nil {
		return err
	}

	rule.HTTPFloodSpeedLimit = make(map[int64]int64)
	rule.HTTPFloodSameURILimit = make(map[int64]int64)

	for _, s := range ymlRule.HTTPFloodSpeedLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rule.HTTPFloodSpeedLimit[seconds] = limit
	}

	for _, s := range ymlRule.HTTPFloodSameURILimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rule.HTTPFloodSameURILimit[seconds] = limit
	}

	return nil

}
