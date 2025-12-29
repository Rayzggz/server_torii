package config

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"

	"github.com/go-playground/validator/v10"
	"gopkg.in/yaml.v3"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validation for directory paths
	err := validate.RegisterValidation("dir", validateDir)
	if err != nil {
		return
	}
}

// validateDir validates that a path is a directory
func validateDir(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// validateConfiguration validates a struct and logs warnings for validation errors
func validateConfiguration(cfg interface{}, configName string) {
	if err := validate.Struct(cfg); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, validationError := range validationErrors {
				log.Printf("[WARNING] Configuration issue in %s.%s may affect runtime: %s (current value: '%v')",
					configName,
					validationError.Field(),
					getValidationErrorMessage(validationError),
					validationError.Value())
			}
		} else {
			log.Printf("[WARNING] Configuration validation failed for %s: %v", configName, err)
		}
	}
}

// getValidationErrorMessage returns a human-readable validation error message
func getValidationErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "field is required but missing or empty"
	case "min":
		return fmt.Sprintf("value must be at least %s", fe.Param())
	case "max":
		return fmt.Sprintf("value must be at most %s", fe.Param())
	case "numeric":
		return "value must be numeric"
	case "url":
		return "value must be a valid URL"
	case "startswith":
		return fmt.Sprintf("value must start with %s", fe.Param())
	case "rate":
		return "value must be a valid rate format"
	case "dir":
		return "path must be an existing directory"
	default:
		return fmt.Sprintf("validation rule '%s' failed", fe.Tag())
	}
}

type MainConfig struct {
	Port                            string           `yaml:"port" validate:"required,numeric,min=1,max=65535"`
	WebPath                         string           `yaml:"web_path" validate:"required,startswith=/"`
	ErrorPage                       string           `yaml:"error_page" validate:"required"`
	LogPath                         string           `yaml:"log_path" validate:"required"`
	NodeName                        string           `yaml:"node_name" validate:"required"`
	ConnectingHostHeaders           []string         `yaml:"connecting_host_headers" validate:"required"`
	ConnectingIPHeaders             []string         `yaml:"connecting_ip_headers" validate:"required"`
	ConnectingURIHeaders            []string         `yaml:"connecting_uri_headers" validate:"required"`
	ConnectingFeatureControlHeaders []string         `yaml:"connecting_feature_control_headers" validate:"required"`
	Sites                           []AllSiteRuleSet `yaml:"sites" validate:"required"`
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
				RulePath: "/www/server_torii/config/rules/default",
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

	// Validate the loaded configuration
	validateConfiguration(&cfg, "MainConfig")

	return &cfg, nil
}

type AllSiteRuleSet struct {
	Host     string `yaml:"host" validate:"required,min=1"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
}

// RuleSet stores all rules
type RuleSet struct {
	IPAllowRule           *dataType.IPAllowRule
	IPBlockRule           *dataType.IPBlockRule
	URLAllowRule          *dataType.URLAllowRule
	URLBlockRule          *dataType.URLBlockRule
	CAPTCHARule           *dataType.CaptchaRule
	VerifyBotRule         *dataType.VerifyBotRule
	HTTPFloodRule         *dataType.HTTPFloodRule
	ExternalMigrationRule *dataType.ExternalMigrationRule
}

// ruleSetWrapper
type ruleSetWrapper struct {
	IPAllowRule           *dataType.IPAllowRule           `yaml:"IPAllow"`
	IPBlockRule           *dataType.IPBlockRule           `yaml:"IPBlock"`
	URLAllowRule          *dataType.URLAllowRule          `yaml:"URLAllow"`
	URLBlockRule          *dataType.URLBlockRule          `yaml:"URLBlock"`
	CAPTCHARule           *captchaRuleWrapper             `yaml:"CAPTCHA"`
	VerifyBotRule         *dataType.VerifyBotRule         `yaml:"VerifyBot"`
	HTTPFloodRule         httpFloodRuleWrapper            `yaml:"HTTPFlood"`
	ExternalMigrationRule *dataType.ExternalMigrationRule `yaml:"ExternalMigration"`
}

type httpFloodRuleWrapper struct {
	Enabled               bool     `yaml:"enabled"`
	HTTPFloodSpeedLimit   []string `yaml:"HTTPFloodSpeedLimit" validate:"required,dive"`
	HTTPFloodSameURILimit []string `yaml:"HTTPFloodSameURILimit" validate:"required,dive"`
	HTTPFloodFailureLimit []string `yaml:"HTTPFloodFailureLimit" validate:"required,dive"`
	FailureBlockDuration  int64    `yaml:"failure_block_duration" validate:"required,min=1"`
}

type captchaRuleWrapper struct {
	Enabled                        bool     `yaml:"enabled"`
	SecretKey                      string   `yaml:"secret_key" validate:"required,min=16"`
	CaptchaValidateTime            int64    `yaml:"captcha_validate_time" validate:"required,min=1,max=9223372036854775807"`
	CaptchaChallengeSessionTimeout int64    `yaml:"captcha_challenge_session_timeout" validate:"required,min=1,max=9223372036854775807"`
	HCaptchaSecret                 string   `yaml:"hcaptcha_secret" validate:"required"`
	CaptchaFailureLimit            []string `yaml:"CaptchaFailureLimit" validate:"required,dive"`
	FailureBlockDuration           int64    `yaml:"failure_block_duration" validate:"required,min=1"`
}

// LoadRules Load all rules from the specified path
func LoadRules(rulePath string) (*RuleSet, error) {
	rs := RuleSet{
		IPAllowRule:           &dataType.IPAllowRule{Trie: &dataType.TrieNode{}},
		IPBlockRule:           &dataType.IPBlockRule{Trie: &dataType.TrieNode{}},
		URLAllowRule:          &dataType.URLAllowRule{List: &dataType.URLRuleList{}},
		URLBlockRule:          &dataType.URLBlockRule{List: &dataType.URLRuleList{}},
		CAPTCHARule:           &dataType.CaptchaRule{},
		VerifyBotRule:         &dataType.VerifyBotRule{},
		HTTPFloodRule:         &dataType.HTTPFloodRule{},
		ExternalMigrationRule: &dataType.ExternalMigrationRule{},
	}

	// Load IP Allow List
	ipAllowFile := filepath.Join(rulePath, "/IP_AllowList.conf")
	if err := loadIPRules(ipAllowFile, rs.IPAllowRule.Trie); err != nil {
		return nil, err
	}

	// Load IP Block List
	ipBlockFile := filepath.Join(rulePath, "/IP_BlockList.conf")
	if err := loadIPRules(ipBlockFile, rs.IPBlockRule.Trie); err != nil {
		return nil, err
	}

	// Load URL Allow List
	urlAllowFile := filepath.Join(rulePath, "/URL_AllowList.conf")
	if err := loadURLRules(urlAllowFile, rs.URLAllowRule.List); err != nil {
		return nil, err
	}

	// Load URL Block List
	urlBlockFile := filepath.Join(rulePath, "/URL_BlockList.conf")
	if err := loadURLRules(urlBlockFile, rs.URLBlockRule.List); err != nil {
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

	if wrapper.IPAllowRule != nil {
		validateConfiguration(wrapper.IPAllowRule, "IPAllowRule")
		rs.IPAllowRule.Enabled = wrapper.IPAllowRule.Enabled
	}
	if wrapper.IPBlockRule != nil {
		validateConfiguration(wrapper.IPBlockRule, "IPBlockRule")
		rs.IPBlockRule.Enabled = wrapper.IPBlockRule.Enabled
	}
	if wrapper.URLAllowRule != nil {
		validateConfiguration(wrapper.URLAllowRule, "URLAllowRule")
		rs.URLAllowRule.Enabled = wrapper.URLAllowRule.Enabled
	}
	if wrapper.URLBlockRule != nil {
		validateConfiguration(wrapper.URLBlockRule, "URLBlockRule")
		rs.URLBlockRule.Enabled = wrapper.URLBlockRule.Enabled
	}
	if wrapper.CAPTCHARule != nil {
		validateConfiguration(wrapper.CAPTCHARule, "CAPTCHARule")
		rs.CAPTCHARule.Enabled = wrapper.CAPTCHARule.Enabled
		rs.CAPTCHARule.SecretKey = wrapper.CAPTCHARule.SecretKey
		rs.CAPTCHARule.CaptchaValidateTime = wrapper.CAPTCHARule.CaptchaValidateTime
		rs.CAPTCHARule.CaptchaChallengeSessionTimeout = wrapper.CAPTCHARule.CaptchaChallengeSessionTimeout
		rs.CAPTCHARule.HCaptchaSecret = wrapper.CAPTCHARule.HCaptchaSecret

		rs.CAPTCHARule.CaptchaFailureLimit = make(map[int64]int64)
		for _, s := range wrapper.CAPTCHARule.CaptchaFailureLimit {
			limit, seconds, err := utils.ParseRate(s)
			if err != nil {
				return err
			}
			rs.CAPTCHARule.CaptchaFailureLimit[seconds] = limit
		}
		rs.CAPTCHARule.FailureBlockDuration = wrapper.CAPTCHARule.FailureBlockDuration
	}
	if wrapper.VerifyBotRule != nil {
		validateConfiguration(wrapper.VerifyBotRule, "VerifyBotRule")
		*rs.VerifyBotRule = *wrapper.VerifyBotRule
	}
	if wrapper.ExternalMigrationRule != nil {
		validateConfiguration(wrapper.ExternalMigrationRule, "ExternalMigrationRule")
		*rs.ExternalMigrationRule = *wrapper.ExternalMigrationRule
	}

	validateConfiguration(&wrapper.HTTPFloodRule, "HTTPFloodRule")
	rs.HTTPFloodRule.Enabled = wrapper.HTTPFloodRule.Enabled
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

	rs.HTTPFloodRule.HTTPFloodFailureLimit = make(map[int64]int64)
	for _, s := range wrapper.HTTPFloodRule.HTTPFloodFailureLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		rs.HTTPFloodRule.HTTPFloodFailureLimit[seconds] = limit
	}
	rs.HTTPFloodRule.FailureBlockDuration = wrapper.HTTPFloodRule.FailureBlockDuration
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
