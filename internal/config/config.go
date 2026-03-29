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
var GlobalConfig *MainConfig

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
	GlobalSecret                    string           `yaml:"global_secret" validate:"required,min=32"`
	NodeName                        string           `yaml:"node_name" validate:"required"`
	EnableGossip                    bool             `yaml:"enable_gossip"`
	ConnectingHostHeaders           []string         `yaml:"connecting_host_headers" validate:"required"`
	ConnectingIPHeaders             []string         `yaml:"connecting_ip_headers" validate:"required"`
	ConnectingURIHeaders            []string         `yaml:"connecting_uri_headers" validate:"required"`
	ConnectingFeatureControlHeaders []string         `yaml:"connecting_feature_control_headers" validate:"required"`
	Sites                           []AllSiteRuleSet `yaml:"sites" validate:"required"`
	Peers                           []Peer           `yaml:"peers"`
}

type Peer struct {
	Name    string `yaml:"name" validate:"required"`
	Address string `yaml:"address" validate:"required,url"`
	Host    string `yaml:"host"`
}

// resolveConfigPath determines the path to the configuration file
func resolveConfigPath(basePath string) string {
	var configPath string
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
	return configPath
}

// readConfigFile reads the configuration file
func readConfigFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// decodeConfig unmarshals the configuration
func decodeConfig(data []byte, cfg *MainConfig) error {
	return yaml.Unmarshal(data, cfg)
}

// applyDefaultConfig populates any empty or missing configuration fields with default values
func applyDefaultConfig(cfg *MainConfig) {
	if cfg.Port == "" {
		cfg.Port = "25555"
	}
	if cfg.WebPath == "" {
		cfg.WebPath = "/torii"
	}
	if cfg.ErrorPage == "" {
		cfg.ErrorPage = "/www/server_torii/config/error_page"
	}
	if cfg.LogPath == "" {
		cfg.LogPath = "/www/server_torii/log/"
	}
	if cfg.NodeName == "" {
		cfg.NodeName = "Server Torii"
	}
	if len(cfg.ConnectingHostHeaders) == 0 {
		cfg.ConnectingHostHeaders = []string{"Torii-Real-Host"}
	}
	if len(cfg.ConnectingIPHeaders) == 0 {
		cfg.ConnectingIPHeaders = []string{"Torii-Real-IP"}
	}
	if len(cfg.ConnectingURIHeaders) == 0 {
		cfg.ConnectingURIHeaders = []string{"Torii-Original-URI"}
	}
	if len(cfg.ConnectingFeatureControlHeaders) == 0 {
		cfg.ConnectingFeatureControlHeaders = []string{"Torii-Feature-Control"}
	}
	if len(cfg.Sites) == 0 {
		cfg.Sites = []AllSiteRuleSet{
			{
				Host:     "default_site",
				RulePath: "/www/server_torii/config/rules/default",
			},
		}
	}
}

// validateMainConfig validates the main configuration object
func validateMainConfig(cfg *MainConfig) {
	validateConfiguration(cfg, "MainConfig")
}

// LoadMainConfig Read the configuration file and return the configuration object
func LoadMainConfig(basePath string) (*MainConfig, error) {
	configPath := resolveConfigPath(basePath)

	var cfg MainConfig

	data, err := readConfigFile(configPath)
	if err != nil {
		log.Printf("[WARNING] failed to read configuration file at %s, using default values: %v", configPath, err)
		applyDefaultConfig(&cfg)
		return &cfg, nil
	}

	if err := decodeConfig(data, &cfg); err != nil {
		log.Printf("[WARNING] failed to parse configuration file at %s, using default values: %v", configPath, err)
		applyDefaultConfig(&cfg)
		return &cfg, nil
	}

	applyDefaultConfig(&cfg)
	validateMainConfig(&cfg)

	return &cfg, nil
}

type AllSiteRuleSet struct {
	Host     string `yaml:"host" validate:"required,min=1"`
	RulePath string `yaml:"rule_path" validate:"required,dir"`
}

// RuleSet stores all rules
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

// ruleSetWrapper
type ruleSetWrapper struct {
	IPAllowRule                 *dataType.IPAllowRule                 `yaml:"IPAllow"`
	IPBlockRule                 *dataType.IPBlockRule                 `yaml:"IPBlock"`
	URLAllowRule                *dataType.URLAllowRule                `yaml:"URLAllow"`
	URLBlockRule                *dataType.URLBlockRule                `yaml:"URLBlock"`
	CAPTCHARule                 *captchaRuleWrapper                   `yaml:"CAPTCHA"`
	VerifyBotRule               *dataType.VerifyBotRule               `yaml:"VerifyBot"`
	HTTPFloodRule               httpFloodRuleWrapper                  `yaml:"HTTPFlood"`
	ExternalMigrationRule       *dataType.ExternalMigrationRule       `yaml:"ExternalMigration"`
	AdaptiveTrafficAnalyzerRule *dataType.AdaptiveTrafficAnalyzerRule `yaml:"AdaptiveTrafficAnalyzer"`
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
		IPAllowRule:                 &dataType.IPAllowRule{Trie: &dataType.TrieNode{}},
		IPBlockRule:                 &dataType.IPBlockRule{Trie: &dataType.TrieNode{}},
		URLAllowRule:                &dataType.URLAllowRule{List: &dataType.URLRuleList{}},
		URLBlockRule:                &dataType.URLBlockRule{List: &dataType.URLRuleList{}},
		CAPTCHARule:                 &dataType.CaptchaRule{},
		VerifyBotRule:               &dataType.VerifyBotRule{},
		HTTPFloodRule:               &dataType.HTTPFloodRule{},
		ExternalMigrationRule:       &dataType.ExternalMigrationRule{},
		AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{},
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

	if err := mapHTTPFloodRule(&wrapper.HTTPFloodRule, rs.HTTPFloodRule); err != nil {
		return err
	}
	return nil
}

func mapCaptchaRule(wrapper *captchaRuleWrapper, dest *dataType.CaptchaRule) error {
	validateConfiguration(wrapper, "CAPTCHARule")
	dest.Enabled = wrapper.Enabled
	dest.SecretKey = wrapper.SecretKey
	dest.CaptchaValidateTime = wrapper.CaptchaValidateTime
	dest.CaptchaChallengeSessionTimeout = wrapper.CaptchaChallengeSessionTimeout
	dest.HCaptchaSecret = wrapper.HCaptchaSecret

	dest.CaptchaFailureLimit = make(map[int64]int64)
	for _, s := range wrapper.CaptchaFailureLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		dest.CaptchaFailureLimit[seconds] = limit
	}
	dest.FailureBlockDuration = wrapper.FailureBlockDuration
	return nil
}

func mapAdaptiveTrafficAnalyzerRule(wrapper *dataType.AdaptiveTrafficAnalyzerRule, dest *dataType.AdaptiveTrafficAnalyzerRule) {
	validateConfiguration(wrapper, "AdaptiveTrafficAnalyzerRule")
	dest.Enabled = wrapper.Enabled
	dest.Tag = wrapper.Tag
	dest.AnalysisInterval = wrapper.AnalysisInterval

	dest.Non200Analysis.Enabled = wrapper.Non200Analysis.Enabled
	dest.Non200Analysis.BlockDuration = wrapper.Non200Analysis.BlockDuration
	dest.Non200Analysis.FailCountThreshold = wrapper.Non200Analysis.FailCountThreshold
	dest.Non200Analysis.FailRateCountThreshold = wrapper.Non200Analysis.FailRateCountThreshold
	dest.Non200Analysis.FailRateThreshold = wrapper.Non200Analysis.FailRateThreshold
	dest.Non200Analysis.UriRateTopN = wrapper.Non200Analysis.UriRateTopN
	dest.Non200Analysis.UriRateThreshold = wrapper.Non200Analysis.UriRateThreshold

	dest.UriAnalysis.Enabled = wrapper.UriAnalysis.Enabled
	dest.UriAnalysis.BlockDuration = wrapper.UriAnalysis.BlockDuration
	dest.UriAnalysis.FailRateThreshold = wrapper.UriAnalysis.FailRateThreshold
	dest.UriAnalysis.FailRateCountThreshold = wrapper.UriAnalysis.FailRateCountThreshold
	dest.UriAnalysis.RequestCountSensitivity = wrapper.UriAnalysis.RequestCountSensitivity
	dest.UriAnalysis.RequestCountThreshold = wrapper.UriAnalysis.RequestCountThreshold
}

func mapHTTPFloodRule(wrapper *httpFloodRuleWrapper, dest *dataType.HTTPFloodRule) error {
	validateConfiguration(wrapper, "HTTPFloodRule")
	dest.Enabled = wrapper.Enabled
	dest.HTTPFloodSpeedLimit = make(map[int64]int64)
	dest.HTTPFloodSameURILimit = make(map[int64]int64)

	for _, s := range wrapper.HTTPFloodSpeedLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		dest.HTTPFloodSpeedLimit[seconds] = limit
	}

	for _, s := range wrapper.HTTPFloodSameURILimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		dest.HTTPFloodSameURILimit[seconds] = limit
	}

	dest.HTTPFloodFailureLimit = make(map[int64]int64)
	for _, s := range wrapper.HTTPFloodFailureLimit {
		limit, seconds, err := utils.ParseRate(s)
		if err != nil {
			return err
		}
		dest.HTTPFloodFailureLimit[seconds] = limit
	}
	dest.FailureBlockDuration = wrapper.FailureBlockDuration
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
