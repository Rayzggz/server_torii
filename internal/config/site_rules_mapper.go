package config

import (
	"fmt"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultCaptchaProvider = "hcaptcha"
	DefaultAltchaCost      = 5000
)

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
	CountryRule                 *countryRuleWrapper                   `yaml:"CountryRule"`
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
	Provider                       string   `yaml:"provider"`
	SecretKey                      string   `yaml:"secret_key" validate:"required,min=16"`
	CaptchaValidateTime            int64    `yaml:"captcha_validate_time" validate:"required,min=1,max=9223372036854775807"`
	CaptchaChallengeSessionTimeout int64    `yaml:"captcha_challenge_session_timeout" validate:"required,min=1,max=9223372036854775807"`
	HCaptchaSecret                 string   `yaml:"hcaptcha_secret"`
	AltchaHMACSecret               string   `yaml:"altcha_hmac_secret"`
	AltchaCost                     int      `yaml:"altcha_cost"`
	CaptchaFailureLimit            []string `yaml:"CaptchaFailureLimit" validate:"required,dive"`
	FailureBlockDuration           int64    `yaml:"failure_block_duration" validate:"required,min=1"`
}

type countryRuleWrapper struct {
	Enabled       bool                 `yaml:"enabled"`
	DefaultAction yaml.Node            `yaml:"default_action"`
	UnknownAction yaml.Node            `yaml:"unknown_action"`
	Countries     map[string]string    `yaml:"countries"`
	UnknownFields map[string]yaml.Node `yaml:",inline"`
}

// A zero node means omitted; an explicit empty or null action is invalid.
func countryActionOrDefault(node yaml.Node) (dataType.CountryAction, error) {
	if node.Kind == 0 {
		return dataType.CountryContinue, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("country action must be a string")
	}
	return parseCountryAction(node.Value)
}

func parseCountryAction(value string) (dataType.CountryAction, error) {
	action := dataType.CountryAction(value)
	switch action {
	case dataType.CountryContinue, dataType.CountryBlock, dataType.CountryCaptcha:
		return action, nil
	default:
		return "", fmt.Errorf("invalid country action %q: expected continue, block, or captcha", value)
	}
}

func mapCountryRule(wrapper *countryRuleWrapper, dest *dataType.CountryRule) error {
	for field := range wrapper.UnknownFields {
		return fmt.Errorf("CountryRule: unknown field %q", field)
	}
	var err error
	dest.Enabled = wrapper.Enabled
	if dest.DefaultAction, err = countryActionOrDefault(wrapper.DefaultAction); err != nil {
		return fmt.Errorf("CountryRule default_action: %w", err)
	}
	if dest.UnknownAction, err = countryActionOrDefault(wrapper.UnknownAction); err != nil {
		return fmt.Errorf("CountryRule unknown_action: %w", err)
	}
	dest.Countries = make(map[string]dataType.CountryAction, len(wrapper.Countries))
	for code, value := range wrapper.Countries {
		normalized, err := normalizeCountryCode(code)
		if err != nil {
			return fmt.Errorf("CountryRule countries: %w", err)
		}
		if _, exists := dest.Countries[normalized]; exists {
			return fmt.Errorf("CountryRule duplicate normalized country %q", normalized)
		}
		action, err := parseCountryAction(value)
		if err != nil {
			return fmt.Errorf("CountryRule country %s: %w", normalized, err)
		}
		dest.Countries[normalized] = action
	}
	return nil
}

func countryRequiresCaptcha(rule *dataType.CountryRule) bool {
	if rule == nil {
		return false
	}
	if rule.DefaultAction == dataType.CountryCaptcha || rule.UnknownAction == dataType.CountryCaptcha {
		return true
	}
	for _, action := range rule.Countries {
		if action == dataType.CountryCaptcha {
			return true
		}
	}
	return false
}

func normalizeCountryCode(code string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(code))
	if len(normalized) != 2 ||
		normalized[0] < 'A' || normalized[0] > 'Z' ||
		normalized[1] < 'A' || normalized[1] > 'Z' {
		return "", fmt.Errorf("%q must contain exactly two ASCII letters", code)
	}
	return normalized, nil
}

func mapCaptchaRule(wrapper *captchaRuleWrapper, dest *dataType.CaptchaRule) error {
	validateConfiguration(wrapper, "CAPTCHARule")
	dest.Enabled = wrapper.Enabled
	dest.Provider = wrapper.Provider
	if dest.Provider == "" {
		dest.Provider = DefaultCaptchaProvider
	}
	dest.SecretKey = wrapper.SecretKey
	dest.CaptchaValidateTime = wrapper.CaptchaValidateTime
	dest.CaptchaChallengeSessionTimeout = wrapper.CaptchaChallengeSessionTimeout
	dest.HCaptchaSecret = wrapper.HCaptchaSecret
	dest.AltchaHMACSecret = wrapper.AltchaHMACSecret
	if dest.AltchaHMACSecret == "" {
		dest.AltchaHMACSecret = wrapper.SecretKey
	}
	dest.AltchaCost = wrapper.AltchaCost
	if dest.AltchaCost == 0 {
		dest.AltchaCost = DefaultAltchaCost
	}
	dest.FailureBlockDuration = wrapper.FailureBlockDuration

	var err error
	dest.CaptchaFailureLimit, err = utils.ParseRateList(wrapper.CaptchaFailureLimit)
	return err
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
	dest.FailureBlockDuration = wrapper.FailureBlockDuration

	var err error
	dest.HTTPFloodSpeedLimit, err = utils.ParseRateList(wrapper.HTTPFloodSpeedLimit)
	if err != nil {
		return err
	}

	dest.HTTPFloodSameURILimit, err = utils.ParseRateList(wrapper.HTTPFloodSameURILimit)
	if err != nil {
		return err
	}

	dest.HTTPFloodFailureLimit, err = utils.ParseRateList(wrapper.HTTPFloodFailureLimit)
	return err
}
