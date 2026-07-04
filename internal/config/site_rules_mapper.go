package config

import (
	"fmt"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
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
	Enabled          bool     `yaml:"enabled"`
	CAPTCHANot       bool     `yaml:"CAPTCHA_NOT"`
	BlockNot         bool     `yaml:"BLOCK_NOT"`
	CAPTCHACountries []string `yaml:"CAPTCHA"`
	BlockCountries   []string `yaml:"BLOCK"`
}

func mapCountryRule(wrapper *countryRuleWrapper, dest *dataType.CountryRule) error {
	dest.Enabled = wrapper.Enabled
	dest.CAPTCHANot = wrapper.CAPTCHANot
	dest.BlockNot = wrapper.BlockNot
	dest.CAPTCHACountries = make(map[string]struct{}, len(wrapper.CAPTCHACountries))
	dest.BlockCountries = make(map[string]struct{}, len(wrapper.BlockCountries))

	for _, code := range wrapper.CAPTCHACountries {
		normalized, err := normalizeCountryCode(code)
		if err != nil {
			return fmt.Errorf("invalid CountryRule CAPTCHA country: %w", err)
		}
		dest.CAPTCHACountries[normalized] = struct{}{}
	}

	for _, code := range wrapper.BlockCountries {
		normalized, err := normalizeCountryCode(code)
		if err != nil {
			return fmt.Errorf("invalid CountryRule BLOCK country: %w", err)
		}
		dest.BlockCountries[normalized] = struct{}{}
	}

	return validateCountryRulePredicates(dest)
}

func validateCountryRulePredicates(rule *dataType.CountryRule) error {
	for first := byte('A'); first <= 'Z'; first++ {
		for second := byte('A'); second <= 'Z'; second++ {
			country := string([]byte{first, second})
			if countryRuleMatches(rule.BlockCountries, rule.BlockNot, country) &&
				countryRuleMatches(rule.CAPTCHACountries, rule.CAPTCHANot, country) {
				return fmt.Errorf("country code %q matches both CountryRule CAPTCHA and BLOCK", country)
			}
		}
	}
	return nil
}

func countryRuleMatches(countries map[string]struct{}, inverted bool, country string) bool {
	_, listed := countries[country]
	return listed != inverted
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
