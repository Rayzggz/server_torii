package config

import (
	"fmt"
	"server_torii/internal/feature"
	"server_torii/internal/ratelimit"
	"server_torii/internal/rules"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultCaptchaProvider = "hcaptcha"
	DefaultAltchaCost      = 5000
)

// ruleSetWrapper
type ruleSetWrapper struct {
	IPAllowRule                 *IPListRule                  `yaml:"IPAllow"`
	IPBlockRule                 *IPListRule                  `yaml:"IPBlock"`
	URLAllowRule                *URLListRule                 `yaml:"URLAllow"`
	URLBlockRule                *URLListRule                 `yaml:"URLBlock"`
	IPCAPTCHARule               *IPListRule                  `yaml:"IPCAPTCHA"`
	URLCAPTCHARule              *URLListRule                 `yaml:"URLCAPTCHA"`
	CAPTCHARule                 *captchaRuleWrapper          `yaml:"CAPTCHA"`
	VerifyBotRule               *VerifyBotRule               `yaml:"VerifyBot"`
	HTTPFloodRule               *httpFloodRuleWrapper        `yaml:"HTTPFlood"`
	ExternalMigrationRule       *ExternalMigrationRule       `yaml:"ExternalMigration"`
	AdaptiveTrafficAnalyzerRule *AdaptiveTrafficAnalyzerRule `yaml:"AdaptiveTrafficAnalyzer"`
	CountryRule                 *countryRuleWrapper          `yaml:"CountryRule"`
	CustomRules                 *customRulesWrapper          `yaml:"CustomRules"`
}

type customRulesWrapper struct {
	Enabled bool                `yaml:"enabled"`
	Rules   []customRuleWrapper `yaml:"rules"`
}

type customRuleWrapper struct {
	ID          string   `yaml:"id"`
	Description string   `yaml:"description"`
	Enabled     *bool    `yaml:"enabled"`
	Expression  string   `yaml:"expression"`
	Action      string   `yaml:"action"`
	Skip        []string `yaml:"skip"`
}

type httpFloodRuleWrapper struct {
	Enabled               bool     `yaml:"enabled"`
	HTTPFloodSpeedLimit   []string `yaml:"HTTPFloodSpeedLimit" validate:"min=1,dive"`
	HTTPFloodSameURILimit []string `yaml:"HTTPFloodSameURILimit" validate:"min=1,dive"`
	HTTPFloodFailureLimit []string `yaml:"HTTPFloodFailureLimit" validate:"min=1,dive"`
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
	CaptchaFailureLimit            []string `yaml:"CaptchaFailureLimit" validate:"min=1,dive"`
	FailureBlockDuration           int64    `yaml:"failure_block_duration" validate:"required,min=1"`
}

type countryRuleWrapper struct {
	Enabled       bool              `yaml:"enabled"`
	DefaultAction yaml.Node         `yaml:"default_action"`
	UnknownAction yaml.Node         `yaml:"unknown_action"`
	Countries     map[string]string `yaml:"countries"`
}

// A zero node means omitted; an explicit empty or null action is invalid.
func countryActionOrDefault(node yaml.Node) (CountryAction, error) {
	if node.Kind == 0 {
		return CountryContinue, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("country action must be a string")
	}
	return parseCountryAction(node.Value)
}

func parseCountryAction(value string) (CountryAction, error) {
	action := CountryAction(value)
	switch action {
	case CountryContinue, CountryBlock, CountryCaptcha:
		return action, nil
	default:
		return "", fmt.Errorf("invalid country action %q: expected continue, block, or captcha", value)
	}
}

func mapCountryRule(wrapper *countryRuleWrapper, dest *CountryRule) error {
	var err error
	dest.Enabled = wrapper.Enabled
	if dest.DefaultAction, err = countryActionOrDefault(wrapper.DefaultAction); err != nil {
		return fmt.Errorf("CountryRule default_action: %w", err)
	}
	if dest.UnknownAction, err = countryActionOrDefault(wrapper.UnknownAction); err != nil {
		return fmt.Errorf("CountryRule unknown_action: %w", err)
	}
	dest.Countries = make(map[string]CountryAction, len(wrapper.Countries))
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

func countryRequiresCaptcha(rule *CountryRule) bool {
	if rule == nil {
		return false
	}
	if rule.DefaultAction == CountryCaptcha || rule.UnknownAction == CountryCaptcha {
		return true
	}
	for _, action := range rule.Countries {
		if action == CountryCaptcha {
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

func mapCaptchaRule(wrapper *captchaRuleWrapper, dest *CaptchaRule) error {
	if err := validateStruct(wrapper, "CAPTCHA"); err != nil {
		return err
	}
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
	dest.CaptchaFailureLimit, err = ratelimit.ParseRateList(wrapper.CaptchaFailureLimit)
	return err
}

// mapAdaptiveTrafficAnalyzerRule copies the section and fills the thresholds it leaves at zero
// with their defaults.
func mapAdaptiveTrafficAnalyzerRule(wrapper *AdaptiveTrafficAnalyzerRule, dest *AdaptiveTrafficAnalyzerRule) error {
	if err := validateStruct(wrapper, "AdaptiveTrafficAnalyzer"); err != nil {
		return err
	}
	*dest = *wrapper
	NormalizeAdaptiveTrafficAnalyzerRule(dest)
	return nil
}

func mapHTTPFloodRule(wrapper *httpFloodRuleWrapper, dest *HTTPFloodRule) error {
	if err := validateStruct(wrapper, "HTTPFlood"); err != nil {
		return err
	}
	dest.Enabled = wrapper.Enabled
	dest.FailureBlockDuration = wrapper.FailureBlockDuration

	var err error
	dest.HTTPFloodSpeedLimit, err = ratelimit.ParseRateList(wrapper.HTTPFloodSpeedLimit)
	if err != nil {
		return err
	}

	dest.HTTPFloodSameURILimit, err = ratelimit.ParseRateList(wrapper.HTTPFloodSameURILimit)
	if err != nil {
		return err
	}

	dest.HTTPFloodFailureLimit, err = ratelimit.ParseRateList(wrapper.HTTPFloodFailureLimit)
	return err
}

// mapCustomRules compiles every enabled rule; any error rejects the whole file so a reload keeps the old rules.
func mapCustomRules(wrapper *customRulesWrapper, dest *rules.CustomRules) error {
	dest.Enabled = wrapper.Enabled
	dest.Rules = make([]*rules.Rule, 0, len(wrapper.Rules))
	seen := make(map[string]bool, len(wrapper.Rules))
	for i, w := range wrapper.Rules {
		label := fmt.Sprintf("CustomRules rule #%d", i+1)
		if w.ID != "" {
			label = fmt.Sprintf("CustomRules rule %q", w.ID)
		}
		if w.ID == "" {
			return fmt.Errorf("%s: id is required", label)
		}
		if seen[w.ID] {
			return fmt.Errorf("%s: duplicate id", label)
		}
		seen[w.ID] = true
		act, err := rules.ParseAction(w.Action)
		if err != nil {
			return fmt.Errorf("%s: %w", label, err)
		}
		var skipMask uint32
		switch {
		case act == rules.ActionSkip && len(w.Skip) == 0:
			return fmt.Errorf("%s: skip action requires a non-empty skip list", label)
		case act != rules.ActionSkip && len(w.Skip) > 0:
			return fmt.Errorf("%s: skip list is only valid with the skip action", label)
		case act == rules.ActionSkip:
			if skipMask, err = feature.ParseSkipTargets(w.Skip); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
		prog, err := rules.Compile(w.Expression)
		if err != nil {
			return fmt.Errorf("%s: expression %s", label, err)
		}
		if w.Enabled != nil && !*w.Enabled {
			continue
		}
		dest.Rules = append(dest.Rules, &rules.Rule{
			ID:          w.ID,
			Description: w.Description,
			Action:      act,
			SkipMask:    skipMask,
			Program:     prog,
		})
	}
	return nil
}
