package config

import (
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
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
