package config

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/feature"
	"server_torii/internal/ratelimit"
	"server_torii/internal/rules"
	"slices"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

const DefaultAltchaCost = 5000

// ruleSetWrapper is a site's Server.yml as it is written.
type ruleSetWrapper struct {
	Lists           *[]listWrapper               `yaml:"lists"`
	CountryRule     *countryRuleWrapper          `yaml:"country_rule"`
	Challenge       *challengeRuleWrapper        `yaml:"challenge"`
	HTTPFlood       *httpFloodRuleWrapper        `yaml:"http_flood"`
	VerifyBot       *verifyBotRuleWrapper        `yaml:"verify_bot"`
	TrafficAnalyzer *AdaptiveTrafficAnalyzerRule `yaml:"traffic_analyzer"`
	CustomRules     *customRulesWrapper          `yaml:"custom_rules"`
}

// missingSections returns the names of the sections the file leaves out, in the order of the
// example configuration.
func (w *ruleSetWrapper) missingSections() []string {
	var missing []string
	for _, section := range []struct {
		name    string
		present bool
	}{
		{"lists", w.Lists != nil},
		{"country_rule", w.CountryRule != nil},
		{"challenge", w.Challenge != nil},
		{"http_flood", w.HTTPFlood != nil},
		{"verify_bot", w.VerifyBot != nil},
		{"traffic_analyzer", w.TrafficAnalyzer != nil},
		{"custom_rules", w.CustomRules != nil},
	} {
		if !section.present {
			missing = append(missing, section.name)
		}
	}
	return missing
}

type verifyBotRuleWrapper struct {
	Enabled bool     `yaml:"enabled"`
	Bots    []string `yaml:"bots"`
}

// mapVerifyBotRule accepts the crawlers Torii can verify; an empty list verifies none.
func mapVerifyBotRule(wrapper *verifyBotRuleWrapper, dest *VerifyBotRule) error {
	dest.Enabled = wrapper.Enabled
	dest.Bots = make(map[string]bool, len(wrapper.Bots))
	for _, name := range wrapper.Bots {
		bot := strings.ToLower(strings.TrimSpace(name))
		if !slices.Contains(Bots, bot) {
			return fmt.Errorf("verify_bot.bots: unknown crawler %q: expected one of %s", name, strings.Join(Bots, ", "))
		}
		if dest.Bots[bot] {
			return fmt.Errorf("verify_bot.bots: %s is listed twice", bot)
		}
		dest.Bots[bot] = true
	}
	return nil
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
	Enabled              bool          `yaml:"enabled"`
	SpeedLimit           []string      `yaml:"speed_limit" validate:"min=1,dive"`
	SameURILimit         []string      `yaml:"same_uri_limit" validate:"min=1,dive"`
	SameURIKey           SameURIKey    `yaml:"same_uri_key" validate:"required,oneof=full path canonical"`
	FailureLimit         []string      `yaml:"failure_limit" validate:"min=1,dive"`
	FailureBlockDuration time.Duration `yaml:"failure_block_duration" validate:"required,min=1s"`
}

type challengeRuleWrapper struct {
	Enabled              bool          `yaml:"enabled"`
	Mode                 ChallengeMode `yaml:"mode" validate:"required,oneof=hcaptcha altcha external"`
	ExternalSecret       string        `yaml:"external_secret" validate:"required_if=Mode external,omitempty,min=16"`
	ClearanceTTL         time.Duration `yaml:"clearance_ttl" validate:"required,min=1s"`
	SessionTTL           time.Duration `yaml:"session_ttl" validate:"required_unless=Mode external,omitempty,min=1s"`
	HCaptchaSecret       string        `yaml:"hcaptcha_secret" validate:"required_if=Mode hcaptcha"`
	AltchaHMACSecret     string        `yaml:"altcha_hmac_secret"`
	AltchaCost           int           `yaml:"altcha_cost" validate:"min=0"` // 0 means DefaultAltchaCost
	RedirectURL          string        `yaml:"redirect_url" validate:"required_if=Mode external,omitempty,url"`
	FailureLimit         []string      `yaml:"failure_limit" validate:"min=1,dive"`
	FailureBlockDuration time.Duration `yaml:"failure_block_duration" validate:"required,min=1s"`
}

type countryRuleWrapper struct {
	Enabled       bool              `yaml:"enabled"`
	DefaultAction yaml.Node         `yaml:"default_action"`
	UnknownAction yaml.Node         `yaml:"unknown_action"`
	Countries     map[string]string `yaml:"countries"`
}

// A zero node means omitted; an explicit empty or null action is invalid.
func countryActionOrDefault(node yaml.Node) (action.Action, error) {
	if node.Kind == 0 {
		return action.ActionContinue, nil
	}
	if node.Kind != yaml.ScalarNode || node.Tag != "!!str" {
		return "", fmt.Errorf("country action must be a string")
	}
	return parseCountryAction(node.Value)
}

func parseCountryAction(value string) (action.Action, error) {
	return action.Parse(value, action.ActionContinue, action.ActionBlock, action.ActionChallenge)
}

func mapCountryRule(wrapper *countryRuleWrapper, dest *CountryRule) error {
	var err error
	dest.Enabled = wrapper.Enabled
	if dest.DefaultAction, err = countryActionOrDefault(wrapper.DefaultAction); err != nil {
		return fmt.Errorf("country_rule.default_action: %w", err)
	}
	if dest.UnknownAction, err = countryActionOrDefault(wrapper.UnknownAction); err != nil {
		return fmt.Errorf("country_rule.unknown_action: %w", err)
	}
	dest.Countries = make(map[string]action.Action, len(wrapper.Countries))
	for code, value := range wrapper.Countries {
		normalized, err := normalizeCountryCode(code)
		if err != nil {
			return fmt.Errorf("country_rule.countries: %w", err)
		}
		if _, exists := dest.Countries[normalized]; exists {
			return fmt.Errorf("country_rule.countries: %s is listed twice", normalized)
		}
		act, err := parseCountryAction(value)
		if err != nil {
			return fmt.Errorf("country_rule.countries.%s: %w", normalized, err)
		}
		dest.Countries[normalized] = act
	}
	return nil
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

func mapChallengeRule(wrapper *challengeRuleWrapper, dest *ChallengeRule) error {
	if err := validateStruct(wrapper, "challenge"); err != nil {
		return err
	}
	dest.Enabled = wrapper.Enabled
	dest.Mode = wrapper.Mode
	dest.ExternalSecret = wrapper.ExternalSecret
	dest.ClearanceTTL = wrapper.ClearanceTTL
	dest.SessionTTL = wrapper.SessionTTL
	dest.HCaptchaSecret = wrapper.HCaptchaSecret
	// Whoever knows this secret signs challenges of their own, as easy as they like.
	if wrapper.AltchaHMACSecret == DefaultGlobalSecret {
		return fmt.Errorf("challenge.altcha_hmac_secret: this is the public value from the example configuration; remove it to use a key derived from global_secret, or set a secret of your own")
	}
	dest.AltchaHMACSecret = wrapper.AltchaHMACSecret
	dest.AltchaCost = wrapper.AltchaCost
	if dest.AltchaCost == 0 {
		dest.AltchaCost = DefaultAltchaCost
	}
	dest.RedirectURL = wrapper.RedirectURL
	dest.FailureBlockDuration = wrapper.FailureBlockDuration

	var err error
	if dest.FailureLimit, err = ratelimit.ParseRates(wrapper.FailureLimit); err != nil {
		return fmt.Errorf("challenge.failure_limit: %w", err)
	}
	return nil
}

// mapAdaptiveTrafficAnalyzerRule copies the section and fills the thresholds it leaves at zero
// with their defaults.
func mapAdaptiveTrafficAnalyzerRule(wrapper *AdaptiveTrafficAnalyzerRule, dest *AdaptiveTrafficAnalyzerRule) error {
	if err := validateStruct(wrapper, "traffic_analyzer"); err != nil {
		return err
	}
	*dest = *wrapper
	NormalizeAdaptiveTrafficAnalyzerRule(dest)
	return nil
}

func mapHTTPFloodRule(wrapper *httpFloodRuleWrapper, dest *HTTPFloodRule) error {
	if err := validateStruct(wrapper, "http_flood"); err != nil {
		return err
	}
	dest.Enabled = wrapper.Enabled
	dest.SameURIKey = wrapper.SameURIKey
	dest.FailureBlockDuration = wrapper.FailureBlockDuration
	for _, list := range []struct {
		key  string
		in   []string
		dest *ratelimit.Rates
	}{
		{"speed_limit", wrapper.SpeedLimit, &dest.SpeedLimit},
		{"same_uri_limit", wrapper.SameURILimit, &dest.SameURILimit},
		{"failure_limit", wrapper.FailureLimit, &dest.FailureLimit},
	} {
		rates, err := ratelimit.ParseRates(list.in)
		if err != nil {
			return fmt.Errorf("http_flood.%s: %w", list.key, err)
		}
		*list.dest = rates
	}
	return nil
}

// mapCustomRules compiles every enabled rule; any error rejects the whole file so a reload keeps the old rules.
func mapCustomRules(wrapper *customRulesWrapper, dest *rules.CustomRules, lists rules.Lists) error {
	dest.Enabled = wrapper.Enabled
	dest.Rules = make([]*rules.Rule, 0, len(wrapper.Rules))
	seen := make(map[string]bool, len(wrapper.Rules))
	for i, w := range wrapper.Rules {
		label := fmt.Sprintf("custom_rules rule #%d", i+1)
		if w.ID != "" {
			label = fmt.Sprintf("custom_rules rule %q", w.ID)
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
		case act == action.ActionSkip && len(w.Skip) == 0:
			return fmt.Errorf("%s: skip action requires a non-empty skip list", label)
		case act != action.ActionSkip && len(w.Skip) > 0:
			return fmt.Errorf("%s: skip list is only valid with the skip action", label)
		case act == action.ActionSkip:
			if skipMask, err = feature.ParseSkipTargets(w.Skip); err != nil {
				return fmt.Errorf("%s: %w", label, err)
			}
		}
		prog, err := rules.Compile(w.Expression, lists)
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
