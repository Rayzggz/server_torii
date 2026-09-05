package config

import (
	"path/filepath"
	"server_torii/internal/dataType"
	"strings"
	"testing"
)

func TestCountryRuleSchema(t *testing.T) {
	tests := []struct {
		name, input string
		invalid     bool
	}{
		{"defaults", "{}", false},
		{"normalized", "countries: { ' us ': captcha, GB: continue }", false},
		{"actions", "default_action: block\nunknown_action: captcha", false},
		{"duplicate normalized", "countries: { us: block, US: continue }", true},
		{"duplicate exact", "countries: { US: block, US: continue }", true},
		{"invalid code", "countries: { USA: block }", true},
		{"invalid action", "countries: { US: allow }", true},
		{"uppercase action", "default_action: BLOCK", true},
		{"empty default", "default_action: ''", true},
		{"null default", "default_action: null", true},
		{"empty unknown", "unknown_action: ''", true},
		{"invalid unknown", "unknown_action: allow", true},
		{"empty country action", "countries: { US: '' }", true},
		{"unknown field", "enabled: false\ndefault_acton: block", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, err := decodeServerRules([]byte("CountryRule:\n  " + strings.ReplaceAll(tt.input, "\n", "\n  ")))
			rule := &dataType.CountryRule{}
			if err == nil {
				err = mapCountryRule(wrapper.CountryRule, rule)
			}
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %t", err, tt.invalid)
			}
			if tt.name == "defaults" && (rule.DefaultAction != dataType.CountryContinue || rule.UnknownAction != dataType.CountryContinue || len(rule.Countries) != 0) {
				t.Fatalf("wrong defaults: %#v", rule)
			}
			if tt.name == "normalized" && rule.Countries["US"] != dataType.CountryCaptcha {
				t.Fatalf("wrong normalization: %#v", rule)
			}
		})
	}
}

func TestCountryCaptchaConfiguration(t *testing.T) {
	for _, policy := range []string{"default_action: captcha", "unknown_action: captcha", "countries: { US: captcha }"} {
		for _, config := range []struct {
			name, yaml string
			invalid    bool
		}{
			{"missing", "", true},
			{"invalid", "CAPTCHA: { enabled: false }", true},
			{"valid disabled", `CAPTCHA:
  enabled: false
  secret_key: "1234567890abcdef"
  captcha_validate_time: 60
  captcha_challenge_session_timeout: 120
  CaptchaFailureLimit: ["3/1m"]
  failure_block_duration: 60
`, false},
		} {
			t.Run(policy+"/"+config.name, func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "Server.yml")
				writeFile(t, file, "CountryRule:\n  enabled: false\n  "+policy+"\n"+config.yaml)
				rules := &RuleSet{CountryRule: &dataType.CountryRule{}, CAPTCHARule: &dataType.CaptchaRule{}, HTTPFloodRule: &dataType.HTTPFloodRule{}}
				err := loadServerRules(file, rules)
				if (err != nil) != config.invalid {
					t.Fatalf("error = %v, invalid = %t", err, config.invalid)
				}
			})
		}
	}
}

func TestExampleCountryRulesLoad(t *testing.T) {
	rules, err := LoadRules(filepath.Join("..", "..", "config_example", "rules", "default"))
	if err != nil {
		t.Fatal(err)
	}
	if rules.CountryRule.Enabled || rules.CountryRule.Countries["US"] != dataType.CountryCaptcha || rules.CountryRule.DefaultAction != dataType.CountryBlock {
		t.Fatalf("unexpected example: %#v", rules.CountryRule)
	}
}

func TestInvalidCountryReloadRetainsSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeRuleFiles(t, dir, map[string]string{"IP_AllowList.conf": "", "IP_BlockList.conf": "", "URL_AllowList.conf": "", "URL_BlockList.conf": "", "Server.yml": "CountryRule: { default_action: block }"})
	cfg := &MainConfig{Sites: []AllSiteRuleSet{{Host: "default_site", RulePath: dir}}}
	manager := &ConfigManager{}
	shared := &dataType.SharedMemory{}
	if err := manager.Reload(cfg, shared); err != nil {
		t.Fatal(err)
	}
	before := manager.Get()
	writeFile(t, filepath.Join(dir, "Server.yml"), "CountryRule: { default_action: invalid }")
	if err := manager.Reload(cfg, shared); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if manager.Get() != before {
		t.Fatal("invalid reload replaced snapshot")
	}
}
