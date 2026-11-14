package config

import (
	"path/filepath"
	"server_torii/internal/action"
	"strings"
	"testing"
)

func TestCountryRuleSchema(t *testing.T) {
	tests := []struct {
		name, input string
		invalid     bool
	}{
		{"defaults", "{}", false},
		{"normalized", "countries: { ' us ': challenge, GB: continue }", false},
		{"actions", "default_action: block\nunknown_action: challenge", false},
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
			rule := &CountryRule{}
			if err == nil {
				err = mapCountryRule(wrapper.CountryRule, rule)
			}
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %t", err, tt.invalid)
			}
			if tt.name == "defaults" && (rule.DefaultAction != action.ActionContinue || rule.UnknownAction != action.ActionContinue || len(rule.Countries) != 0) {
				t.Fatalf("wrong defaults: %#v", rule)
			}
			if tt.name == "normalized" && rule.Countries["US"] != action.ActionChallenge {
				t.Fatalf("wrong normalization: %#v", rule)
			}
		})
	}
}

func TestCountryCaptchaConfiguration(t *testing.T) {
	for _, policy := range []string{"default_action: challenge", "unknown_action: challenge", "countries: { US: challenge }"} {
		for _, config := range []struct {
			name, yaml string
			invalid    bool
		}{
			{"invalid", "Challenge: { enabled: false }", true},
			{"valid disabled", `Challenge:
  mode: hcaptcha
  enabled: false
  clearance_ttl: 60
  session_ttl: 120
  failure_limit: ["3/1m"]
  failure_block_duration: 60
`, false},
		} {
			t.Run(policy+"/"+config.name, func(t *testing.T) {
				file := filepath.Join(t.TempDir(), "Server.yml")
				writeFile(t, file, "CountryRule:\n  enabled: false\n  "+policy+"\n"+config.yaml)
				rules := NewRuleSet()
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
	if rules.CountryRule.Enabled || rules.CountryRule.Countries["US"] != action.ActionChallenge || rules.CountryRule.DefaultAction != action.ActionBlock {
		t.Fatalf("unexpected example: %#v", rules.CountryRule)
	}
}

func TestInvalidCountryReloadRetainsSnapshot(t *testing.T) {
	dir := t.TempDir()
	writeRuleFiles(t, dir, map[string]string{"Server.yml": "CountryRule: { default_action: block }"})
	cfg := &MainConfig{Sites: []AllSiteRuleSet{{ID: "default_site", RulePath: dir}}}
	manager := &Manager{}
	if err := manager.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	before := manager.Get()
	writeFile(t, filepath.Join(dir, "Server.yml"), "CountryRule: { default_action: invalid }")
	if err := manager.Reload(cfg); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if manager.Get() != before {
		t.Fatal("invalid reload replaced snapshot")
	}
}
