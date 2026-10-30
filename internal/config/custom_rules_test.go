package config

import (
	"path/filepath"
	"server_torii/internal/dataType"
	"server_torii/internal/rules"
	"strings"
	"testing"
)

func TestCustomRulesSchema(t *testing.T) {
	tests := []struct {
		name, input string
		wantErr     string
	}{
		{"empty", "enabled: true", ""},
		{"valid", `rules:
  - id: a
    expression: 'http.referer contains "spam"'
    action: block
  - id: b
    expression: 'starts_with(http.request.uri.path, "/api/")'
    action: skip
    skip: [HTTPFlood, CountryRule]`, ""},
		{"unknown top field", "rule: []", `unknown field "rule"`},
		{"unknown rule field", "rules: [{id: a, expression: 'true', action: log, actoin: block}]", `unknown field "actoin"`},
		{"missing id", "rules: [{expression: 'true', action: log}]", "rule #1: id is required"},
		{"duplicate id", "rules: [{id: a, expression: 'true', action: log}, {id: a, expression: 'true', action: log}]", "duplicate id"},
		{"bad action", "rules: [{id: a, expression: 'true', action: deny}]", `invalid action "deny"`},
		{"bad expression", "rules: [{id: a, expression: 'http.hots eq \"x\"', action: block}]", `rule "a": expression col 1: unknown field`},
		{"empty expression", "rules: [{id: a, action: block}]", "expression is empty"},
		{"skip without list", "rules: [{id: a, expression: 'true', action: skip}]", "requires a non-empty skip list"},
		{"skip list on block", "rules: [{id: a, expression: 'true', action: block, skip: [HTTPFlood]}]", "only valid with the skip action"},
		{"bad skip target", "rules: [{id: a, expression: 'true', action: skip, skip: [IPAllow]}]", `invalid skip target "IPAllow"`},
		{"disabled rule still compiled", "rules: [{id: a, enabled: false, expression: 'bad', action: block}]", "expression"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, err := decodeServerRules([]byte("CustomRules:\n  " + strings.ReplaceAll(tt.input, "\n", "\n  ")))
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			dest := &rules.CustomRules{}
			err = mapCustomRules(wrapper.CustomRules, dest)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

func TestCustomRulesDisabledRuleDropped(t *testing.T) {
	wrapper, err := decodeServerRules([]byte(`CustomRules:
  enabled: true
  rules:
    - {id: off, enabled: false, expression: 'true', action: block}
    - {id: on, expression: 'true', action: skip, skip: [Captcha, HTTPFlood]}
`))
	if err != nil {
		t.Fatal(err)
	}
	dest := &rules.CustomRules{}
	if err := mapCustomRules(wrapper.CustomRules, dest); err != nil {
		t.Fatal(err)
	}
	if !dest.Enabled || len(dest.Rules) != 1 || dest.Rules[0].ID != "on" {
		t.Fatalf("rules = %#v", dest.Rules)
	}
	if dest.Rules[0].SkipMask != rules.SkipCaptcha|rules.SkipHTTPFlood {
		t.Fatalf("skip mask = %b", dest.Rules[0].SkipMask)
	}
}

func TestCustomRulesDependencies(t *testing.T) {
	const validCaptcha = `CAPTCHA:
  enabled: false
  secret_key: "1234567890abcdef"
  captcha_validate_time: 60
  captcha_challenge_session_timeout: 120
  CaptchaFailureLimit: ["3/1m"]
  failure_block_duration: 60
`
	const validExternal = `ExternalMigration:
  enabled: false
  redirect_url: "https://example.com/migration"
  secret_key: "1234567890abcdef"
  session_timeout: 60
`
	for _, tc := range []struct {
		name, action, extra string
		invalid             bool
	}{
		{"captcha missing", "captcha", "", true},
		{"captcha invalid", "captcha", "CAPTCHA: { enabled: false }\n", true},
		{"captcha valid", "captcha", validCaptcha, false},
		{"external missing", "external", "", true},
		{"external valid", "external", validExternal, false},
		{"block needs nothing", "block", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file := filepath.Join(t.TempDir(), "Server.yml")
			writeFile(t, file, "CustomRules:\n  enabled: false\n  rules:\n    - {id: a, expression: 'true', action: "+tc.action+"}\n"+tc.extra)
			rs := &RuleSet{CountryRule: &dataType.CountryRule{}, CAPTCHARule: &dataType.CaptchaRule{}, HTTPFloodRule: &dataType.HTTPFloodRule{}, ExternalMigrationRule: &dataType.ExternalMigrationRule{}}
			err := loadServerRules(file, rs)
			if (err != nil) != tc.invalid {
				t.Fatalf("error = %v, invalid = %t", err, tc.invalid)
			}
			if err == nil && (rs.CustomRules == nil || len(rs.CustomRules.Rules) != 1) {
				t.Fatalf("rules not loaded: %#v", rs.CustomRules)
			}
		})
	}
}
