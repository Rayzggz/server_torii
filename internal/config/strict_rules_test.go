package config

import (
	"strings"
	"testing"
)

const strictHTTPFlood = `HTTPFlood:
  enabled: false
  HTTPFloodSpeedLimit: ["5/10s"]
  HTTPFloodSameURILimit: ["3/10s"]
  HTTPFloodFailureLimit: ["3/30s"]
  failure_block_duration: 300
`

// Server.yml is rejected as a whole on any problem; nothing is skipped or replaced by a default.
func TestLoadRules_Strict(t *testing.T) {
	for name, tt := range map[string]struct {
		settings string
		want     string // "" means the file loads
	}{
		"empty file":                {"", ""},
		"complete section":          {strictHTTPFlood, ""},
		"analyzer defaults":         {"AdaptiveTrafficAnalyzer: {enabled: true}", ""},
		"unknown section":           {"HTTPFlod: {enabled: true}", `unknown field "HTTPFlod"`},
		"unknown key":               {strings.Replace(strictHTTPFlood, "enabled", "enable", 1), `unknown field "enable"`},
		"removed analyzer key":      {"AdaptiveTrafficAnalyzer: {enabled: true, tag: x}", `unknown field "tag"`},
		"wrong type":                {strings.Replace(strictHTTPFlood, "300", "soon", 1), "cannot unmarshal"},
		"incomplete, disabled":      {"HTTPFlood: {enabled: false}", "HTTPFlood.HTTPFloodSpeedLimit: list needs at least 1 entry"},
		"empty limit list":          {strings.Replace(strictHTTPFlood, `["5/10s"]`, "[]", 1), "HTTPFlood.HTTPFloodSpeedLimit: list needs at least 1 entry"},
		"bad rate":                  {strings.Replace(strictHTTPFlood, "5/10s", "fast", 1), "fast"},
		"bad block duration":        {strings.Replace(strictHTTPFlood, "300", "0", 1), "HTTPFlood.failure_block_duration: field is required"},
		"incomplete captcha":        {"CAPTCHA: {enabled: false}", "CAPTCHA.secret_key: field is required"},
		"incomplete external":       {"ExternalMigration: {enabled: false}", "ExternalMigration.redirect_url: field is required"},
		"bad external URL":          {"ExternalMigration: {redirect_url: nowhere, secret_key: 1234567890abcdef, session_timeout: 5}", "ExternalMigration.redirect_url: value must be a valid URL"},
		"bad analyzer action":       {"AdaptiveTrafficAnalyzer: {ip_detection: {action: ban}}", "AdaptiveTrafficAnalyzer.ip_detection.action: value must be one of: observe captcha_unverified captcha block"},
		"bad analyzer URI action":   {"AdaptiveTrafficAnalyzer: {uri_detection: {action: Block}}", "AdaptiveTrafficAnalyzer.uri_detection.action"},
		"negative analyzer value":   {"AdaptiveTrafficAnalyzer: {window_buckets: -1}", "AdaptiveTrafficAnalyzer.window_buckets: value must be at least 0"},
		"analyzer rate over 1":      {"AdaptiveTrafficAnalyzer: {ip_detection: {fail_rate_threshold: 1.5}}", "AdaptiveTrafficAnalyzer.ip_detection.fail_rate_threshold: value must be at most 1"},
		"every problem is reported": {"ExternalMigration: {redirect_url: nowhere}", "ExternalMigration.session_timeout"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadRules(ipCaptchaDirectory(t, tt.settings))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("LoadRules: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}

// A section the file leaves out keeps its rule disabled and empty.
func TestLoadRules_AbsentSections(t *testing.T) {
	rules, err := LoadRules(ipCaptchaDirectory(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if rules.HTTPFloodRule.Enabled || rules.CAPTCHARule.Enabled || rules.ExternalMigrationRule.Enabled ||
		rules.AdaptiveTrafficAnalyzerRule.Enabled || rules.CustomRules.Enabled || rules.CountryRule.Enabled {
		t.Fatalf("a rule is enabled without a section: %+v", rules)
	}
	if windows := rules.CounterWindows(); windows != (CounterWindows{}) {
		t.Fatalf("CounterWindows = %+v, want zero", windows)
	}
}

// The shipped example rules must stay loadable.
func TestLoadRules_Example(t *testing.T) {
	if _, err := LoadRules("../../config_example/rules/default"); err != nil {
		t.Fatalf("the example rules do not load: %v", err)
	}
}
