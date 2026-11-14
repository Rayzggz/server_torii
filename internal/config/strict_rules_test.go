package config

import (
	"os"
	"path/filepath"
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
		"every check off":           {"", ""},
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
		"incomplete challenge":      {"Challenge: {enabled: false}", "Challenge.clearance_ttl: field is required"},
		"external without secret":   {"Challenge: {mode: external, clearance_ttl: 5}", "Challenge.external_secret: field is required with this mode"},
		"old cookie key of a site":  {"Challenge: {mode: hcaptcha, secret_key: 1234567890abcdef}", `unknown field "secret_key"`},
		"challenge without mode":    {"Challenge: {enabled: false}", "Challenge.mode: field is required"},
		"bad challenge mode":        {"Challenge: {mode: recaptcha}", "Challenge.mode: value must be one of: hcaptcha altcha external"},
		"external without URL":      {"Challenge: {mode: external, clearance_ttl: 5}", "Challenge.redirect_url: field is required"},
		"bad external URL":          {"Challenge: {mode: external, redirect_url: nowhere, clearance_ttl: 5}", "Challenge.redirect_url: value must be a valid URL"},
		"removed CAPTCHA section":   {"CAPTCHA: {enabled: false}", `unknown field "CAPTCHA"`},
		"removed external section":  {"ExternalMigration: {enabled: false}", `unknown field "ExternalMigration"`},
		"bad analyzer action":       {"AdaptiveTrafficAnalyzer: {ip_detection: {action: ban}}", "AdaptiveTrafficAnalyzer.ip_detection.action: value must be one of: observe challenge_unverified challenge block"},
		"bad analyzer URI action":   {"AdaptiveTrafficAnalyzer: {uri_detection: {action: Block}}", "AdaptiveTrafficAnalyzer.uri_detection.action"},
		"negative analyzer value":   {"AdaptiveTrafficAnalyzer: {window_buckets: -1}", "AdaptiveTrafficAnalyzer.window_buckets: value must be at least 0"},
		"analyzer rate over 1":      {"AdaptiveTrafficAnalyzer: {ip_detection: {fail_rate_threshold: 1.5}}", "AdaptiveTrafficAnalyzer.ip_detection.fail_rate_threshold: value must be at most 1"},
		"every problem is reported": {"Challenge: {mode: external, redirect_url: nowhere}", "Challenge.clearance_ttl"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadRules(siteDirectory(t, tt.settings))
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

// Every section is required: a file that leaves one out is rejected, and the error names all
// that are missing.
func TestLoadRules_MissingSections(t *testing.T) {
	load := func(t *testing.T, serverRules string) error {
		dir := siteDirectory(t, "")
		writeRawFile(t, filepath.Join(dir, "Server.yml"), serverRules)
		_, err := LoadRules(dir)
		return err
	}

	complete := completeServerRules("")
	if err := load(t, complete); err != nil {
		t.Fatalf("a complete file with every check off: %v", err)
	}

	err := load(t, "")
	if err == nil {
		t.Fatal("an empty file loaded")
	}
	for _, section := range disabledSections {
		if !strings.Contains(err.Error(), section.name) {
			t.Errorf("the error for an empty file does not name %s: %v", section.name, err)
		}
	}

	for _, section := range disabledSections {
		t.Run(section.name, func(t *testing.T) {
			err := load(t, strings.Replace(complete, section.text, "", 1))
			if err == nil || !strings.Contains(err.Error(), "missing sections: "+section.name+".") {
				t.Fatalf("error = %v, want %s reported as the one missing section", err, section.name)
			}
		})
	}
}

// A check that is switched off is still loaded in full.
func TestLoadRules_DisabledSectionsAreLoaded(t *testing.T) {
	rules, err := LoadRules(siteDirectory(t, ""))
	if err != nil {
		t.Fatal(err)
	}
	if rules.HTTPFloodRule.Enabled || rules.Challenge.Enabled ||
		rules.AdaptiveTrafficAnalyzerRule.Enabled || rules.CustomRules.Enabled || rules.CountryRule.Enabled {
		t.Fatalf("a rule is enabled: %+v", rules)
	}
	if rules.Challenge.Mode != ChallengeHCaptcha {
		t.Fatalf("the disabled challenge was not loaded: %+v", rules.Challenge)
	}
	if want := (CounterWindows{HTTPFloodSpeed: 10, HTTPFloodSameURI: 10, HTTPFloodFailure: 30, ChallengeFailure: 60}); rules.CounterWindows() != want {
		t.Fatalf("CounterWindows = %+v, want %+v", rules.CounterWindows(), want)
	}
}

// The shipped example rules must stay loadable.
func TestLoadRules_Example(t *testing.T) {
	if _, err := LoadRules("../../config_example/rules/default"); err != nil {
		t.Fatalf("the example rules do not load: %v", err)
	}
}

// The rules the end-to-end suite runs with must load, as they are and in the external mode the
// suite switches one of its sites to.
func TestLoadRules_E2EFixture(t *testing.T) {
	const fixture = "../../tests/e2e/fixtures/rules"
	for _, mode := range []ChallengeMode{ChallengeAltcha, ChallengeExternal} {
		dir := t.TempDir()
		entries, err := os.ReadDir(fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			data, err := os.ReadFile(filepath.Join(fixture, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if entry.Name() == "Server.yml" {
				data = []byte(strings.Replace(string(data), "mode: altcha", "mode: "+string(mode), 1))
			}
			writeFile(t, filepath.Join(dir, entry.Name()), string(data))
		}
		rules, err := LoadRules(dir)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if rules.Challenge.Mode != mode {
			t.Fatalf("%s: challenge = %+v", mode, rules.Challenge)
		}
	}
}
