package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const strictHTTPFlood = `http_flood:
  enabled: false
  speed_limit: ["5/10s"]
  same_uri_limit: ["3/10s"]
  failure_limit: ["3/30s"]
  failure_block_duration: 300s
`

// Server.yml is rejected as a whole on any problem; nothing is skipped or replaced by a default.
func TestLoadRules_Strict(t *testing.T) {
	for name, tt := range map[string]struct {
		settings string
		want     string // "" means the file loads
	}{
		"every check off":           {"", ""},
		"complete section":          {strictHTTPFlood, ""},
		"analyzer defaults":         {"traffic_analyzer: {enabled: true}", ""},
		"unknown section":           {"HTTPFlod: {enabled: true}", `unknown field "HTTPFlod"`},
		"unknown key":               {strings.Replace(strictHTTPFlood, "enabled", "enable", 1), `unknown field "enable"`},
		"removed analyzer key":      {"traffic_analyzer: {enabled: true, tag: x}", `unknown field "tag"`},
		"wrong type":                {strings.Replace(strictHTTPFlood, "300s", "soon", 1), "`soon` is not a duration"},
		"duration without a unit":   {strings.Replace(strictHTTPFlood, "300s", "300", 1), "`300` is not a duration: write it with a unit"},
		"incomplete, disabled":      {"http_flood: {enabled: false}", "http_flood.speed_limit: list needs at least 1 entry"},
		"empty limit list":          {strings.Replace(strictHTTPFlood, `["5/10s"]`, "[]", 1), "http_flood.speed_limit: list needs at least 1 entry"},
		"bad rate":                  {strings.Replace(strictHTTPFlood, "5/10s", "fast", 1), "fast"},
		"bad block duration":        {strings.Replace(strictHTTPFlood, "300", "0", 1), "http_flood.failure_block_duration: field is required"},
		"incomplete challenge":      {"challenge: {enabled: false}", "challenge.clearance_ttl: field is required"},
		"second document":           {"lists: []\n---\nlists: []", "more than one YAML document"},
		"hcaptcha without secret":   {"challenge: {mode: hcaptcha, clearance_ttl: 5s}", "challenge.hcaptcha_secret: field is required with this mode"},
		"external without secret":   {"challenge: {mode: external, clearance_ttl: 5s}", "challenge.external_secret: field is required with this mode"},
		"old cookie key of a site":  {"challenge: {mode: hcaptcha, secret_key: 1234567890abcdef}", `unknown field "secret_key"`},
		"challenge without mode":    {"challenge: {enabled: false}", "challenge.mode: field is required"},
		"bad challenge mode":        {"challenge: {mode: recaptcha}", "challenge.mode: value must be one of: hcaptcha altcha external"},
		"external without URL":      {"challenge: {mode: external, clearance_ttl: 5s}", "challenge.redirect_url: field is required"},
		"bad external URL":          {"challenge: {mode: external, redirect_url: nowhere, clearance_ttl: 5s}", "challenge.redirect_url: value must be a valid URL"},
		"removed CAPTCHA section":   {"CAPTCHA: {enabled: false}", `unknown field "CAPTCHA"`},
		"removed external section":  {"ExternalMigration: {enabled: false}", `unknown field "ExternalMigration"`},
		"bad analyzer action":       {"traffic_analyzer: {ip_detection: {action: ban}}", "traffic_analyzer.ip_detection.action: value must be one of: observe challenge_unverified challenge block"},
		"bad analyzer URI action":   {"traffic_analyzer: {uri_detection: {action: Block}}", "traffic_analyzer.uri_detection.action"},
		"negative analyzer value":   {"traffic_analyzer: {window_buckets: -1}", "traffic_analyzer.window_buckets: value must be at least 0"},
		"analyzer rate over 1":      {"traffic_analyzer: {ip_detection: {fail_rate_threshold: 1.5}}", "traffic_analyzer.ip_detection.fail_rate_threshold: value must be at most 1"},
		"every problem is reported": {"challenge: {mode: external, redirect_url: nowhere}", "challenge.clearance_ttl"},
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

// The shipped example rules must stay loadable once they have an ALTCHA secret of their own.
// As shipped they are refused, for the public secret alone.
func TestLoadRules_Example(t *testing.T) {
	_, err := LoadRules(exampleRulesPath)
	if err == nil || strings.Count(err.Error(), "\n") != 1 || !strings.Contains(err.Error(), "challenge.altcha_hmac_secret: this is the public value") {
		t.Fatalf("the example as shipped: error = %v, want the public secret refused and nothing else", err)
	}
	if _, err := LoadRules(exampleRulesDirectory(t)); err != nil {
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
