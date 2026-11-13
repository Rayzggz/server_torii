package config

import (
	"net"
	"path/filepath"
	"testing"
)

func TestConfigIntegration_LoadAndReloadManager(t *testing.T) {
	tempDir := t.TempDir()
	ruleDir := filepath.Join(tempDir, "rules", "default")
	mustMkdirAll(t, ruleDir)

	writeRuleFiles(t, ruleDir, map[string]string{
		"IP_AllowList.conf":  "192.168.1.0/24\n",
		"IP_BlockList.conf":  "10.0.0.5\n",
		"URL_AllowList.conf": "/healthz\n^/api/.*$\n",
		"URL_BlockList.conf": "/admin\n",
		"Server.yml": `IPAllow:
  enabled: true
IPBlock:
  enabled: true
URLAllow:
  enabled: true
URLBlock:
  enabled: true
CountryRule:
  enabled: true
  default_action: block
  countries:
    us: captcha
CAPTCHA:
  enabled: true
  secret_key: "1234567890abcdef"
  captcha_validate_time: 60
  captcha_challenge_session_timeout: 120
  hcaptcha_secret: "hcaptcha-secret"
  CaptchaFailureLimit:
    - "3/1m"
    - "5/2m"
  failure_block_duration: 300
VerifyBot:
  enabled: true
  verify_google_bot: true
HTTPFlood:
  enabled: true
  HTTPFloodSpeedLimit:
    - "10/1m"
    - "20/2m"
  HTTPFloodSameURILimit:
    - "5/30s"
    - "8/45s"
  HTTPFloodFailureLimit:
    - "4/5m"
  failure_block_duration: 600
ExternalMigration:
  enabled: true
  redirect_url: "https://example.com/migrate"
  secret_key: "1234567890abcdef"
  session_timeout: 180
`,
	})

	writeFile(t, filepath.Join(tempDir, "torii.yml"), `port: "8080"
web_path: "/edge"
node_name: "integration-node"
sites:
  - host: "default_site"
    rule_path: "`+filepath.ToSlash(ruleDir)+`"
`)

	cfg, err := LoadMainConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadMainConfig returned unexpected error: %v", err)
	}

	if cfg.Port != "8080" {
		t.Fatalf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.WebPath != "/edge" {
		t.Fatalf("WebPath = %q, want %q", cfg.WebPath, "/edge")
	}
	if cfg.NodeName != "integration-node" {
		t.Fatalf("NodeName = %q, want %q", cfg.NodeName, "integration-node")
	}
	if cfg.LogPath != DefaultLogPath {
		t.Fatalf("LogPath = %q, want default %q", cfg.LogPath, DefaultLogPath)
	}

	manager := NewManager()
	if err := manager.Reload(cfg); err != nil {
		t.Fatalf("Reload returned unexpected error: %v", err)
	}

	snapshot := manager.Get()
	if snapshot == nil {
		t.Fatal("manager.Get() returned nil snapshot")
	}

	rules := GetSiteRules(snapshot.SiteRules, "unknown.example.com")
	if rules == nil {
		t.Fatal("GetSiteRules returned nil for default_site fallback")
	}

	if !rules.IPAllowRule.Enabled {
		t.Fatal("IPAllowRule.Enabled = false, want true")
	}
	if !rules.IPAllowRule.Trie.Search(net.ParseIP("192.168.1.15")) {
		t.Fatal("IP allow trie did not match configured CIDR")
	}
	if !rules.IPBlockRule.Trie.Search(net.ParseIP("10.0.0.5")) {
		t.Fatal("IP block trie did not match configured IP")
	}
	if !rules.URLAllowRule.List.Match("/healthz") {
		t.Fatal("URL allow list did not match static rule")
	}
	if !rules.URLAllowRule.List.Match("/api/test") {
		t.Fatal("URL allow list did not match regex rule")
	}
	if !rules.URLBlockRule.List.Match("/admin") {
		t.Fatal("URL block list did not match configured rule")
	}
	if !rules.CountryRule.Enabled {
		t.Fatal("CountryRule.Enabled = false, want true")
	}
	if rules.CountryRule.Countries["US"] != CountryCaptcha || rules.CountryRule.DefaultAction != CountryBlock {
		t.Fatalf("unexpected country policy: %#v", rules.CountryRule)
	}
	if !rules.CAPTCHARule.Enabled {
		t.Fatal("CAPTCHARule.Enabled = false, want true")
	}
	if rules.CAPTCHARule.CaptchaFailureLimit[120] != 5 {
		t.Fatalf("CaptchaFailureLimit[120] = %d, want 5", rules.CAPTCHARule.CaptchaFailureLimit[120])
	}
	if !rules.VerifyBotRule.Enabled {
		t.Fatal("VerifyBotRule.Enabled = false, want true")
	}
	if !rules.HTTPFloodRule.Enabled {
		t.Fatal("HTTPFloodRule.Enabled = false, want true")
	}
	if rules.HTTPFloodRule.HTTPFloodSpeedLimit[120] != 20 {
		t.Fatalf("HTTPFloodSpeedLimit[120] = %d, want 20", rules.HTTPFloodRule.HTTPFloodSpeedLimit[120])
	}
	if !rules.ExternalMigrationRule.Enabled {
		t.Fatal("ExternalMigrationRule.Enabled = false, want true")
	}

	if got, want := snapshot.CounterWindows(), (CounterWindows{HTTPFloodSpeed: 120, HTTPFloodSameURI: 45, HTTPFloodFailure: 300, CaptchaFailure: 120}); got != want {
		t.Fatalf("CounterWindows = %+v, want %+v", got, want)
	}

	writeFile(t, filepath.Join(ruleDir, "Server.yml"), `IPAllow:
  enabled: false
IPBlock:
  enabled: true
URLAllow:
  enabled: true
URLBlock:
  enabled: true
CAPTCHA:
  enabled: true
  secret_key: "1234567890abcdef"
  captcha_validate_time: 60
  captcha_challenge_session_timeout: 120
  hcaptcha_secret: "hcaptcha-secret"
  CaptchaFailureLimit:
    - "7/4m"
  failure_block_duration: 300
HTTPFlood:
  enabled: true
  HTTPFloodSpeedLimit:
    - "11/4m"
  HTTPFloodSameURILimit:
    - "9/1m"
  HTTPFloodFailureLimit:
    - "4/15m"
  failure_block_duration: 600
`)

	if err := manager.Reload(cfg); err != nil {
		t.Fatalf("Reload returned unexpected error: %v", err)
	}

	reloaded := manager.Get()
	if reloaded == nil {
		t.Fatal("manager.Get() returned nil snapshot after reload")
	}

	reloadedRules := reloaded.SiteRules["default_site"]
	if reloadedRules == nil {
		t.Fatal("default_site missing after reload")
	}
	if reloadedRules.IPAllowRule.Enabled {
		t.Fatal("IPAllowRule.Enabled = true after reload, want false")
	}
	if reloadedRules.CountryRule == nil || reloadedRules.CountryRule.Enabled {
		t.Fatal("CountryRule should remain present and disabled when omitted")
	}
	if got, want := reloaded.CounterWindows(), (CounterWindows{HTTPFloodSpeed: 240, HTTPFloodSameURI: 60, HTTPFloodFailure: 900, CaptchaFailure: 240}); got != want {
		t.Fatalf("CounterWindows after reload = %+v, want %+v", got, want)
	}
}
