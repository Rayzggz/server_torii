package config

import (
	"net"
	"os"
	"path/filepath"
	"server_torii/internal/dataType"
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

	sharedMem := &dataType.SharedMemory{}
	if err := InitManager(cfg, sharedMem); err != nil {
		t.Fatalf("InitManager returned unexpected error: %v", err)
	}

	snapshot := Manager.Get()
	if snapshot == nil {
		t.Fatal("Manager.Get() returned nil snapshot")
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

	if got := sharedMem.HTTPFloodSpeedLimitCounter.Load(); got == nil || got.GetSegSize() != 120 {
		if got == nil {
			t.Fatal("HTTPFloodSpeedLimitCounter = nil, want initialized counter")
		}
		t.Fatalf("HTTPFloodSpeedLimitCounter segSize = %d, want 120", got.GetSegSize())
	}
	if got := sharedMem.HTTPFloodSameURILimitCounter.Load(); got == nil || got.GetSegSize() != 45 {
		if got == nil {
			t.Fatal("HTTPFloodSameURILimitCounter = nil, want initialized counter")
		}
		t.Fatalf("HTTPFloodSameURILimitCounter segSize = %d, want 45", got.GetSegSize())
	}
	if got := sharedMem.HTTPFloodFailureLimitCounter.Load(); got == nil || got.GetSegSize() != 300 {
		if got == nil {
			t.Fatal("HTTPFloodFailureLimitCounter = nil, want initialized counter")
		}
		t.Fatalf("HTTPFloodFailureLimitCounter segSize = %d, want 300", got.GetSegSize())
	}
	if got := sharedMem.CaptchaFailureLimitCounter.Load(); got == nil || got.GetSegSize() != 120 {
		if got == nil {
			t.Fatal("CaptchaFailureLimitCounter = nil, want initialized counter")
		}
		t.Fatalf("CaptchaFailureLimitCounter segSize = %d, want 120", got.GetSegSize())
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

	if err := Manager.Reload(cfg, sharedMem); err != nil {
		t.Fatalf("Reload returned unexpected error: %v", err)
	}

	reloaded := Manager.Get()
	if reloaded == nil {
		t.Fatal("Manager.Get() returned nil snapshot after reload")
	}

	reloadedRules := reloaded.SiteRules["default_site"]
	if reloadedRules == nil {
		t.Fatal("default_site missing after reload")
	}
	if reloadedRules.IPAllowRule.Enabled {
		t.Fatal("IPAllowRule.Enabled = true after reload, want false")
	}
	if got := sharedMem.HTTPFloodSpeedLimitCounter.Load().GetSegSize(); got != 240 {
		t.Fatalf("HTTPFloodSpeedLimitCounter segSize after reload = %d, want 240", got)
	}
	if got := sharedMem.HTTPFloodSameURILimitCounter.Load().GetSegSize(); got != 60 {
		t.Fatalf("HTTPFloodSameURILimitCounter segSize after reload = %d, want 60", got)
	}
	if got := sharedMem.HTTPFloodFailureLimitCounter.Load().GetSegSize(); got != 900 {
		t.Fatalf("HTTPFloodFailureLimitCounter segSize after reload = %d, want 900", got)
	}
	if got := sharedMem.CaptchaFailureLimitCounter.Load().GetSegSize(); got != 240 {
		t.Fatalf("CaptchaFailureLimitCounter segSize after reload = %d, want 240", got)
	}
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) failed: %v", path, err)
	}
}

func writeRuleFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		writeFile(t, filepath.Join(dir, name), content)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", path, err)
	}
}
