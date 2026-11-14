package config

import (
	"net/netip"
	"path/filepath"
	"server_torii/internal/action"
	"testing"
)

func TestConfigIntegration_LoadAndReloadManager(t *testing.T) {
	tempDir := t.TempDir()
	ruleDir := filepath.Join(tempDir, "rules", "default")
	mustMkdirAll(t, ruleDir)

	writeRuleFiles(t, ruleDir, map[string]string{
		"IP_AllowList.conf":  "192.168.1.0/24\n",
		"IP_BlockList.conf":  "10.0.0.5\n",
		"URL_AllowList.conf": "/healthz\nregex:^/api/.*$\n",
		"URL_BlockList.conf": "/admin\n",
		"Server.yml": `Lists:
  - {name: ip_allow, enabled: true, type: ip, file: IP_AllowList.conf, action: allow}
  - {name: ip_block, enabled: true, type: ip, file: IP_BlockList.conf, action: block}
  - {name: url_allow, enabled: true, type: url, file: URL_AllowList.conf, action: allow}
  - {name: url_block, enabled: true, type: url, file: URL_BlockList.conf, action: block}
CountryRule:
  enabled: true
  default_action: block
  countries:
    us: challenge
Challenge:
  mode: hcaptcha
  enabled: true
  secret_key: "1234567890abcdef"
  clearance_ttl: 60
  session_ttl: 120
  hcaptcha_secret: "hcaptcha-secret"
  failure_limit:
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
`,
	})

	writeFile(t, filepath.Join(tempDir, "torii.yml"), `port: "8080"
web_path: "/edge"
node_name: "integration-node"
sites:
  - id: "default_site"
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

	// A request that names no site belongs to the default site.
	rules := snapshot.Site("")
	if rules == nil || rules.ID != "default_site" {
		t.Fatalf("Site(\"\") = %+v, want the default site", rules)
	}
	if snapshot.Site("unknown_site") != nil {
		t.Fatal("an unknown site ID fell back to another site")
	}

	addr := netip.MustParseAddr
	for name, on := range map[string]bool{
		"ip_allow":  rules.Lists.ByName("ip_allow").ContainsAddr(addr("192.168.1.15")),
		"ip_block":  rules.Lists.ByName("ip_block").ContainsAddr(addr("10.0.0.5")),
		"url_exact": rules.Lists.ByName("url_allow").ContainsURL("/healthz"),
		"url_regex": rules.Lists.ByName("url_allow").ContainsURL("/api/test"),
		"url_block": rules.Lists.ByName("url_block").ContainsURL("/admin"),
		"enabled":   rules.Lists.ByName("ip_allow").Enabled,
		"allows":    rules.Lists.AllowsAddr(addr("192.168.1.15")) && rules.Lists.AllowsURL("/healthz"),
		"order":     len(rules.Lists.All()) == 4 && rules.Lists.All()[0].Name == "ip_allow",
	} {
		if !on {
			t.Errorf("lists: %s does not hold", name)
		}
	}
	if !rules.CountryRule.Enabled {
		t.Fatal("CountryRule.Enabled = false, want true")
	}
	if rules.CountryRule.Countries["US"] != action.ActionChallenge || rules.CountryRule.DefaultAction != action.ActionBlock {
		t.Fatalf("unexpected country policy: %#v", rules.CountryRule)
	}
	if !rules.Challenge.Enabled {
		t.Fatal("Challenge.Enabled = false, want true")
	}
	if rules.Challenge.FailureLimit[120] != 5 {
		t.Fatalf("FailureLimit[120] = %d, want 5", rules.Challenge.FailureLimit[120])
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

	if got, want := snapshot.CounterWindows()["default_site"], (CounterWindows{HTTPFloodSpeed: 120, HTTPFloodSameURI: 45, HTTPFloodFailure: 300, ChallengeFailure: 120}); got != want {
		t.Fatalf("CounterWindows = %+v, want %+v", got, want)
	}

	writeFile(t, filepath.Join(ruleDir, "Server.yml"), `Lists:
  - {name: ip_allow, enabled: false, type: ip, file: IP_AllowList.conf, action: allow}
  - {name: ip_block, enabled: true, type: ip, file: IP_BlockList.conf, action: block}
  - {name: url_allow, enabled: true, type: url, file: URL_AllowList.conf, action: allow}
  - {name: url_block, enabled: true, type: url, file: URL_BlockList.conf, action: block}
Challenge:
  mode: hcaptcha
  enabled: true
  secret_key: "1234567890abcdef"
  clearance_ttl: 60
  session_ttl: 120
  hcaptcha_secret: "hcaptcha-secret"
  failure_limit:
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
	if reloadedRules.Lists.ByName("ip_allow").Enabled || reloadedRules.Lists.AllowsAddr(netip.MustParseAddr("192.168.1.15")) {
		t.Fatal("ip_allow is still enabled after the reload switched it off")
	}
	if reloadedRules.CountryRule == nil || reloadedRules.CountryRule.Enabled {
		t.Fatal("CountryRule should remain present and disabled when omitted")
	}
	if got, want := reloaded.CounterWindows()["default_site"], (CounterWindows{HTTPFloodSpeed: 240, HTTPFloodSameURI: 60, HTTPFloodFailure: 900, ChallengeFailure: 240}); got != want {
		t.Fatalf("CounterWindows after reload = %+v, want %+v", got, want)
	}
}
