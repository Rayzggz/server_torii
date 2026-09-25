package config

import (
	"net"
	"os"
	"path/filepath"
	"server_torii/internal/dataType"
	"testing"
)

const ipCaptchaSettings = `CAPTCHA:
  enabled: false
  secret_key: "1234567890abcdef"
  captcha_validate_time: 60
  captcha_challenge_session_timeout: 120
  CaptchaFailureLimit: ["3/1m"]
  failure_block_duration: 60
`

func ipCaptchaDirectory(t *testing.T, settings string) string {
	t.Helper()
	dir := t.TempDir()
	writeRuleFiles(t, dir, map[string]string{"IP_AllowList.conf": "", "IP_BlockList.conf": "", "URL_AllowList.conf": "", "URL_BlockList.conf": "", "Server.yml": settings})
	return dir
}

func TestIPCaptchaConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, settings, list string
		missing, invalid     bool
	}{
		{"old config", "", "", true, false},
		{"enabled missing", "IPCAPTCHA: { enabled: true }\n" + ipCaptchaSettings, "", true, true},
		{"enabled empty", "IPCAPTCHA: { enabled: true }\n" + ipCaptchaSettings, "", false, false},
		{"enabled no captcha", "IPCAPTCHA: { enabled: true }", "", false, true},
		{"invalid captcha", "IPCAPTCHA: { enabled: true }\nCAPTCHA: { enabled: false }", "192.0.2.10", false, true},
		{"disabled populated no captcha", "", "192.0.2.10", false, true},
		{"disabled populated valid captcha", ipCaptchaSettings, "192.0.2.10", false, false},
		{"unsupported entries", "", "bad\n2001:db8::1\n2001:db8::/32\n# comment\n", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := ipCaptchaDirectory(t, tt.settings)
			if !tt.missing {
				writeFile(t, filepath.Join(dir, "IP_CAPTCHAList.conf"), tt.list)
			}
			rules, err := LoadRules(dir)
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %t", err, tt.invalid)
			}
			if err == nil && (rules.IPCAPTCHARule == nil || rules.IPCAPTCHARule.Trie == nil) {
				t.Fatal("missing initialized rule")
			}
		})
	}
}

func TestIPCaptchaUsesIPAllowMatching(t *testing.T) {
	dir := ipCaptchaDirectory(t, ipCaptchaSettings)
	list := "192.0.2.10\n198.51.100.0/24\nbad\n2001:db8::/32\n\n"
	writeFile(t, filepath.Join(dir, "IP_AllowList.conf"), list)
	writeFile(t, filepath.Join(dir, "IP_CAPTCHAList.conf"), list)
	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]bool{"192.0.2.10": true, "192.0.2.11": false, "198.51.100.255": true, "198.51.101.1": false, "2001:db8::1": false} {
		address := net.ParseIP(ip)
		got := rules.IPCAPTCHARule.Trie.Search(address)
		if got != want || got != rules.IPAllowRule.Trie.Search(address) {
			t.Errorf("%s: match = %t, want %t", ip, got, want)
		}
	}
}

func TestIPCaptchaReloadAndSiteIsolation(t *testing.T) {
	first := ipCaptchaDirectory(t, "IPCAPTCHA: { enabled: true }\n"+ipCaptchaSettings)
	second := ipCaptchaDirectory(t, "")
	list := filepath.Join(first, "IP_CAPTCHAList.conf")
	writeFile(t, list, "192.0.2.10")
	cfg := &MainConfig{Sites: []AllSiteRuleSet{{Host: "default_site", RulePath: first}, {Host: "other.example", RulePath: second}}}
	manager := &ConfigManager{}
	shared := &dataType.SharedMemory{}
	if err := manager.Reload(cfg, shared); err != nil {
		t.Fatal(err)
	}
	old := manager.Get()
	if !old.SiteRules["other.example"].IPCAPTCHARule.Trie.IsEmpty() {
		t.Fatal("list leaked across sites")
	}
	writeFile(t, list, "192.0.2.11")
	if err := manager.Reload(cfg, shared); err != nil {
		t.Fatal(err)
	}
	current := manager.Get()
	trie := current.SiteRules["default_site"].IPCAPTCHARule.Trie
	if trie.Search(net.ParseIP("192.0.2.10")) || !trie.Search(net.ParseIP("192.0.2.11")) {
		t.Fatal("reload did not replace list")
	}
	if !old.SiteRules["default_site"].IPCAPTCHARule.Trie.Search(net.ParseIP("192.0.2.10")) {
		t.Fatal("old snapshot mutated")
	}
	if err := os.Remove(list); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(cfg, shared); err == nil {
		t.Fatal("missing enabled list accepted")
	}
	if manager.Get() != current {
		t.Fatal("failed reload replaced snapshot")
	}
}
