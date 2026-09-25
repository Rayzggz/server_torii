package config

import (
	"os"
	"path/filepath"
	"server_torii/internal/dataType"
	"testing"
)

func TestURLCaptchaConfiguration(t *testing.T) {
	for _, tt := range []struct {
		name, settings, list string
		missing, invalid     bool
	}{
		{"omitted", "", "", true, false},
		{"enabled missing", "URLCAPTCHA: { enabled: true }\n" + ipCaptchaSettings, "", true, true},
		{"enabled empty", "URLCAPTCHA: { enabled: true }\n" + ipCaptchaSettings, "", false, false},
		{"enabled no captcha", "URLCAPTCHA: { enabled: true }", "", false, true},
		{"invalid captcha", "URLCAPTCHA: { enabled: true }\nCAPTCHA: { enabled: false }", "/login", false, true},
		{"disabled populated no captcha", "URLCAPTCHA: { enabled: false }", "/login", false, true},
		{"disabled populated valid captcha", ipCaptchaSettings, "/login", false, false},
		{"invalid regex skipped", "", "^(\n\n", false, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := ipCaptchaDirectory(t, tt.settings)
			if !tt.missing {
				writeFile(t, filepath.Join(dir, "URL_CAPTCHAList.conf"), tt.list)
			}
			rules, err := LoadRules(dir)
			if (err != nil) != tt.invalid {
				t.Fatalf("error = %v, invalid = %t", err, tt.invalid)
			}
			if err == nil && (rules.URLCAPTCHARule == nil || rules.URLCAPTCHARule.List == nil) {
				t.Fatal("uninitialized rule")
			}
		})
	}
}

func TestURLCaptchaUsesURLAllowMatching(t *testing.T) {
	dir := ipCaptchaDirectory(t, ipCaptchaSettings)
	list := "/login\n^/admin(/|$)\n^(\n\n"
	writeFile(t, filepath.Join(dir, "URL_AllowList.conf"), list)
	writeFile(t, filepath.Join(dir, "URL_CAPTCHAList.conf"), list)
	rules, err := LoadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	for uri, want := range map[string]bool{"/login": true, "/login?next=/": false, "/admin": true, "/admin/users?a=1": true, "/administrator": false, "/other": false} {
		got := rules.URLCAPTCHARule.List.Match(uri)
		if got != want || got != rules.URLAllowRule.List.Match(uri) {
			t.Errorf("%s: match %t, want %t", uri, got, want)
		}
	}
}

func TestURLCaptchaReloadAndIsolation(t *testing.T) {
	first := ipCaptchaDirectory(t, "URLCAPTCHA: { enabled: true }\n"+ipCaptchaSettings)
	second := ipCaptchaDirectory(t, "")
	file := filepath.Join(first, "URL_CAPTCHAList.conf")
	writeFile(t, file, "/login")
	cfg := &MainConfig{Sites: []AllSiteRuleSet{{Host: "default_site", RulePath: first}, {Host: "other.example", RulePath: second}}}
	manager := &ConfigManager{}
	shared := &dataType.SharedMemory{}
	if err := manager.Reload(cfg, shared); err != nil {
		t.Fatal(err)
	}
	before := manager.Get()
	if before.SiteRules["other.example"].URLCAPTCHARule.List.Match("/login") {
		t.Fatal("cross-site list leak")
	}
	writeFile(t, file, "/admin")
	if err := manager.Reload(cfg, shared); err != nil {
		t.Fatal(err)
	}
	current := manager.Get()
	list := current.SiteRules["default_site"].URLCAPTCHARule.List
	if list.Match("/login") || !list.Match("/admin") {
		t.Fatal("list not replaced")
	}
	if !before.SiteRules["default_site"].URLCAPTCHARule.List.Match("/login") {
		t.Fatal("old snapshot mutated")
	}
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	if err := manager.Reload(cfg, shared); err == nil {
		t.Fatal("missing enabled list accepted")
	}
	if manager.Get() != current {
		t.Fatal("failed reload changed snapshot")
	}
}
