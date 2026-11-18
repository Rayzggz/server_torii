package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// The secret signs the cookies of every site, so it is always required. The public example
// value is refused once it would also sign gossip.
func TestLoadMainConfig_GlobalSecret(t *testing.T) {
	for name, tt := range map[string]struct {
		yaml string
		want string // "" means the configuration loads
	}{
		"no secret":                 {"", "global_secret: field is required"},
		"empty secret":              {"global_secret: \"\"", "global_secret: field is required"},
		"own secret":                {"global_secret: 9f86d081884c7d659a2feaa0c55ad015", ""},
		"no gossip, public secret":  {"global_secret: " + DefaultGlobalSecret, "public value from the example configuration"},
		"gossip, own secret":        {"enable_gossip: true\nglobal_secret: 9f86d081884c7d659a2feaa0c55ad015", ""},
		"gossip, no secret":         {"enable_gossip: true", "global_secret: field is required"},
		"gossip, short secret":      {"enable_gossip: true\nglobal_secret: short", "global_secret: value must be at least 32 characters long"},
		"gossip, public secret":     {"enable_gossip: true\nglobal_secret: " + DefaultGlobalSecret, "public value from the example configuration"},
		"no gossip, short secret":   {"global_secret: short", "global_secret: value must be at least 32 characters long"},
		"secret never in the error": {"enable_gossip: true\nglobal_secret: hunter2", "global_secret"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadMainConfig(writeRawMainConfig(t, tt.yaml))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("LoadMainConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("the error repeats the secret: %v", err)
			}
		})
	}
}

// The key that signs the cookies depends on the global secret alone: nodes that share the secret
// share the key, and it is not the secret itself, which also signs gossip.
func TestCookieKey(t *testing.T) {
	a := &MainConfig{GlobalSecret: "9f86d081884c7d659a2feaa0c55ad015", NodeName: "a"}
	b := &MainConfig{GlobalSecret: "9f86d081884c7d659a2feaa0c55ad015", NodeName: "b", EnableGossip: true}
	other := &MainConfig{GlobalSecret: "0f86d081884c7d659a2feaa0c55ad015"}
	// printf '%s' 'torii cookie key' | openssl dgst -sha256 -hmac 9f86d081884c7d659a2feaa0c55ad015
	const want = "ed57aa1aa0b3da5250ede1bed0c4f8631d80e0717409d93ec5c41d33749266ad"
	if a.CookieKey() != want {
		t.Errorf("CookieKey = %s", a.CookieKey())
	}
	if a.CookieKey() != b.CookieKey() || a.CookieKey() == other.CookieKey() || a.CookieKey() == a.GlobalSecret {
		t.Error("the cookie key must follow the global secret, and nothing else")
	}
}

// Every site signs its cookies with the key derived from the global secret. A site that sets no
// ALTCHA secret signs its challenges with it too.
func TestSitesGetTheCookieKey(t *testing.T) {
	dir := writeMainConfig(t, "")
	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(cfg.Sites[0].RulePath, "Server.yml"), "")
	sites, err := LoadSiteRules(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rule := sites["default_site"].Challenge
	if rule.CookieKey != cfg.CookieKey() || rule.AltchaHMACSecret != cfg.CookieKey() || rule.ExternalSecret != "" {
		t.Fatalf("rule = %+v", rule)
	}
}
