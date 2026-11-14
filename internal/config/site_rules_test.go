package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotSite(t *testing.T) {
	shop, fallback := &RuleSet{ID: "shop"}, &RuleSet{ID: "fallback"}
	snap := &SiteConfigSnapshot{
		SiteRules:   map[string]*RuleSet{"shop": shop, "fallback": fallback},
		DefaultSite: "fallback",
	}
	if got := snap.Site("shop"); got != shop {
		t.Errorf("Site(shop) = %+v", got)
	}
	// No ID selects the default site; an unknown ID selects nothing.
	if got := snap.Site(""); got != fallback {
		t.Errorf("Site(\"\") = %+v, want the default site", got)
	}
	if got := snap.Site("nope"); got != nil {
		t.Errorf("Site(nope) = %+v, want nil", got)
	}

	snap.DefaultSite = ""
	if got := snap.Site(""); got != nil {
		t.Errorf("Site(\"\") without a default site = %+v, want nil", got)
	}
}

// A site ID is also a directory name, so its characters are restricted.
func TestValidSiteID(t *testing.T) {
	for id, want := range map[string]bool{
		"shop":                  true,
		"default_site":          true,
		"bb68gmy3WvoPMy8arf":    true,
		strings.Repeat("a", 32): true,
		strings.Repeat("a", 33): false,
		"":                      false,
		"example.com":           false,
		"my-site":               false,
		"*.example.com":         false,
		"../etc":                false,
		"site one":              false,
	} {
		if got := ValidSiteID(id); got != want {
			t.Errorf("ValidSiteID(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestLoadSiteRulesIdentity(t *testing.T) {
	dir := t.TempDir()
	writeSite := func(name, analyzer string) string {
		t.Helper()
		siteDir := filepath.Join(dir, name)
		if err := os.MkdirAll(siteDir, 0o755); err != nil {
			t.Fatal(err)
		}
		for _, list := range []string{"IP_AllowList.conf", "IP_BlockList.conf", "URL_AllowList.conf", "URL_BlockList.conf"} {
			if err := os.WriteFile(filepath.Join(siteDir, list), nil, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(siteDir, "Server.yml"), []byte(analyzer), 0o644); err != nil {
			t.Fatal(err)
		}
		return siteDir
	}
	plain := writeSite("plain", "")
	// A "tag" left over from older configurations is ignored: reports name the site by its ID.
	tagged := writeSite("tagged", "AdaptiveTrafficAnalyzer:\n  enabled: true\n  tag: other_tag\n")

	// The site ID becomes the identity of the rule set.
	rules, err := LoadSiteRules(&MainConfig{Sites: []AllSiteRuleSet{{ID: "shop", RulePath: tagged}, {ID: "blog", RulePath: plain}}, DefaultSite: "blog"})
	if err != nil {
		t.Fatalf("LoadSiteRules: %v", err)
	}
	for _, id := range []string{"shop", "blog"} {
		if rules[id].ID != id {
			t.Errorf("site %s: ID %q", id, rules[id].ID)
		}
	}

	for name, tt := range map[string]struct {
		cfg  MainConfig
		want string
	}{
		"invalid id":      {MainConfig{Sites: []AllSiteRuleSet{{ID: "example.com", RulePath: plain}}}, "invalid id"},
		"missing id":      {MainConfig{Sites: []AllSiteRuleSet{{RulePath: plain}}}, "invalid id"},
		"legacy host key": {MainConfig{Sites: []AllSiteRuleSet{{Host: "example.com", RulePath: plain}}}, "no longer supported"},
		"duplicate id":    {MainConfig{Sites: []AllSiteRuleSet{{ID: "shop", RulePath: plain}, {ID: "shop", RulePath: plain}}}, "duplicate id"},
		"unknown default": {MainConfig{Sites: []AllSiteRuleSet{{ID: "shop", RulePath: plain}}, DefaultSite: "blog"}, "default_site"},
		"no sites":        {MainConfig{}, "no sites configured"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadSiteRules(&tt.cfg)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
		})
	}
}
