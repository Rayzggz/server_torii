package config

import (
	"net"
	"path/filepath"
	"server_torii/internal/iptrie"
	"server_torii/internal/urllist"
	"strings"
	"testing"
)

func TestLoadIPRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "IP_BlockList.conf")
	writeFile(t, path, "# office range\n10.0.0.0/8\n\n  # indented comment\n192.0.2.1\n")

	trie := &iptrie.TrieNode{}
	if err := loadIPRules(path, trie); err != nil {
		t.Fatalf("loadIPRules: %v", err)
	}
	if !trie.Search(net.ParseIP("10.1.2.3")) || !trie.Search(net.ParseIP("192.0.2.1")) {
		t.Fatal("valid entries were not loaded")
	}

	// A line that is not an address rejects the file: skipping it would drop a rule unnoticed.
	writeFile(t, path, "10.0.0.0/8\n\n# comment\nnot-an-ip\n192.0.2.1\n")
	err := loadIPRules(path, &iptrie.TrieNode{})
	if err == nil || !strings.Contains(err.Error(), path+":4:") || !strings.Contains(err.Error(), `"not-an-ip"`) {
		t.Fatalf("error = %v, want file:line and the value", err)
	}
}

func TestLoadURLRules(t *testing.T) {
	path := filepath.Join(t.TempDir(), "URL_BlockList.conf")
	writeFile(t, path, "# admin paths\n/admin\n^/api/.*$\n")

	list := &urllist.URLRuleList{}
	if err := loadURLRules(path, list); err != nil {
		t.Fatalf("loadURLRules: %v", err)
	}
	if list.Match("# admin paths") {
		t.Fatal("comment line was loaded as a pattern")
	}
	if !list.Match("/admin") || !list.Match("/api/x") {
		t.Fatal("valid entries were not loaded")
	}

	writeFile(t, path, "/admin\n^/bad[regex$\n")
	err := loadURLRules(path, &urllist.URLRuleList{})
	if err == nil || !strings.Contains(err.Error(), path+":2:") || !strings.Contains(err.Error(), "invalid regex") {
		t.Fatalf("error = %v, want file:line and the reason", err)
	}
}
