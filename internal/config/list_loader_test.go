package config

import (
	"net"
	"path/filepath"
	"server_torii/internal/iptrie"
	"server_torii/internal/urllist"
	"strings"
	"testing"
)

func TestLoadIPRules_CommentsSkippedInvalidLogged(t *testing.T) {
	buf := captureLog(t)
	path := filepath.Join(t.TempDir(), "IP_BlockList.conf")
	writeFile(t, path, "# office range\n10.0.0.0/8\n\n  # indented comment\nnot-an-ip\n192.0.2.1\n")

	trie := &iptrie.TrieNode{}
	if err := loadIPRules(path, trie); err != nil {
		t.Fatalf("loadIPRules: %v", err)
	}
	if !trie.Search(net.ParseIP("10.1.2.3")) || !trie.Search(net.ParseIP("192.0.2.1")) {
		t.Fatal("valid entries were not loaded")
	}

	out := buf.String()
	if strings.Count(out, "[WARNING]") != 1 {
		t.Fatalf("want exactly one warning, got:\n%s", out)
	}
	if !strings.Contains(out, path+":5:") || !strings.Contains(out, `"not-an-ip"`) {
		t.Fatalf("warning lacks file:line or value:\n%s", out)
	}
}

func TestLoadURLRules_CommentsSkippedInvalidLogged(t *testing.T) {
	buf := captureLog(t)
	path := filepath.Join(t.TempDir(), "URL_BlockList.conf")
	writeFile(t, path, "# admin paths\n/admin\n^/bad[regex$\n^/api/.*$\n")

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

	out := buf.String()
	if strings.Count(out, "[WARNING]") != 1 {
		t.Fatalf("want exactly one warning, got:\n%s", out)
	}
	if !strings.Contains(out, path+":3:") || !strings.Contains(out, "invalid regex") {
		t.Fatalf("warning lacks file:line or reason:\n%s", out)
	}
}
