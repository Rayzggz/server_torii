package config

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMainConfig_MissingFileFallsBackToDefaults(t *testing.T) {
	tempDir := t.TempDir()

	cfg, err := LoadMainConfig(tempDir)
	if err == nil {
		t.Fatal("LoadMainConfig error = nil, want read error")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("LoadMainConfig error = %v, want os.ErrNotExist", err)
	}

	want := DefaultMainConfig()
	assertMainConfigEqual(t, cfg, want)
}

func TestLoadMainConfig_InvalidYAMLFallsBackToDefaults(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "torii.yml")
	if err := os.WriteFile(configPath, []byte("port: [invalid"), 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := LoadMainConfig(tempDir)
	if err == nil {
		t.Fatal("LoadMainConfig error = nil, want YAML parse error")
	}

	want := DefaultMainConfig()
	assertMainConfigEqual(t, cfg, want)
}

func TestLoadMainConfig_ValidPartialConfigOverlaysDefaults(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "torii.yml")
	content := []byte("port: \"8080\"\nweb_path: \"/custom\"\nnode_name: \"custom-node\"\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := LoadMainConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadMainConfig returned unexpected error: %v", err)
	}

	if cfg.Port != "8080" {
		t.Fatalf("Port = %q, want %q", cfg.Port, "8080")
	}
	if cfg.WebPath != "/custom" {
		t.Fatalf("WebPath = %q, want %q", cfg.WebPath, "/custom")
	}
	if cfg.NodeName != "custom-node" {
		t.Fatalf("NodeName = %q, want %q", cfg.NodeName, "custom-node")
	}
	if cfg.ErrorPage != DefaultErrorPage {
		t.Fatalf("ErrorPage = %q, want default %q", cfg.ErrorPage, DefaultErrorPage)
	}
	if cfg.LogPath != DefaultLogPath {
		t.Fatalf("LogPath = %q, want default %q", cfg.LogPath, DefaultLogPath)
	}
	if cfg.EnableGossip {
		t.Fatal("EnableGossip = true, want default false")
	}
	if len(cfg.ConnectingHostHeaders) != len(DefaultConnectingHostHeaders) || cfg.ConnectingHostHeaders[0] != DefaultConnectingHostHeaders[0] {
		t.Fatalf("ConnectingHostHeaders = %v, want %v", cfg.ConnectingHostHeaders, DefaultConnectingHostHeaders)
	}
	if len(cfg.Sites) != len(DefaultSites) || cfg.Sites[0] != DefaultSites[0] {
		t.Fatalf("Sites = %v, want %v", cfg.Sites, DefaultSites)
	}
	if len(cfg.Peers) != 0 {
		t.Fatalf("Peers = %v, want empty slice when gossip is disabled and peers are omitted", cfg.Peers)
	}
}

func TestLoadMainConfig_ValidFullConfigUsesDecodedValues(t *testing.T) {
	tempDir := t.TempDir()
	ruleDir := filepath.Join(tempDir, "rules")
	if err := os.Mkdir(ruleDir, 0o755); err != nil {
		t.Fatalf("Mkdir failed: %v", err)
	}

	configPath := filepath.Join(tempDir, "torii.yml")
	content := []byte("port: \"8081\"\nweb_path: \"/edge\"\nerror_page: \"/tmp/errors\"\nlog_path: \"/tmp/logs/\"\nglobal_secret: \"12345678901234567890123456789012\"\nnode_name: \"node-a\"\nenable_gossip: true\nconnecting_host_headers:\n  - \"X-Host\"\nconnecting_ip_headers:\n  - \"X-IP\"\nconnecting_uri_headers:\n  - \"X-URI\"\nconnecting_feature_control_headers:\n  - \"X-Feature\"\nsites:\n  - host: \"default_site\"\n    rule_path: \"" + filepath.ToSlash(ruleDir) + "\"\npeers:\n  - name: \"peer-a\"\n    address: \"https://example.com\"\n    host: \"peer.example.com\"\n")
	if err := os.WriteFile(configPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	cfg, err := LoadMainConfig(tempDir)
	if err != nil {
		t.Fatalf("LoadMainConfig returned unexpected error: %v", err)
	}

	if cfg.Port != "8081" {
		t.Fatalf("Port = %q, want %q", cfg.Port, "8081")
	}
	if cfg.WebPath != "/edge" {
		t.Fatalf("WebPath = %q, want %q", cfg.WebPath, "/edge")
	}
	if cfg.ErrorPage != "/tmp/errors" {
		t.Fatalf("ErrorPage = %q, want %q", cfg.ErrorPage, "/tmp/errors")
	}
	if cfg.LogPath != "/tmp/logs/" {
		t.Fatalf("LogPath = %q, want %q", cfg.LogPath, "/tmp/logs/")
	}
	if cfg.GlobalSecret != "12345678901234567890123456789012" {
		t.Fatalf("GlobalSecret = %q, want full decoded value", cfg.GlobalSecret)
	}
	if !cfg.EnableGossip {
		t.Fatal("EnableGossip = false, want true")
	}
	if len(cfg.ConnectingHostHeaders) != 1 || cfg.ConnectingHostHeaders[0] != "X-Host" {
		t.Fatalf("ConnectingHostHeaders = %v, want [X-Host]", cfg.ConnectingHostHeaders)
	}
	if len(cfg.Sites) != 1 || cfg.Sites[0].RulePath != filepath.ToSlash(ruleDir) {
		t.Fatalf("Sites = %v, want decoded site rule path", cfg.Sites)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Address != "https://example.com" {
		t.Fatalf("Peers = %v, want decoded peer", cfg.Peers)
	}
}

func assertMainConfigEqual(t *testing.T, got, want *MainConfig) {
	t.Helper()

	if got.Port != want.Port {
		t.Fatalf("Port = %q, want %q", got.Port, want.Port)
	}
	if got.WebPath != want.WebPath {
		t.Fatalf("WebPath = %q, want %q", got.WebPath, want.WebPath)
	}
	if got.ErrorPage != want.ErrorPage {
		t.Fatalf("ErrorPage = %q, want %q", got.ErrorPage, want.ErrorPage)
	}
	if got.LogPath != want.LogPath {
		t.Fatalf("LogPath = %q, want %q", got.LogPath, want.LogPath)
	}
	assertGlobalSecretValid(t, got.GlobalSecret)
	assertGlobalSecretValid(t, want.GlobalSecret)
	if got.NodeName != want.NodeName {
		t.Fatalf("NodeName = %q, want %q", got.NodeName, want.NodeName)
	}
	if got.EnableGossip != want.EnableGossip {
		t.Fatalf("EnableGossip = %v, want %v", got.EnableGossip, want.EnableGossip)
	}
	if len(got.ConnectingHostHeaders) != len(want.ConnectingHostHeaders) || got.ConnectingHostHeaders[0] != want.ConnectingHostHeaders[0] {
		t.Fatalf("ConnectingHostHeaders = %v, want %v", got.ConnectingHostHeaders, want.ConnectingHostHeaders)
	}
	if len(got.ConnectingIPHeaders) != len(want.ConnectingIPHeaders) || got.ConnectingIPHeaders[0] != want.ConnectingIPHeaders[0] {
		t.Fatalf("ConnectingIPHeaders = %v, want %v", got.ConnectingIPHeaders, want.ConnectingIPHeaders)
	}
	if len(got.ConnectingURIHeaders) != len(want.ConnectingURIHeaders) || got.ConnectingURIHeaders[0] != want.ConnectingURIHeaders[0] {
		t.Fatalf("ConnectingURIHeaders = %v, want %v", got.ConnectingURIHeaders, want.ConnectingURIHeaders)
	}
	if len(got.ConnectingFeatureControlHeaders) != len(want.ConnectingFeatureControlHeaders) || got.ConnectingFeatureControlHeaders[0] != want.ConnectingFeatureControlHeaders[0] {
		t.Fatalf("ConnectingFeatureControlHeaders = %v, want %v", got.ConnectingFeatureControlHeaders, want.ConnectingFeatureControlHeaders)
	}
	if len(got.Sites) != len(want.Sites) || got.Sites[0] != want.Sites[0] {
		t.Fatalf("Sites = %v, want %v", got.Sites, want.Sites)
	}
	if len(got.Peers) != len(want.Peers) {
		t.Fatalf("Peers length = %d, want %d", len(got.Peers), len(want.Peers))
	}
}

func assertGlobalSecretValid(t *testing.T, secret string) {
	t.Helper()

	if len(secret) != 32 {
		t.Fatalf("GlobalSecret length = %d, want %d", len(secret), 32)
	}
	if _, err := hex.DecodeString(secret); err != nil {
		t.Fatalf("GlobalSecret = %q, want valid hex: %v", secret, err)
	}
}
