package config

import (
	"testing"
)

func TestApplyDefaultConfig_AllEmpty(t *testing.T) {
	cfg := &MainConfig{}
	applyDefaultConfig(cfg)

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %q, want %q", cfg.Port, DefaultPort)
	}
	if cfg.WebPath != DefaultWebPath {
		t.Errorf("WebPath = %q, want %q", cfg.WebPath, DefaultWebPath)
	}
	if cfg.ErrorPage != DefaultErrorPage {
		t.Errorf("ErrorPage = %q, want %q", cfg.ErrorPage, DefaultErrorPage)
	}
	if cfg.LogPath != DefaultLogPath {
		t.Errorf("LogPath = %q, want %q", cfg.LogPath, DefaultLogPath)
	}
	if cfg.NodeName != DefaultNodeName {
		t.Errorf("NodeName = %q, want %q", cfg.NodeName, DefaultNodeName)
	}
	if len(cfg.ConnectingHostHeaders) != 1 || cfg.ConnectingHostHeaders[0] != "Torii-Real-Host" {
		t.Errorf("ConnectingHostHeaders = %v, want %v", cfg.ConnectingHostHeaders, DefaultConnectingHostHeaders)
	}
	if len(cfg.ConnectingIPHeaders) != 1 || cfg.ConnectingIPHeaders[0] != "Torii-Real-IP" {
		t.Errorf("ConnectingIPHeaders = %v, want %v", cfg.ConnectingIPHeaders, DefaultConnectingIPHeaders)
	}
	if len(cfg.ConnectingURIHeaders) != 1 || cfg.ConnectingURIHeaders[0] != "Torii-Original-URI" {
		t.Errorf("ConnectingURIHeaders = %v, want %v", cfg.ConnectingURIHeaders, DefaultConnectingURIHeaders)
	}
	if len(cfg.ConnectingFeatureControlHeaders) != 1 || cfg.ConnectingFeatureControlHeaders[0] != "Torii-Feature-Control" {
		t.Errorf("ConnectingFeatureControlHeaders = %v, want %v", cfg.ConnectingFeatureControlHeaders, DefaultConnectingFeatureControlHeaders)
	}
	if len(cfg.Sites) != 1 || cfg.Sites[0].Host != "default_site" {
		t.Errorf("Sites = %v, want default_site entry", cfg.Sites)
	}
}

func TestApplyDefaultConfig_PreservesExisting(t *testing.T) {
	cfg := &MainConfig{
		Port:     "8080",
		WebPath:  "/custom",
		NodeName: "my-node",
	}
	applyDefaultConfig(cfg)

	if cfg.Port != "8080" {
		t.Errorf("Port should be preserved, got %q", cfg.Port)
	}
	if cfg.WebPath != "/custom" {
		t.Errorf("WebPath should be preserved, got %q", cfg.WebPath)
	}
	if cfg.NodeName != "my-node" {
		t.Errorf("NodeName should be preserved, got %q", cfg.NodeName)
	}
	// But empty fields should still get defaults
	if cfg.ErrorPage != DefaultErrorPage {
		t.Errorf("ErrorPage = %q, want %q", cfg.ErrorPage, DefaultErrorPage)
	}
}

func TestDefaultMainConfig_ReturnsFullConfig(t *testing.T) {
	cfg := DefaultMainConfig()

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %q, want %q", cfg.Port, DefaultPort)
	}
	if cfg.WebPath != DefaultWebPath {
		t.Errorf("WebPath = %q, want %q", cfg.WebPath, DefaultWebPath)
	}
	if len(cfg.Sites) != 1 {
		t.Errorf("Sites should have 1 entry, got %d", len(cfg.Sites))
	}
}

func TestDefaultMainConfig_ReturnsCopies(t *testing.T) {
	cfg1 := DefaultMainConfig()
	cfg2 := DefaultMainConfig()

	cfg1.ConnectingHostHeaders[0] = "modified"
	if cfg2.ConnectingHostHeaders[0] == "modified" {
		t.Error("DefaultMainConfig should return independent copies of slices")
	}
}
