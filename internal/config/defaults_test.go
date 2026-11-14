package config

import "testing"

func TestDefaultMainConfig(t *testing.T) {
	cfg := DefaultMainConfig()

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %q, want %q", cfg.Port, DefaultPort)
	}
	if cfg.WebPath != DefaultWebPath {
		t.Errorf("WebPath = %q, want %q", cfg.WebPath, DefaultWebPath)
	}
	if cfg.GlobalSecret != "" {
		t.Errorf("GlobalSecret = %q, want none: a secret must be configured, not defaulted", cfg.GlobalSecret)
	}
	if len(cfg.Sites) != 1 || cfg.DefaultSite != cfg.Sites[0].ID {
		t.Errorf("Sites = %v, DefaultSite = %q", cfg.Sites, cfg.DefaultSite)
	}
}

func TestDefaultMainConfig_ReturnsCopies(t *testing.T) {
	cfg1 := DefaultMainConfig()
	cfg2 := DefaultMainConfig()

	cfg1.Sites[0].ID = "modified"
	if cfg2.Sites[0].ID == "modified" {
		t.Error("DefaultMainConfig should return independent copies of slices")
	}
}
