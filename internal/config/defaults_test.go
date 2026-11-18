package config

import "testing"

func TestDefaultMainConfig(t *testing.T) {
	cfg := DefaultMainConfig()

	if len(cfg.Listen) != 1 || cfg.Listen[0] != DefaultListen {
		t.Errorf("Listen = %v, want %q", cfg.Listen, DefaultListen)
	}
	if cfg.WebPath != DefaultWebPath {
		t.Errorf("WebPath = %q, want %q", cfg.WebPath, DefaultWebPath)
	}
	if cfg.GlobalSecret != "" {
		t.Errorf("GlobalSecret = %q, want none: a secret must be configured, not defaulted", cfg.GlobalSecret)
	}
	// No site is the default unless the configuration names one.
	if len(cfg.Sites) != 1 || cfg.DefaultSite != "" {
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
