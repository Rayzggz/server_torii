package config

import "testing"

func TestDefaultMainConfig_ReturnsFullConfig(t *testing.T) {
	cfg := DefaultMainConfig()

	if cfg.Port != DefaultPort {
		t.Errorf("Port = %q, want %q", cfg.Port, DefaultPort)
	}
	if cfg.WebPath != DefaultWebPath {
		t.Errorf("WebPath = %q, want %q", cfg.WebPath, DefaultWebPath)
	}
	if cfg.GlobalSecret != DefaultGlobalSecret {
		t.Errorf("GlobalSecret = %q, want %q", cfg.GlobalSecret, DefaultGlobalSecret)
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
