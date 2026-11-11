package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

func TestLoadMainConfig_WarnsOnExampleGlobalSecret(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config_example", "torii.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "torii.yml"), example, 0o644); err != nil {
		t.Fatal(err)
	}

	logs := captureLog(t)
	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if cfg.GlobalSecret != DefaultGlobalSecret {
		t.Fatalf("example global_secret = %q, no longer DefaultGlobalSecret; update this test", cfg.GlobalSecret)
	}
	if !strings.Contains(logs.String(), "[WARNING] Configuration issue in MainConfig.GlobalSecret") {
		t.Fatalf("no warning for the public secret; logs:\n%s", logs.String())
	}
}

func TestLoadMainConfig_NoWarningForOwnGlobalSecret(t *testing.T) {
	dir := t.TempDir()
	content := "global_secret: \"9f86d081884c7d659a2feaa0c55ad015\"\n"
	if err := os.WriteFile(filepath.Join(dir, "torii.yml"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	logs := captureLog(t)
	if _, err := LoadMainConfig(dir); err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if strings.Contains(logs.String(), "GlobalSecret") {
		t.Fatalf("unexpected GlobalSecret warning:\n%s", logs.String())
	}
}

func TestWarnPublicGlobalSecret(t *testing.T) {
	captureLog(t)
	if !warnPublicGlobalSecret(&MainConfig{GlobalSecret: DefaultGlobalSecret}) {
		t.Fatal("default secret not flagged")
	}
	if warnPublicGlobalSecret(DefaultMainConfig()) {
		t.Fatal("randomly generated default secret flagged")
	}
}
