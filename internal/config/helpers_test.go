package config

import (
	"os"
	"path/filepath"
	"testing"
)

// decodeServerRules decodes the text of a Server.yml the way the loader does.
func decodeServerRules(data []byte) (ruleSetWrapper, error) {
	var wrapper ruleSetWrapper
	err := decodeStrict(data, &wrapper)
	return wrapper, err
}

func mustMkdirAll(t *testing.T, path string) {
	t.Helper()

	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatalf("MkdirAll(%q) failed: %v", path, err)
	}
}

func writeRuleFiles(t *testing.T, dir string, files map[string]string) {
	t.Helper()

	for name, content := range files {
		writeFile(t, filepath.Join(dir, name), content)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", path, err)
	}
}
