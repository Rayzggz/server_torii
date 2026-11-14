package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// decodeServerRules decodes the text of a Server.yml the way the loader does.
func decodeServerRules(data []byte) (ruleSetWrapper, error) {
	var wrapper ruleSetWrapper
	err := decodeStrict(data, &wrapper)
	return wrapper, err
}

// siteDirectory makes the directory of a site whose Server.yml has the given sections; the
// sections left out are added, switched off.
func siteDirectory(t *testing.T, settings string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "Server.yml"), settings)
	return dir
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

// disabledSections is a complete Server.yml with every check switched off, by section.
var disabledSections = []struct{ name, text string }{
	{"Lists", "Lists: []\n"},
	{"CountryRule", "CountryRule: {enabled: false}\n"},
	{"Challenge", "Challenge: {enabled: false, mode: hcaptcha, clearance_ttl: 60, session_ttl: 120, failure_limit: [\"3/1m\"], failure_block_duration: 60}\n"},
	{"HTTPFlood", "HTTPFlood: {enabled: false, HTTPFloodSpeedLimit: [\"5/10s\"], HTTPFloodSameURILimit: [\"3/10s\"], HTTPFloodFailureLimit: [\"3/30s\"], failure_block_duration: 300}\n"},
	{"VerifyBot", "VerifyBot: {enabled: false}\n"},
	{"AdaptiveTrafficAnalyzer", "AdaptiveTrafficAnalyzer: {enabled: false}\n"},
	{"CustomRules", "CustomRules: {enabled: false}\n"},
}

// completeServerRules adds, switched off, every section the text of a Server.yml leaves out, so
// a test only writes the sections it is about.
func completeServerRules(content string) string {
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	for _, section := range disabledSections {
		if !strings.HasPrefix(content, section.name+":") && !strings.Contains(content, "\n"+section.name+":") {
			content += section.text
		}
	}
	return content
}

// writeFile writes a file of a site. A Server.yml is completed with the sections it leaves out;
// writeRawFile writes it as it is.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if filepath.Base(path) == "Server.yml" {
		content = completeServerRules(content)
	}
	writeRawFile(t, path, content)
}

func writeRawFile(t *testing.T, path, content string) {
	t.Helper()

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%q) failed: %v", path, err)
	}
}
