package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// testGlobalSecret is the secret of the configurations that do not set their own.
const testGlobalSecret = "test-only-global-secret-0123456789"

// writeMainConfig writes a torii.yml holding extra and returns its directory. Unless extra
// lists sites itself, the file gets one valid site; unless it sets a secret, a valid one.
func writeMainConfig(t *testing.T, extra string) string {
	t.Helper()
	if !strings.Contains(extra, "global_secret:") {
		extra += "\nglobal_secret: " + testGlobalSecret
	}
	return writeRawMainConfig(t, extra)
}

// writeRawMainConfig is writeMainConfig without the secret.
func writeRawMainConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	rules := filepath.Join(dir, "rules")
	mustMkdirAll(t, rules)
	sites := "sites:\n  - id: default_site\n    rule_path: \"" + filepath.ToSlash(rules) + "\"\n"
	if strings.HasPrefix(extra, "sites:") {
		sites = "default_site: \"\"\n"
	}
	writeFile(t, filepath.Join(dir, "torii.yml"), sites+extra+"\n")
	return dir
}

func TestLoadMainConfig_MissingFile(t *testing.T) {
	cfg, err := LoadMainConfig(t.TempDir())
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("error = %v, want os.ErrNotExist", err)
	}
	if cfg != nil {
		t.Fatalf("config = %+v, want none: a missing file must not fall back to defaults", cfg)
	}
}

func TestLoadMainConfig_Rejects(t *testing.T) {
	for name, tt := range map[string]struct {
		yaml string
		want string
	}{
		"invalid YAML":         {"listen: [invalid", "failed to parse"},
		"unknown key":          {"prot: \"8080\"", `unknown field "prot"`},
		"unknown site key":     {"sites:\n  - id: a\n    rule_path: .\n    host: example.com", `unknown field "host"`},
		"removed header key":   {"connecting_ip_headers: [X-Real-IP]", `unknown field "connecting_ip_headers"`},
		"wrong type":           {"enable_gossip: maybe", "cannot unmarshal"},
		"removed port":         {"port: \"25555\"", `unknown field "port"`},
		"no listen address":    {"listen: []", "listen: list needs at least 1 entry"},
		"bad port":             {"listen: [\"127.0.0.1:70000\"]", "listen[0]: value must be host:port or unix:/path/to.sock"},
		"no report address":    {"listen: [\"unix:/run/torii.sock\"]", "log_listen: field is required when listen has no TCP address"},
		"missing site pages":   {"sites:\n  - id: a\n    rule_path: .\n    error_page: /no/such/dir", "sites[0].error_page: path must be an existing directory"},
		"bad web path":         {"web_path: torii", "web_path: value must start with /"},
		"bad listen address":   {"listen: [\"nowhere\"]", "listen[0]: value must be host:port or unix:/path/to.sock"},
		"bad socket mode":      {"unix_socket_mode: \"rw\"", "unix_socket_mode: value must be octal"},
		"missing rule dir":     {"sites:\n  - id: a\n    rule_path: /no/such/dir", "sites[0].rule_path: path must be an existing directory"},
		"invalid site id":      {"sites:\n  - id: example.com\n    rule_path: .", "sites[0].id: value must be 1 to 32 letters, digits or underscores"},
		"missing site id":      {"sites:\n  - rule_path: .", "sites[0].id"},
		"duplicate site id":    {"sites:\n  - id: a\n    rule_path: .\n  - id: a\n    rule_path: .", `sites[1].id: duplicate id "a"`},
		"no sites":             {"sites: []", "sites: list needs at least 1 entry"},
		"unknown default site": {"default_site: nowhere", `default_site: "nowhere" is not one of the configured sites`},
		"second document":      {"web_path: /torii\n---\nweb_path: /other", "more than one YAML document"},
		"bad log level":        {"log_level: verbose", "log_level: value must be one of: debug info warn error"},
		"bad peer address":     {"peers:\n  - name: b\n    address: not-a-url", "peers[0].address: value must be a valid URL"},
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadMainConfig(writeMainConfig(t, tt.yaml))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
			if cfg != nil {
				t.Fatal("a rejected configuration was returned")
			}
		})
	}
}

// Every problem is reported at once, so one start attempt is enough to fix the file.
func TestLoadMainConfig_ReportsEveryProblem(t *testing.T) {
	_, err := LoadMainConfig(writeMainConfig(t, "listen: [\":0\"]\nweb_path: torii\ndefault_site: nowhere"))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"listen[0]:", "web_path:", "default_site:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestLoadMainConfig_PartialConfigKeepsDefaults(t *testing.T) {
	dir := writeMainConfig(t, "listen: [\":8080\"]\nweb_path: \"/custom\"\nnode_name: \"custom-node\"")

	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if len(cfg.Listen) != 1 || cfg.Listen[0] != ":8080" || cfg.WebPath != "/custom" || cfg.NodeName != "custom-node" {
		t.Fatalf("configured values lost: %+v", cfg)
	}
	if cfg.ConfigDir != dir {
		t.Fatalf("ConfigDir = %q, want %q", cfg.ConfigDir, dir)
	}
	if cfg.ErrorPage != DefaultErrorPage || cfg.LogPath != DefaultLogPath || cfg.DefaultSite != "" || cfg.LogLevel != "info" {
		t.Fatalf("defaults lost: %+v", cfg)
	}
	if cfg.EnableGossip || len(cfg.Peers) != 0 {
		t.Fatalf("gossip is on or has peers: %+v", cfg)
	}
	if got := cfg.LogListenAddrs(); len(got) != 1 || got[0] != "127.0.0.1:8080" {
		t.Fatalf("report address = %v, want the loopback address on the port of listen", got)
	}
}

func TestLoadMainConfig_FullConfig(t *testing.T) {
	dir := writeMainConfig(t, "web_path: \"/edge\"\nerror_page: \"/tmp/errors\"\nlog_path: \"/tmp/logs/\"\n"+
		"global_secret: \"12345678901234567890123456789012\"\nnode_name: \"node-a\"\n"+
		"listen: [\"127.0.0.1:8081\", \"unix:/run/torii.sock\"]\nlog_listen: [\"unix:/run/torii_log.sock\"]\nunix_socket_mode: \"0660\"\n"+
		"enable_gossip: true\npeers:\n  - name: \"peer-a\"\n    address: \"https://example.com\"\n    host: \"peer.example.com\"")

	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if cfg.WebPath != "/edge" || cfg.ErrorPage != "/tmp/errors" || cfg.LogPath != "/tmp/logs/" {
		t.Fatalf("wrong values: %+v", cfg)
	}
	if cfg.GlobalSecret != "12345678901234567890123456789012" || !cfg.EnableGossip || cfg.NodeName != "node-a" {
		t.Fatalf("wrong gossip values: %+v", cfg)
	}
	if len(cfg.Listen) != 2 || len(cfg.LogListen) != 1 || cfg.SocketMode() != 0o660 {
		t.Fatalf("wrong listen values: %+v", cfg)
	}
	if peers := cfg.Peers; len(peers) != 1 || peers[0].Address != "https://example.com" || peers[0].Host != "peer.example.com" {
		t.Fatalf("Peers = %v", peers)
	}
}

// The shipped example must stay loadable once it has a secret of its own; only that and its
// paths are specific to an installation. As shipped it is refused, for the secret alone.
func TestLoadMainConfig_Example(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config_example", "torii.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	text := strings.ReplaceAll(string(example), "/www/server_torii/config/rules/default", filepath.ToSlash(dir))
	text = strings.ReplaceAll(text, "/www/server_torii/config/rules/example.com", filepath.ToSlash(dir))
	writeFile(t, filepath.Join(dir, "torii.yml"), text)
	_, err = LoadMainConfig(dir)
	if err == nil || strings.Count(err.Error(), "\n") != 1 || !strings.Contains(err.Error(), "global_secret: this is the public value") {
		t.Fatalf("the example as shipped: error = %v, want the public secret refused and nothing else", err)
	}

	writeFile(t, filepath.Join(dir, "torii.yml"), strings.ReplaceAll(text, DefaultGlobalSecret, testGlobalSecret))
	if _, err := LoadMainConfig(dir); err != nil {
		t.Fatalf("the example configuration does not load: %v", err)
	}
}
