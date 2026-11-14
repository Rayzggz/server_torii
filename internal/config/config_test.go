package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeMainConfig writes a torii.yml holding extra and returns its directory. Unless extra
// lists sites itself, the file gets one valid site.
func writeMainConfig(t *testing.T, extra string) string {
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
		"invalid YAML":         {"port: [invalid", "failed to parse"},
		"unknown key":          {"prot: \"8080\"", `unknown field "prot"`},
		"unknown site key":     {"sites:\n  - id: a\n    rule_path: .\n    host: example.com", `unknown field "host"`},
		"removed header key":   {"connecting_ip_headers: [X-Real-IP]", `unknown field "connecting_ip_headers"`},
		"wrong type":           {"enable_gossip: maybe", "cannot unmarshal"},
		"bad port":             {"port: \"70000\"", "port: value must be a port number"},
		"bad web path":         {"web_path: torii", "web_path: value must start with /"},
		"bad listen address":   {"listen: [\"nowhere\"]", "listen[0]: value must be host:port or unix:/path/to.sock"},
		"bad socket mode":      {"unix_socket_mode: \"rw\"", "unix_socket_mode: value must be octal"},
		"missing rule dir":     {"sites:\n  - id: a\n    rule_path: /no/such/dir", "sites[0].rule_path: path must be an existing directory"},
		"invalid site id":      {"sites:\n  - id: example.com\n    rule_path: .", "sites[0].id: value must be 1 to 32 letters, digits or underscores"},
		"missing site id":      {"sites:\n  - rule_path: .", "sites[0].id"},
		"duplicate site id":    {"sites:\n  - id: a\n    rule_path: .\n  - id: a\n    rule_path: .", `sites[1].id: duplicate id "a"`},
		"no sites":             {"sites: []", "sites: list needs at least 1 entry"},
		"unknown default site": {"default_site: nowhere", `default_site: "nowhere" is not one of the configured sites`},
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
	_, err := LoadMainConfig(writeMainConfig(t, "port: \"0\"\nweb_path: torii\ndefault_site: nowhere"))
	if err == nil {
		t.Fatal("no error")
	}
	for _, want := range []string{"port:", "web_path:", "default_site:"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error lacks %q:\n%v", want, err)
		}
	}
}

func TestLoadMainConfig_PartialConfigKeepsDefaults(t *testing.T) {
	dir := writeMainConfig(t, "port: \"8080\"\nweb_path: \"/custom\"\nnode_name: \"custom-node\"")

	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if cfg.Port != "8080" || cfg.WebPath != "/custom" || cfg.NodeName != "custom-node" {
		t.Fatalf("configured values lost: %+v", cfg)
	}
	if cfg.ConfigDir != dir {
		t.Fatalf("ConfigDir = %q, want %q", cfg.ConfigDir, dir)
	}
	if cfg.ErrorPage != DefaultErrorPage || cfg.LogPath != DefaultLogPath || cfg.DefaultSite != DefaultSiteID {
		t.Fatalf("defaults lost: %+v", cfg)
	}
	if cfg.EnableGossip || len(cfg.Peers) != 0 {
		t.Fatalf("gossip = %v, peers = %v, want none", cfg.EnableGossip, cfg.Peers)
	}
}

func TestLoadMainConfig_FullConfig(t *testing.T) {
	dir := writeMainConfig(t, "port: \"8081\"\nweb_path: \"/edge\"\nerror_page: \"/tmp/errors\"\nlog_path: \"/tmp/logs/\"\n"+
		"global_secret: \"12345678901234567890123456789012\"\nnode_name: \"node-a\"\nenable_gossip: true\n"+
		"listen: [\"127.0.0.1:8081\", \"unix:/run/torii.sock\"]\nlog_listen: [\"unix:/run/torii_log.sock\"]\nunix_socket_mode: \"0660\"\n"+
		"peers:\n  - name: \"peer-a\"\n    address: \"https://example.com\"\n    host: \"peer.example.com\"")

	cfg, err := LoadMainConfig(dir)
	if err != nil {
		t.Fatalf("LoadMainConfig: %v", err)
	}
	if cfg.Port != "8081" || cfg.WebPath != "/edge" || cfg.ErrorPage != "/tmp/errors" || cfg.LogPath != "/tmp/logs/" {
		t.Fatalf("wrong values: %+v", cfg)
	}
	if cfg.GlobalSecret != "12345678901234567890123456789012" || !cfg.EnableGossip || cfg.NodeName != "node-a" {
		t.Fatalf("wrong gossip values: %+v", cfg)
	}
	if len(cfg.Listen) != 2 || len(cfg.LogListen) != 1 || cfg.SocketMode() != 0o660 {
		t.Fatalf("wrong listen values: %+v", cfg)
	}
	if len(cfg.Peers) != 1 || cfg.Peers[0].Address != "https://example.com" || cfg.Peers[0].Host != "peer.example.com" {
		t.Fatalf("Peers = %v", cfg.Peers)
	}
}

// The shipped example must stay loadable; only its paths are specific to an installation.
func TestLoadMainConfig_Example(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", "config_example", "torii.yml"))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	text := strings.ReplaceAll(string(example), "/www/server_torii/config/rules/default", filepath.ToSlash(dir))
	text = strings.ReplaceAll(text, "/www/server_torii/config/rules/example.com", filepath.ToSlash(dir))
	writeFile(t, filepath.Join(dir, "torii.yml"), text)

	if _, err := LoadMainConfig(dir); err != nil {
		t.Fatalf("the example configuration does not load: %v", err)
	}
}
