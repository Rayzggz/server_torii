package config

import (
	"strings"
	"testing"
)

// The secret only signs gossip, so it is only required, and only checked, when gossip is on.
func TestLoadMainConfig_GlobalSecret(t *testing.T) {
	for name, tt := range map[string]struct {
		yaml string
		want string // "" means the configuration loads
	}{
		"no gossip, no secret":      {"", ""},
		"no gossip, public secret":  {"global_secret: " + DefaultGlobalSecret, ""},
		"gossip, own secret":        {"enable_gossip: true\nglobal_secret: 9f86d081884c7d659a2feaa0c55ad015", ""},
		"gossip, no secret":         {"enable_gossip: true", "global_secret: field is required when gossip is enabled"},
		"gossip, short secret":      {"enable_gossip: true\nglobal_secret: short", "global_secret: value must be at least 32 characters long"},
		"gossip, public secret":     {"enable_gossip: true\nglobal_secret: " + DefaultGlobalSecret, "public value from the example configuration"},
		"no gossip, short secret":   {"global_secret: short", "global_secret: value must be at least 32 characters long"},
		"secret never in the error": {"enable_gossip: true\nglobal_secret: hunter2", "global_secret"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := LoadMainConfig(writeMainConfig(t, tt.yaml))
			if tt.want == "" {
				if err != nil {
					t.Fatalf("LoadMainConfig: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want one containing %q", err, tt.want)
			}
			if strings.Contains(err.Error(), "hunter2") {
				t.Fatalf("the error repeats the secret: %v", err)
			}
		})
	}
}
