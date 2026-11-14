package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// LoadMainConfig reads and validates torii.yml. Keys the file leaves out keep their defaults.
// Any problem — a missing file, a YAML error, an unknown key, an invalid value — is an error:
// the server must not start on a configuration other than the one the operator wrote.
func LoadMainConfig(basePath string) (*MainConfig, error) {
	configPath := resolveConfigPath(basePath)
	cfg := DefaultMainConfig()
	cfg.ConfigDir = filepath.Dir(configPath)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read configuration file: %w", err)
	}
	if err := decodeStrict(data, cfg); err != nil {
		return nil, fmt.Errorf("failed to parse configuration file %s: %w", configPath, err)
	}
	if err := validateMainConfig(cfg); err != nil {
		return nil, fmt.Errorf("invalid configuration file %s:\n%w", configPath, err)
	}
	return cfg, nil
}
