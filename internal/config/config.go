package config

import "fmt"

var GlobalConfig *MainConfig

// LoadMainConfig reads the configuration file and returns the configuration object.
func LoadMainConfig(basePath string) (*MainConfig, error) {
	configPath := resolveConfigPath(basePath)
	cfg := DefaultMainConfig()

	data, err := readConfigFile(configPath)
	if err != nil {
		return cfg, fmt.Errorf("failed to read configuration file at %s: %w", configPath, err)
	}

	if err := decodeConfig(data, cfg); err != nil {
		return DefaultMainConfig(), fmt.Errorf("failed to parse configuration file at %s: %w", configPath, err)
	}

	validateMainConfig(cfg)

	return cfg, nil
}
