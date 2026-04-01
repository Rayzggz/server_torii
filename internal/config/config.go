package config

import "log"

var GlobalConfig *MainConfig

// LoadMainConfig reads the configuration file and returns the configuration object.
func LoadMainConfig(basePath string) (*MainConfig, error) {
	configPath := resolveConfigPath(basePath)
	cfg := DefaultMainConfig()

	data, err := readConfigFile(configPath)
	if err != nil {
		log.Printf("[WARNING] failed to read configuration file at %s, falling back to full default main config: %v", configPath, err)
		return cfg, nil
	}

	if err := decodeConfig(data, cfg); err != nil {
		log.Printf("[WARNING] failed to parse configuration file at %s, falling back to full default main config: %v", configPath, err)
		return DefaultMainConfig(), nil
	}

	validateMainConfig(cfg)

	return cfg, nil
}
