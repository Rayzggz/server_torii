package config

import "log"

var GlobalConfig *MainConfig

// LoadMainConfig reads the configuration file and returns the configuration object.
func LoadMainConfig(basePath string) (*MainConfig, error) {
	configPath := resolveConfigPath(basePath)

	var cfg MainConfig

	data, err := readConfigFile(configPath)
	if err != nil {
		log.Printf("[WARNING] failed to read configuration file at %s, using default values: %v", configPath, err)
		applyDefaultConfig(&cfg)
		return &cfg, nil
	}

	if err := decodeConfig(data, &cfg); err != nil {
		log.Printf("[WARNING] failed to parse configuration file at %s, using default values: %v", configPath, err)
		applyDefaultConfig(&cfg)
		return &cfg, nil
	}

	applyDefaultConfig(&cfg)
	validateMainConfig(&cfg)

	return &cfg, nil
}
