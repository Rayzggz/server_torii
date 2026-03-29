package config

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// resolveConfigPath determines the path to the configuration file
func resolveConfigPath(basePath string) string {
	var configPath string
	if basePath != "" {
		if strings.HasSuffix(basePath, "torii.yml") {
			configPath = basePath
		} else {
			configPath = filepath.Join(basePath, "torii.yml")
			if _, err := os.Stat(configPath); os.IsNotExist(err) {
				configPath = filepath.Join(basePath, "config", "torii.yml")
			}
		}
	} else {
		cwd, _ := os.Getwd()
		configPath = filepath.Join(cwd, "config", "torii.yml")
	}
	return configPath
}

// readConfigFile reads the configuration file
func readConfigFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// decodeConfig unmarshals the configuration
func decodeConfig(data []byte, cfg *MainConfig) error {
	return yaml.Unmarshal(data, cfg)
}

// LoadMainConfig Read the configuration file and return the configuration object
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
