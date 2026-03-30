package config

import (
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
