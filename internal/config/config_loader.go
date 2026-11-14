package config

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
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

// unknownFieldError matches how yaml.v3 reports a key the target struct does not have.
var unknownFieldError = regexp.MustCompile(`field (\S+) not found in type \S+`)

// decodeStrict decodes YAML into out and rejects keys out has no field for, so a misspelled
// key is an error instead of a setting that silently keeps its default. An empty document
// leaves out unchanged.
func decodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(out)
	if err == nil || errors.Is(err, io.EOF) {
		return nil
	}
	// The Go type name means nothing to whoever edits the file.
	return errors.New(unknownFieldError.ReplaceAllString(err.Error(), `unknown field "$1"`))
}
