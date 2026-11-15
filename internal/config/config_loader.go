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

// bareDurationError matches how yaml.v3 reports a value that is not a duration, such as a number
// without a unit.
var bareDurationError = regexp.MustCompile("cannot unmarshal \\S+ `([^`]*)` into time\\.Duration")

// decodeStrict decodes YAML into out and rejects keys out has no field for, so a misspelled
// key is an error instead of a setting that silently keeps its default. An empty document
// leaves out unchanged. A file holds one document: what follows a `---` would otherwise be
// settings that are silently not applied.
func decodeStrict(data []byte, out any) error {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	err := dec.Decode(out)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		var extra yaml.Node
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			return errors.New("the file holds more than one YAML document: remove the `---` and what follows it, or merge it into the first document")
		}
		return nil
	}
	// The Go type names mean nothing to whoever edits the file.
	msg := unknownFieldError.ReplaceAllString(err.Error(), `unknown field "$1"`)
	msg = bareDurationError.ReplaceAllString(msg, "`$1` is not a duration: write it with a unit, such as 30s, 10m or 2h")
	return errors.New(msg)
}
