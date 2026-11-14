package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Register custom validation for directory paths
	err := validate.RegisterValidation("dir", validateDir)
	if err != nil {
		log.Fatalf("failed to register \"dir\" validator: %v", err)
	}

	// Register custom validation for TCP/UDP port numbers stored as strings.
	// min/max on a string field compare length, not value, so they cannot express a port range.
	err = validate.RegisterValidation("port", validatePort)
	if err != nil {
		log.Fatalf("failed to register \"port\" validator: %v", err)
	}

	if err = validate.RegisterValidation("listen_addr", validateListenAddr); err != nil {
		log.Fatalf("failed to register \"listen_addr\" validator: %v", err)
	}
	if err = validate.RegisterValidation("socket_mode", validateSocketMode); err != nil {
		log.Fatalf("failed to register \"socket_mode\" validator: %v", err)
	}
}

// validatePort validates that a string is a decimal port number in the range 1-65535.
func validatePort(fl validator.FieldLevel) bool {
	port, err := strconv.Atoi(fl.Field().String())
	return err == nil && port >= 1 && port <= 65535
}

// validateListenAddr accepts "host:port" (host may be empty) or "unix:" followed by a path.
func validateListenAddr(fl validator.FieldLevel) bool {
	addr := fl.Field().String()
	if path, ok := strings.CutPrefix(addr, UnixListenPrefix); ok {
		return path != ""
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	n, err := strconv.Atoi(port)
	return err == nil && n >= 1 && n <= 65535
}

// validateSocketMode accepts octal permission bits such as "0660".
func validateSocketMode(fl validator.FieldLevel) bool {
	mode, err := strconv.ParseUint(fl.Field().String(), 8, 32)
	return err == nil && mode <= 0o777
}

// validateDir validates that a path is a directory.
func validateDir(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// validateConfiguration validates a struct and logs warnings for validation errors.
func validateConfiguration(cfg interface{}, configName string) {
	if err := validate.Struct(cfg); err != nil {
		var validationErrors validator.ValidationErrors
		if errors.As(err, &validationErrors) {
			for _, validationError := range validationErrors {
				log.Printf("[WARNING] Configuration issue in %s.%s may affect runtime: %s (current value: '%v')",
					configName,
					validationError.Field(),
					getValidationErrorMessage(validationError),
					validationError.Value())
			}
		} else {
			log.Printf("[WARNING] Configuration validation failed for %s: %v", configName, err)
		}
	}
}

// getValidationErrorMessage returns a human-readable validation error message.
func getValidationErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "field is required but missing or empty"
	case "min":
		return fmt.Sprintf("value must be at least %s", fe.Param())
	case "max":
		return fmt.Sprintf("value must be at most %s", fe.Param())
	case "numeric":
		return "value must be numeric"
	case "url":
		return "value must be a valid URL"
	case "startswith":
		return fmt.Sprintf("value must start with %s", fe.Param())
	case "rate":
		return "value must be a valid rate format"
	case "dir":
		return "path must be an existing directory"
	case "port":
		return "value must be a port number between 1 and 65535"
	case "listen_addr":
		return "value must be host:port or unix:/path/to.sock"
	case "socket_mode":
		return "value must be octal permission bits such as 0660"
	default:
		return fmt.Sprintf("validation rule '%s' failed", fe.Tag())
	}
}

// validateMainConfig validates the main configuration object.
func validateMainConfig(cfg *MainConfig) {
	validateConfiguration(cfg, "MainConfig")
	warnPublicGlobalSecret(cfg)
}

// warnPublicGlobalSecret reports whether global_secret is DefaultGlobalSecret, which is published in
// config_example/torii.yml, and logs a warning if so. Anyone can forge gossip messages signed with it.
func warnPublicGlobalSecret(cfg *MainConfig) bool {
	if cfg.GlobalSecret != DefaultGlobalSecret {
		return false
	}
	log.Printf("[WARNING] Configuration issue in MainConfig.GlobalSecret: global_secret is the public default value from the example configuration; " +
		"anyone can forge gossip messages signed with it. Set it to a random value, e.g. the output of `openssl rand -hex 16`.")
	return true
}
