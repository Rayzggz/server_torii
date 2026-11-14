package config

import (
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate

func init() {
	validate = validator.New()

	// Report fields by the key the operator wrote, not by the Go field name.
	validate.RegisterTagNameFunc(func(f reflect.StructField) string {
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			return f.Name
		}
		return name
	})

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
	if err = validate.RegisterValidation("site_id", func(fl validator.FieldLevel) bool {
		return ValidSiteID(fl.Field().String())
	}); err != nil {
		log.Fatalf("failed to register \"site_id\" validator: %v", err)
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

// validateStruct checks cfg against its validate tags. It returns every violation, one per
// line, each naming the offending key under section. Values are left out: some are secrets.
func validateStruct(cfg any, section string) error {
	err := validate.Struct(cfg)
	if err == nil {
		return nil
	}
	var validationErrors validator.ValidationErrors
	if !errors.As(err, &validationErrors) {
		return fmt.Errorf("%s: %w", section, err)
	}
	problems := make([]error, 0, len(validationErrors))
	for _, fe := range validationErrors {
		// The namespace starts with the Go type name; the section name replaces it.
		_, key, _ := strings.Cut(fe.Namespace(), ".")
		if section != "" {
			key = section + "." + key
		}
		problems = append(problems, fmt.Errorf("%s: %s", key, getValidationErrorMessage(fe)))
	}
	return errors.Join(problems...)
}

// getValidationErrorMessage returns a human-readable validation error message.
func getValidationErrorMessage(fe validator.FieldError) string {
	switch fe.Tag() {
	case "required":
		return "field is required but missing or empty"
	case "required_if":
		return "field is required when gossip is enabled"
	case "oneof":
		return fmt.Sprintf("value must be one of: %s", fe.Param())
	case "site_id":
		return fmt.Sprintf("value must be 1 to %d letters, digits or underscores", MaxSiteIDLength)
	case "min":
		// For lists and strings the bound is a length, not a value.
		switch fe.Kind() {
		case reflect.Slice:
			return fmt.Sprintf("list needs at least %s entry", fe.Param())
		case reflect.String:
			return fmt.Sprintf("value must be at least %s characters long", fe.Param())
		}
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

// validateMainConfig returns every problem in the main configuration.
func validateMainConfig(cfg *MainConfig) error {
	problems := []error{validateStruct(cfg, "")}
	if cfg.EnableGossip && cfg.GlobalSecret == DefaultGlobalSecret {
		problems = append(problems, errors.New("global_secret: this is the public value from the example configuration, "+
			"so anyone could forge gossip messages; set a random one, e.g. the output of `openssl rand -hex 16`"))
	}
	seen := make(map[string]bool, len(cfg.Sites))
	for i, site := range cfg.Sites {
		if seen[site.ID] {
			problems = append(problems, fmt.Errorf("sites[%d].id: duplicate id %q", i, site.ID))
		}
		seen[site.ID] = true
	}
	if cfg.DefaultSite != "" && !seen[cfg.DefaultSite] {
		problems = append(problems, fmt.Errorf("default_site: %q is not one of the configured sites", cfg.DefaultSite))
	}
	return errors.Join(problems...)
}
