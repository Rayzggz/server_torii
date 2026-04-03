package config

import (
	"errors"
	"fmt"
	"log"
	"os"

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
	default:
		return fmt.Sprintf("validation rule '%s' failed", fe.Tag())
	}
}

// validateMainConfig validates the main configuration object.
func validateMainConfig(cfg *MainConfig) {
	validateConfiguration(cfg, "MainConfig")
}
