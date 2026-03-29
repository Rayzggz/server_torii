package config

// Package config - config.go
// 职责: 提供配置包对外的入口及全局公共变量定义。
// 仅保留基础核心数据结构与公共校验方法，避免大杂烩。

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"server_torii/internal/dataType"

	"github.com/go-playground/validator/v10"
)

var validate *validator.Validate
var GlobalConfig *MainConfig

func init() {
	validate = validator.New()

	// Register custom validation for directory paths
	err := validate.RegisterValidation("dir", validateDir)
	if err != nil {
		return
	}
}

// validateDir validates that a path is a directory
func validateDir(fl validator.FieldLevel) bool {
	path := fl.Field().String()
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// validateConfiguration validates a struct and logs warnings for validation errors
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

// getValidationErrorMessage returns a human-readable validation error message
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

// RuleSet stores all rules
type RuleSet struct {
	IPAllowRule                 *dataType.IPAllowRule
	IPBlockRule                 *dataType.IPBlockRule
	URLAllowRule                *dataType.URLAllowRule
	URLBlockRule                *dataType.URLBlockRule
	CAPTCHARule                 *dataType.CaptchaRule
	VerifyBotRule               *dataType.VerifyBotRule
	HTTPFloodRule               *dataType.HTTPFloodRule
	ExternalMigrationRule       *dataType.ExternalMigrationRule
	AdaptiveTrafficAnalyzerRule *dataType.AdaptiveTrafficAnalyzerRule
}

// GetSiteRules returns the rules for a specific host
func GetSiteRules(siteRules map[string]*RuleSet, host string) *RuleSet {
	if rules, ok := siteRules[host]; ok {
		return rules
	}

	// Check for wildcard match (e.g., *.example.com)
	parts := strings.Split(host, ".")
	if len(parts) > 1 {
		wildcardHost := "*." + strings.Join(parts[1:], ".")
		if rules, ok := siteRules[wildcardHost]; ok {
			return rules
		}
	}

	// Return default site rules
	if rules, ok := siteRules["default_site"]; ok {
		return rules
	}

	return nil
}
