// Package feature is the single list of the checks in the request pipeline: their order,
// their names, the feature control bit that switches each one, and whether a custom rule may skip it.
package feature

import (
	"fmt"
	"server_torii/internal/request"
	"strings"
)

// Check identifies one step of the pipeline. The constants are in execution order.
type Check uint8

const (
	IPAllow Check = iota
	IPBlock
	URLAllow
	URLBlock
	CustomRules
	IPCAPTCHA
	URLCAPTCHA
	CountryRule
	VerifyBot
	ActionRule
	HTTPFlood
	ExternalMigration
	Captcha

	// Count is the number of checks.
	Count
)

type definition struct {
	// name is what a site's Server.yml calls the check, for instance in a custom rule's skip list.
	name string
	// control is the check's bit in the feature control header, zero when it cannot be switched.
	control uint16
	// skippable checks run after CustomRules, so a custom rule can skip them.
	skippable bool
}

var definitions = [Count]definition{
	IPAllow:           {"IPAllow", request.FeatureIPAllow, false},
	IPBlock:           {"IPBlock", request.FeatureIPBlock, false},
	URLAllow:          {"URLAllow", request.FeatureURLAllow, false},
	URLBlock:          {"URLBlock", request.FeatureURLBlock, false},
	CustomRules:       {"CustomRules", request.FeatureCustomRules, true},
	IPCAPTCHA:         {"IPCAPTCHA", request.FeatureIPCAPTCHA, true},
	URLCAPTCHA:        {"URLCAPTCHA", request.FeatureURLCAPTCHA, true},
	CountryRule:       {"CountryRule", request.FeatureCountryRule, true},
	VerifyBot:         {"VerifyBot", request.FeatureVerifyBot, true},
	ActionRule:        {"ActionRule", 0, true},
	HTTPFlood:         {"HTTPFlood", request.FeatureHTTPFlood, true},
	ExternalMigration: {"ExternalMigration", request.FeatureExternalMigration, true},
	Captcha:           {"Captcha", request.FeatureCaptcha, true},
}

// Pipeline returns every check in execution order.
func Pipeline() []Check {
	checks := make([]Check, Count)
	for i := range checks {
		checks[i] = Check(i)
	}
	return checks
}

func (c Check) String() string {
	if c < Count {
		return definitions[c].name
	}
	return "UNKNOWN"
}

// ControlMask returns the check's bit in request.UserRequest.FeatureControl, or zero when the
// check has no switch.
func (c Check) ControlMask() uint16 {
	if c < Count {
		return definitions[c].control
	}
	return 0
}

// SkipMask returns the check's bit in a custom rule's skip mask, or zero when it cannot be skipped.
func (c Check) SkipMask() uint32 {
	if c < Count && definitions[c].skippable {
		return 1 << c
	}
	return 0
}

// ParseSkipTargets turns check names into a skip mask.
func ParseSkipTargets(names []string) (uint32, error) {
	var mask uint32
	for _, name := range names {
		bit := uint32(0)
		for c := Check(0); c < Count; c++ {
			if definitions[c].name == name {
				bit = c.SkipMask()
				break
			}
		}
		if bit == 0 {
			return 0, fmt.Errorf("invalid skip target %q: expected one of %s", name, strings.Join(skippableNames(), ", "))
		}
		mask |= bit
	}
	return mask, nil
}

func skippableNames() []string {
	var names []string
	for c := Check(0); c < Count; c++ {
		if definitions[c].skippable {
			names = append(names, definitions[c].name)
		}
	}
	return names
}
