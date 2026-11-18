// Package feature is the single list of the checks in the request pipeline: their order,
// their names, the feature control bit that switches each one, and whether a custom rule may skip it.
package feature

import (
	"fmt"
	"strings"
)

// Check identifies one step of the pipeline. The constants are in execution order.
type Check uint8

const (
	Lists Check = iota
	CustomRules
	CountryRule
	VerifyBot
	ActionRule
	HTTPFlood
	Challenge

	// Count is the number of checks.
	Count
)

type definition struct {
	// name is what a site's Server.yml calls the check, for instance in a custom rule's skip list.
	name string
	// switchable checks can be turned on and off, by the site configuration and per request.
	switchable bool
	// skippable checks run after CustomRules, so a custom rule can skip them.
	skippable bool
}

var definitions = [Count]definition{
	// Lists has no switch of its own: each list has one.
	Lists:       {"Lists", false, false},
	CustomRules: {"CustomRules", true, true},
	CountryRule: {"CountryRule", true, true},
	VerifyBot:   {"VerifyBot", true, true},
	// ActionRule has no switch: it is driven by the rules other components install at runtime.
	ActionRule: {"ActionRule", false, true},
	HTTPFlood:  {"HTTPFlood", true, true},
	Challenge:  {"Challenge", true, true},
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
	if c < Count && definitions[c].switchable {
		return 1 << c
	}
	return 0
}

// Enabled reports whether the check runs for a request with the given feature control bits.
// A check without a switch always runs.
func (c Check) Enabled(featureControl uint16) bool {
	mask := c.ControlMask()
	return mask == 0 || featureControl&mask != 0
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

// ByName returns the check with the given name. Case, underscores and hyphens are ignored, so
// "http_flood" and "HTTPFlood" name the same check.
func ByName(name string) (Check, bool) {
	want := foldName(name)
	for c := Check(0); c < Count; c++ {
		if foldName(definitions[c].name) == want {
			return c, true
		}
	}
	return Count, false
}

// ControlMaskByName returns the feature control bit of the check with the given name. Case,
// underscores and hyphens are ignored, so "http_flood" and "HTTPFlood" name the same check.
// It reports false for an unknown name and for a check that has no switch.
func ControlMaskByName(name string) (uint16, bool) {
	c, ok := ByName(name)
	if !ok {
		return 0, false
	}
	return c.ControlMask(), definitions[c].switchable
}

func foldName(name string) string {
	return strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
}
