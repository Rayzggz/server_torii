package rules

import (
	"fmt"
	"strings"
)

type Action string

const (
	ActionAllow    Action = "allow"    // pass immediately, skipping every later check
	ActionSkip     Action = "skip"     // skip the listed checks, keep evaluating rules
	ActionContinue Action = "continue" // stop evaluating rules, run the normal pipeline
	ActionLog      Action = "log"      // log only, keep evaluating rules
	ActionBlock    Action = "block"
	ActionCaptcha  Action = "captcha"
	ActionExternal Action = "external"
)

// ParseAction validates an action name from configuration.
func ParseAction(name string) (Action, error) {
	switch a := Action(name); a {
	case ActionAllow, ActionSkip, ActionContinue, ActionLog, ActionBlock, ActionCaptcha, ActionExternal:
		return a, nil
	default:
		return "", fmt.Errorf("invalid action %q: expected allow, skip, continue, log, block, captcha or external", name)
	}
}

// Skip targets are the checks that run after CustomRules and can be skipped by a skip rule.
const (
	SkipCustomRules uint32 = 1 << iota // the remaining custom rules
	SkipIPCAPTCHA
	SkipURLCAPTCHA
	SkipCountryRule
	SkipVerifyBot
	SkipActionRule
	SkipHTTPFlood
	SkipExternalMigration
	SkipCaptcha
)

var skipTargets = map[string]uint32{
	"CustomRules":       SkipCustomRules,
	"IPCAPTCHA":         SkipIPCAPTCHA,
	"URLCAPTCHA":        SkipURLCAPTCHA,
	"CountryRule":       SkipCountryRule,
	"VerifyBot":         SkipVerifyBot,
	"ActionRule":        SkipActionRule,
	"HTTPFlood":         SkipHTTPFlood,
	"ExternalMigration": SkipExternalMigration,
	"Captcha":           SkipCaptcha,
}

// ParseSkipTargets turns check names into a skip mask.
func ParseSkipTargets(names []string) (uint32, error) {
	var mask uint32
	for _, name := range names {
		bit, ok := skipTargets[name]
		if !ok {
			return 0, fmt.Errorf("invalid skip target %q: expected one of %s", name,
				"CustomRules, IPCAPTCHA, URLCAPTCHA, CountryRule, VerifyBot, ActionRule, HTTPFlood, ExternalMigration, Captcha")
		}
		mask |= bit
	}
	return mask, nil
}

// Rule is one compiled custom rule.
type Rule struct {
	ID          string
	Description string
	Action      Action
	SkipMask    uint32
	Program     *Program
}

// CustomRules is the ordered rule list of a site; disabled rules are dropped at load time.
type CustomRules struct {
	Enabled bool
	Rules   []*Rule
}

// Uses reports whether any rule has the given action.
func (c *CustomRules) Uses(a Action) bool {
	if c == nil {
		return false
	}
	for _, rule := range c.Rules {
		if rule.Action == a {
			return true
		}
	}
	return false
}

// String gives a short label for logs.
func (r *Rule) String() string {
	return strings.ToUpper(string(r.Action)) + " id=" + r.ID
}
