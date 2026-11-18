package rules

import (
	"server_torii/internal/action"
	"strings"
)

// ParseAction validates an action name from configuration.
//
//	allow     pass immediately, skipping every later check
//	skip      skip the listed checks, keep evaluating rules
//	continue  stop evaluating rules, run the checks that follow
//	log       log only, keep evaluating rules
//	block     forbid the request
//	challenge stop evaluating rules and make the client prove itself, unless a later check
//	          ends the request with something stricter
func ParseAction(name string) (action.Action, error) {
	return action.Parse(name, action.ActionAllow, action.ActionSkip, action.ActionContinue, action.ActionLog,
		action.ActionBlock, action.ActionChallenge)
}

// Rule is one compiled custom rule.
type Rule struct {
	ID          string
	Description string
	Action      action.Action
	SkipMask    uint32
	Program     *Program
}

// CustomRules is the ordered rule list of a site; disabled rules are dropped at load time.
type CustomRules struct {
	Enabled bool
	Rules   []*Rule
}

// String gives a short label for logs.
func (r *Rule) String() string {
	return strings.ToUpper(string(r.Action)) + " id=" + r.ID
}
