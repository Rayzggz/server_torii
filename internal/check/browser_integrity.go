package check

import (
	"log/slog"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/integrity"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// BrowserIntegrity applies the rules of package integrity the site lists: a request that
// cannot have come from the browser its User-Agent names gets the action of the site. The
// rule that found it is named in Torii-Reason.
func BrowserIntegrity(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.BrowserIntegrity
	if rule == nil {
		return
	}
	name, note := integrity.New(reqData.UserAgent, reqData.Headers).Finding(rule.Applies)
	if name == "" {
		return
	}
	if rule.Action == action.ActionObserve {
		rt.Event(reqData, slog.LevelInfo, "browser integrity", slog.String("rule", name), slog.String("note", note))
		return
	}
	decision.Detail = name
	decision.Note = note
	applyAction(reqData, decision, rt, rule.Action)
}
