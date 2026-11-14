package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// CountryRule applies a country override, default policy, or unknown policy.
func CountryRule(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.CountryRule
	if rule == nil {
		return
	}
	selected := rule.UnknownAction
	reason := "unknown=" + reqData.CountryUnknown
	if country := reqData.Country; country != "" {
		reason = "country=" + country
		selected = rule.DefaultAction
		if override, exists := rule.Countries[country]; exists {
			selected = override
		}
	}
	if selected == action.ActionBlock || selected == action.ActionChallenge {
		logx.Info(reqData, "", "CountryRule "+string(selected)+" "+reason)
	}
	applyAction(reqData, decision, rt, selected)
}
