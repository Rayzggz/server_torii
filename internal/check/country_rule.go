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
	switch selected {
	case config.CountryBlock:
		logx.Info(reqData, "", "CountryRule BLOCK "+reason)
		decision.SetVerdict(action.Done, action.VerdictBlock)
	case config.CountryCaptcha:
		logx.Info(reqData, "", "CountryRule CAPTCHA "+reason)
		requireCaptcha(reqData, ruleSet, decision, rt)
	}
}
