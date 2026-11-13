package check

import (
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"strings"
)

// CountryRule applies a country override, default policy, or unknown policy.
func CountryRule(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.CountryRule
	if reqData.FeatureControl&request.FeatureCountryRule == 0 || rule == nil {
		decision.Set(action.Continue)
		return
	}
	selected := rule.UnknownAction
	reason := "unknown=unresolved"
	addr, err := netip.ParseAddr(strings.TrimSpace(reqData.RemoteIP))
	switch {
	case err != nil:
		reason = "unknown=invalid_ip"
	case !addr.IsGlobalUnicast() || addr.IsPrivate():
		reason = "unknown=non_routable_ip"
	case rt.CountryResolver == nil:
		reason = "unknown=missing_resolver"
	default:
		country, err := rt.CountryResolver.Country(addr)
		if err != nil {
			reason = "unknown=lookup_error"
		} else if country != "" {
			country = strings.ToUpper(country)
			reason = "country=" + country
			selected = rule.DefaultAction
			if override, exists := rule.Countries[country]; exists {
				selected = override
			}
		}
	}
	switch selected {
	case config.CountryBlock:
		logx.Info(reqData, "", "CountryRule BLOCK "+reason)
		decision.SetVerdict(action.Done, action.VerdictBlock)
	case config.CountryCaptcha:
		logx.Info(reqData, "", "CountryRule CAPTCHA "+reason)
		requireCaptcha(reqData, ruleSet, decision, rt)
	default:
		decision.Set(action.Continue)
	}
}
