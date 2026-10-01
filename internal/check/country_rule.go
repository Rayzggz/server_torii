package check

import (
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
)

// CountryRule applies a country override, default policy, or unknown policy.
func CountryRule(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	rule := ruleSet.CountryRule
	if reqData.FeatureControl&dataType.FeatureCountryRule == 0 || rule == nil {
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
	case sharedMem.CountryResolver == nil:
		reason = "unknown=missing_resolver"
	default:
		country, err := sharedMem.CountryResolver.Country(addr)
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
	case dataType.CountryBlock:
		utils.LogInfo(reqData, "", "CountryRule BLOCK "+reason)
		decision.SetCode(action.Done, []byte("403"))
	case dataType.CountryCaptcha:
		utils.LogInfo(reqData, "", "CountryRule CAPTCHA "+reason)
		reqData.FeatureControl |= dataType.FeatureCaptcha
		Captcha(reqData, ruleSet, decision, sharedMem)
	default:
		decision.Set(action.Continue)
	}
}
