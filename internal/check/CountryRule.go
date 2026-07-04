package check

import (
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
)

// CountryRule applies per-site country actions using the shared GeoIP resolver.
func CountryRule(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	if (reqData.FeatureControl&dataType.FeatureCountryRule) == 0 ||
		ruleSet.CountryRule == nil ||
		sharedMem.CountryResolver == nil {
		decision.Set(action.Continue)
		return
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(reqData.RemoteIP))
	if err != nil {
		decision.Set(action.Continue)
		return
	}

	country, err := sharedMem.CountryResolver.Country(addr)
	if err != nil || country == "" {
		decision.Set(action.Continue)
		return
	}
	country = strings.ToUpper(country)

	if _, blocked := ruleSet.CountryRule.BlockCountries[country]; blocked {
		utils.LogInfo(reqData, "", "CountryRule BLOCK")
		decision.SetCode(action.Done, []byte("403"))
		return
	}

	if _, challenged := ruleSet.CountryRule.CAPTCHACountries[country]; challenged {
		utils.LogInfo(reqData, "", "CountryRule CAPTCHA")
		reqData.FeatureControl |= dataType.FeatureCaptcha
		Captcha(reqData, ruleSet, decision, sharedMem)
		return
	}

	decision.Set(action.Continue)
}
