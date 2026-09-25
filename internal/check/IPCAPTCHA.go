package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

// IPCAPTCHA applies the existing CAPTCHA flow to addresses in the site's IP list.
func IPCAPTCHA(reqData dataType.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, sharedMem *dataType.SharedMemory) {
	decision.Set(action.Continue)
	rule := ruleSet.IPCAPTCHARule
	if reqData.FeatureControl&dataType.FeatureIPCAPTCHA == 0 || rule == nil || rule.Trie == nil {
		return
	}
	ip := net.ParseIP(reqData.RemoteIP)
	if ip == nil || !rule.Trie.Search(ip) {
		return
	}
	utils.LogInfo(reqData, "", "IPCAPTCHA")
	reqData.FeatureControl |= dataType.FeatureCaptcha
	Captcha(reqData, ruleSet, decision, sharedMem)
}
