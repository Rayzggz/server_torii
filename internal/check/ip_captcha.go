package check

import (
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// IPCAPTCHA applies the existing CAPTCHA flow to addresses in the site's IP list.
func IPCAPTCHA(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	decision.Set(action.Continue)
	rule := ruleSet.IPCAPTCHARule
	if reqData.FeatureControl&request.FeatureIPCAPTCHA == 0 || rule == nil || rule.Trie == nil {
		return
	}
	ip := net.ParseIP(reqData.RemoteIP)
	if ip == nil || !rule.Trie.Search(ip) {
		return
	}
	logx.Info(reqData, "", "IPCAPTCHA")
	requireCaptcha(reqData, ruleSet, decision, rt)
}
