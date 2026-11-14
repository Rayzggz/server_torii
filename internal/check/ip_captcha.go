package check

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

// IPCAPTCHA marks the addresses in the site's IP list for a challenge.
func IPCAPTCHA(reqData request.UserRequest, ruleSet *config.RuleSet, decision *action.Decision, rt *state.Runtime) {
	rule := ruleSet.IPCAPTCHARule
	if rule == nil || !rule.Trie.SearchAddr(reqData.ClientAddr()) {
		return
	}
	logx.Info(reqData, "", "IPCAPTCHA")
	decision.RequireChallenge = true
}
