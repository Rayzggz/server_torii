package server

import (
	"fmt"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/feature"
	"server_torii/internal/logx"
	"server_torii/internal/request"
	"server_torii/internal/state"
)

type CheckFunc func(request.UserRequest, *config.RuleSet, *action.Decision, *state.Runtime)

// checkFuncs implements each step of feature.Pipeline.
var checkFuncs = [feature.Count]CheckFunc{
	feature.IPAllow:           check.IPAllowList,
	feature.IPBlock:           check.IPBlockList,
	feature.URLAllow:          check.URLAllowList,
	feature.URLBlock:          check.URLBlockList,
	feature.CustomRules:       check.CustomRules,
	feature.IPCAPTCHA:         check.IPCAPTCHA,
	feature.URLCAPTCHA:        check.URLCAPTCHA,
	feature.CountryRule:       check.CountryRule,
	feature.VerifyBot:         check.VerifyBot,
	feature.ActionRule:        check.ActionRule,
	feature.HTTPFlood:         check.HTTPFlood,
	feature.ExternalMigration: check.ExternalMigration,
	feature.Captcha:           check.Captcha,
}

// CheckMain runs the check pipeline and answers the auth_request subrequest.
func (s *Server) CheckMain(w http.ResponseWriter, userRequestData request.UserRequest, ruleSet *config.RuleSet) {
	decision := action.NewDecision()

	for _, c := range feature.Pipeline() {
		if decision.SkipMask&c.SkipMask() != 0 {
			continue
		}
		checkFuncs[c](userRequestData, ruleSet, decision, s.rt)
		if decision.State == action.Done {
			break
		}
	}

	switch decision.Verdict {
	case action.VerdictAllow:
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Server Torii Access Passed"))
		if err != nil {
			logx.Error(userRequestData, fmt.Sprintf("Error writing response: %v", err), "CheckMain")
			return
		}
	case action.VerdictBlock, action.VerdictCaptcha, action.VerdictRateLimit, action.VerdictExternal:
		w.Header().Set("Torii-Action", decision.Verdict.String())
		w.WriteHeader(445)
		_, err := w.Write([]byte("Server Torii Auth Required"))
		if err != nil {
			logx.Error(userRequestData, fmt.Sprintf("Error writing response: %v", err), "CheckMain")
			return
		}
	default:
		//should never happen
		logx.Error(userRequestData, fmt.Sprintf("Error access in wrong state: %v", decision), "CheckMain")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
}
