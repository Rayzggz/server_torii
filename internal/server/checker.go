package server

import (
	"fmt"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/rules"
	"server_torii/internal/utils"
)

type CheckFunc func(dataType.UserRequest, *config.RuleSet, *action.Decision, *dataType.SharedMemory)

// checkStep pairs a check with the rules.Skip* bit that lets a custom skip rule bypass it.
type checkStep struct {
	skip uint32
	fn   CheckFunc
}

func CheckMain(w http.ResponseWriter, userRequestData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) {
	decision := action.NewDecision()

	checkSteps := []checkStep{
		{0, check.IPAllowList},
		{0, check.IPBlockList},
		{0, check.URLAllowList},
		{0, check.URLBlockList},
		{rules.SkipCustomRules, check.CustomRules},
		{rules.SkipIPCAPTCHA, check.IPCAPTCHA},
		{rules.SkipURLCAPTCHA, check.URLCAPTCHA},
		{rules.SkipCountryRule, check.CountryRule},
		{rules.SkipVerifyBot, check.VerifyBot},
		{rules.SkipActionRule, check.ActionRule},
		{rules.SkipHTTPFlood, check.HTTPFlood},
		{rules.SkipExternalMigration, check.ExternalMigration},
		{rules.SkipCaptcha, check.Captcha},
	}

	for _, step := range checkSteps {
		if decision.SkipMask&step.skip != 0 {
			continue
		}
		step.fn(userRequestData, ruleSet, decision, sharedMem)
		if decision.State == action.Done {
			break
		}
	}

	switch string(decision.HTTPCode) {
	case "200":
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Server Torii Access Passed"))
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error writing response: %v", err), "CheckMain")
			return
		}
	case "403", "CAPTCHA", "429", "EXTERNAL":
		w.Header().Set("Torii-Action", string(decision.HTTPCode))
		w.WriteHeader(445)
		_, err := w.Write([]byte("Server Torii Auth Required"))
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error writing response: %v", err), "CheckMain")
			return
		}
	default:
		//should never happen
		utils.LogError(userRequestData, fmt.Sprintf("Error access in wrong state: %v", decision), "CheckMain")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
}
