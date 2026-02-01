package server

import (
	"fmt"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
)

type CheckFunc func(dataType.UserRequest, *config.RuleSet, *action.Decision, *dataType.SharedMemory)

func CheckMain(w http.ResponseWriter, userRequestData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) {
	decision := action.NewDecision()

	checkFuncs := make([]CheckFunc, 0)
	checkFuncs = append(checkFuncs, check.IPAllowList)
	checkFuncs = append(checkFuncs, check.IPBlockList)
	checkFuncs = append(checkFuncs, check.URLAllowList)
	checkFuncs = append(checkFuncs, check.URLBlockList)
	checkFuncs = append(checkFuncs, check.VerifyBot)
	checkFuncs = append(checkFuncs, check.ActionRule)
	checkFuncs = append(checkFuncs, check.HTTPFlood)
	checkFuncs = append(checkFuncs, check.ExternalMigration)
	checkFuncs = append(checkFuncs, check.Captcha)

	for _, checkFunc := range checkFuncs {
		checkFunc(userRequestData, ruleSet, decision, sharedMem)
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
