package server

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strings"
	"time"
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
	checkFuncs = append(checkFuncs, check.HTTPFlood)
	checkFuncs = append(checkFuncs, check.ExternalMigration)
	checkFuncs = append(checkFuncs, check.Captcha)

	for _, checkFunc := range checkFuncs {
		checkFunc(userRequestData, ruleSet, decision, sharedMem)
		if decision.State == action.Done {
			break
		}
	}

	if bytes.Compare(decision.HTTPCode, []byte("200")) == 0 {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error writing response: %v", err), "CheckMain")
			return
		}
	} else if bytes.Compare(decision.HTTPCode, []byte("403")) == 0 {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := struct {
			EdgeTag   string
			ConnectIP string
			Date      string
		}{
			EdgeTag:   cfg.NodeName,
			ConnectIP: userRequestData.RemoteIP,
			Date:      time.Now().Format("2006-01-02 15:04:05"),
		}
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err = tpl.Execute(w, data); err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if bytes.Compare(decision.HTTPCode, []byte("CAPTCHA")) == 0 {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/CAPTCHA.html")
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Set-Cookie", "__torii_session_id="+string(decision.ResponseData)+"; Path=/; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err = tpl.Execute(w, nil); err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if bytes.Compare(decision.HTTPCode, []byte("429")) == 0 {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/429.html")
		if err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		data := struct {
			EdgeTag   string
			ConnectIP string
			Date      string
		}{
			EdgeTag:   cfg.NodeName,
			ConnectIP: userRequestData.RemoteIP,
			Date:      time.Now().Format("2006-01-02 15:04:05"),
		}
		w.WriteHeader(http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err = tpl.Execute(w, data); err != nil {
			utils.LogError(userRequestData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if bytes.Compare(decision.HTTPCode, []byte("EXTERNAL")) == 0 {
		w.Header().Set("Set-Cookie", "__torii_session_id="+string(decision.ResponseData)+"; Path=/;  Max-Age=86400; Priority=High; HttpOnly; SameSite=Lax")

		sessionID := string(decision.ResponseData)
		sessionParts := strings.Split(sessionID, ":")
		if len(sessionParts) != 2 {
			utils.LogError(userRequestData, "Invalid session ID format", "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		timestamp := sessionParts[0]
		hmacValue := check.CalculateRedirectHMAC(userRequestData.Host, timestamp, userRequestData.Uri, ruleSet.ExternalMigrationRule.SecretKey)

		w.Header().Set("Location", ruleSet.ExternalMigrationRule.RedirectUrl+"?domain="+userRequestData.Host+"&session_id="+sessionID+"&original_uri="+userRequestData.Uri+"&hmac="+hmacValue)
		w.WriteHeader(http.StatusFound)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}

		return
	} else {
		//should never happen
		utils.LogError(userRequestData, fmt.Sprintf("Error access in wrong state: %v", decision), "CheckMain")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
}
