package server

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"time"
)

type CheckFunc func(dataType.UserRequest, *config.RuleSet, *action.Decision)

func CheckMain(w http.ResponseWriter, userRequestData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {
	decision := action.NewDecision()

	checkFuncs := make([]CheckFunc, 0)
	checkFuncs = append(checkFuncs, check.IPAllowList)
	checkFuncs = append(checkFuncs, check.IPBlockList)
	checkFuncs = append(checkFuncs, check.URLAllowList)
	checkFuncs = append(checkFuncs, check.URLBlockList)
	checkFuncs = append(checkFuncs, check.VerifyBot)
	checkFuncs = append(checkFuncs, check.Captcha)

	for _, checkFunc := range checkFuncs {
		checkFunc(userRequestData, ruleSet, decision)
		if decision.State == action.Done {
			break
		}
	}

	if bytes.Compare(decision.HTTPCode, []byte("200")) == 0 {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			log.Printf("Error write response: %v", err)
			return
		}
	} else if bytes.Compare(decision.HTTPCode, []byte("403")) == 0 {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
		if err != nil {
			log.Printf("Error template: %v", err)
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
			log.Printf("Error template: %v", err)
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if bytes.Compare(decision.HTTPCode, []byte("CAPTCHA")) == 0 {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/CAPTCHA.html")
		if err != nil {
			log.Printf("Error template: %v", err)
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Set-Cookie", "__torii_session_id="+string(decision.ResponseData)+"; Path=/; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err = tpl.Execute(w, nil); err != nil {
			log.Printf("Error template: %v", err)
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else {
		//should never happen
		log.Printf("Error access in wrong state: %v", decision)
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
}
