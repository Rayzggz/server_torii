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

func CheckTorii(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {
	decision := action.NewDecision()

	decision.SetCode(action.Continue, []byte("403"))
	if reqData.Uri == cfg.WebPath+"/captcha" {
		check.CheckCaptcha(r, reqData, ruleSet, decision)
	}
	if bytes.Compare(decision.HTTPCode, []byte("200")) == 0 {
		if bytes.Compare(decision.ResponseData, []byte("bad")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("bad"))
			if err != nil {
				log.Printf("Error writing response: %v", err)
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("badSession")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("badSession"))
			if err != nil {
				log.Printf("Error writing response: %v", err)
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("good")) == 0 {
			w.Header().Set("Set-Cookie", "__torii_clearance="+string(check.GenClearance(reqData, *ruleSet))+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(decision.ResponseData)
			if err != nil {
				log.Printf("Error writing response: %v", err)
				return
			}
		} else {
			//should not be here
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("500 - Internal Server Error"))
			if err != nil {
				log.Printf("Error writing response: %v", err)
				return
			}
		}
	} else {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
		if err != nil {
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

		data := struct {
			EdgeTag   string
			ConnectIP string
			Date      string
		}{
			EdgeTag:   cfg.NodeName,
			ConnectIP: reqData.RemoteIP,
			Date:      time.Now().Format("2006-01-02 15:04:05"),
		}
		w.WriteHeader(http.StatusForbidden)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err = tpl.Execute(w, data); err != nil {
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
