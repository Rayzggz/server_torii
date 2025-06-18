package server

import (
	"bytes"
	"crypto/hmac"
	"html/template"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strconv"
	"time"
)

func CheckTorii(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) {
	decision := action.NewDecision()

	decision.SetCode(action.Continue, []byte("403"))
	if reqData.Uri == cfg.WebPath+"/captcha" {
		check.CheckCaptcha(r, reqData, ruleSet, decision)
	} else if reqData.Uri == cfg.WebPath+"/health_check" {
		decision.SetResponse(action.Done, []byte("200"), []byte("ok"))
	} else if reqData.Uri == cfg.WebPath+"/external_migration" {
		handleExternalMigration(w, r, reqData, ruleSet, decision)
	}
	if bytes.Compare(decision.HTTPCode, []byte("200")) == 0 {
		if bytes.Compare(decision.ResponseData, []byte("ok")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("ok"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		}
		if bytes.Compare(decision.ResponseData, []byte("bad")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("bad"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("badSession")) == 0 {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("badSession"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
			return
		} else if bytes.Compare(decision.ResponseData, []byte("good")) == 0 {
			w.Header().Set("Set-Cookie", "__torii_clearance="+string(check.GenClearance(reqData, *ruleSet))+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write(decision.ResponseData)
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
				return
			}
		} else {
			//should not be here
			w.WriteHeader(http.StatusInternalServerError)
			_, err := w.Write([]byte("500 - Internal Server Error"))
			if err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
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

func handleExternalMigration(w http.ResponseWriter, r *http.Request, data dataType.UserRequest, set *config.RuleSet, decision *action.Decision) {
	if !set.ExternalMigrationRule.Enabled {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	originalURI := r.URL.Query().Get("original_uri")
	timestampStr := r.URL.Query().Get("timestamp")
	hmacParam := r.URL.Query().Get("hmac")

	if timestampStr == "" || hmacParam == "" {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	currentTime := time.Now().Unix()
	if currentTime-timestamp > set.ExternalMigrationRule.SessionTimeout {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	if !check.VerifyExternalMigrationSessionIDCookie(data, *set) {
		decision.SetResponse(action.Done, []byte("200"), []byte("badSession"))
		return
	}

	expectedHMAC := check.CalculateExternalMigrationHMAC(data.ToriiSessionID, timestampStr, set.ExternalMigrationRule.SecretKey)
	if !hmac.Equal([]byte(expectedHMAC), []byte(hmacParam)) {
		decision.SetResponse(action.Done, []byte("200"), []byte("bad"))
		return
	}

	decision.SetResponse(action.Continue, []byte("302"), []byte(originalURI))
}
