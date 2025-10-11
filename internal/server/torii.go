package server

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"html/template"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"strconv"
	"strings"
	"time"
)

func CheckTorii(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) {
	decision := action.NewDecision()

	decision.SetCode(action.Continue, []byte("403"))
	if reqData.Uri == cfg.WebPath+"/captcha" {
		check.CheckCaptcha(r, reqData, ruleSet, decision)
	} else if reqData.Uri == cfg.WebPath+"/health_check" {
		handleHealthCheck(w, r, reqData, ruleSet, cfg)
		return
	} else if strings.HasPrefix(reqData.Uri, cfg.WebPath+"/external_migration") {
		handleExternalMigration(w, r, reqData, ruleSet, cfg)
		return
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

func handleHealthCheck(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {

	var builder strings.Builder
	builder.WriteString("ok\n")
	builder.WriteString("version=")
	builder.WriteString(dataType.ServerToriiVersion)
	builder.WriteString("\n")
	builder.WriteString("time=")
	builder.WriteString(time.Now().Format(time.RFC3339))
	builder.WriteString("\n")
	builder.WriteString("ts=")
	builder.WriteString(strconv.FormatFloat(float64(time.Now().UnixNano())/1e9, 'f', 3, 64))
	builder.WriteString("\n")
	builder.WriteString("sliver=")
	builder.WriteString(cfg.NodeName)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(builder.String()))
	if err != nil {
		utils.LogError(reqData, "Error writing response: "+err.Error(), "handleHealthCheck")
		return
	}
	return
}

func handleExternalMigration(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {
	if !ruleSet.ExternalMigrationRule.Enabled {
		if !check.VerifyExternalMigrationSessionIDCookie(reqData, *ruleSet) {
			showExternalMigrationError(w, reqData, cfg, "Migration disabled")
			return
		}
		http.Redirect(w, r, r.URL.Query().Get("original_uri"), http.StatusFound)
		return
	}

	originalURI := r.URL.Query().Get("original_uri")
	timestampStr := r.URL.Query().Get("timestamp")
	hmacParam := r.URL.Query().Get("hmac")

	if timestampStr == "" || hmacParam == "" {
		utils.LogInfo(reqData, "Missing required parameters for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, "Missing required parameters")
		return
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		utils.LogInfo(reqData, "Invalid timestamp format", fmt.Sprintf("handleExternalMigration: %v", err))
		showExternalMigrationError(w, reqData, cfg, "Invalid timestamp format")
		return
	}

	currentTime := time.Now().Unix()
	if currentTime-timestamp > 30 {
		utils.LogInfo(reqData, fmt.Sprintf("Migration link expired - age: %ds, timeout: %ds", currentTime-timestamp, ruleSet.ExternalMigrationRule.SessionTimeout), "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, "Migration link has expired")
		return
	}

	if !check.VerifyExternalMigrationSessionIDCookie(reqData, *ruleSet) {
		utils.LogInfo(reqData, "Session verification failed for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, "Invalid session")
		return
	}

	expectedHMAC := check.CalculateExternalMigrationHMAC(reqData.ToriiSessionID, timestampStr, originalURI, ruleSet.ExternalMigrationRule.SecretKey)
	if !hmac.Equal([]byte(expectedHMAC), []byte(hmacParam)) {
		utils.LogInfo(reqData, "HMAC verification failed for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, "Invalid migration signature")
		return
	}

	w.Header().Set("Set-Cookie", "__torii_clearance="+string(check.GenExternalMigrationClearance(reqData, *ruleSet))+"; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
	http.Redirect(w, r, originalURI, http.StatusFound)
}

func showExternalMigrationError(w http.ResponseWriter, data dataType.UserRequest, cfg *config.MainConfig, errorMsg string) {
	tpl, err := template.ParseFiles(cfg.ErrorPage + "/error.html")
	if err != nil {
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}

	templateData := struct {
		ErrorCode    string
		ErrorTitle   string
		ErrorMessage string
		EdgeTag      string
		ConnectIP    string
		Date         string
	}{
		ErrorCode:    "400",
		ErrorTitle:   "Migration Error",
		ErrorMessage: errorMsg,
		EdgeTag:      cfg.NodeName,
		ConnectIP:    data.RemoteIP,
		Date:         time.Now().Format("2006-01-02 15:04:05"),
	}

	w.WriteHeader(http.StatusBadRequest)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err = tpl.Execute(w, templateData); err != nil {
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
}
