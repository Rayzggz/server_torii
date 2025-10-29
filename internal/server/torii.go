package server

import (
	"bytes"
	"crypto/hmac"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
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
	if strings.HasPrefix(r.URL.Path, cfg.WebPath+"/checker_pages/") {
		handleCheckerPages(w, r, reqData, ruleSet, cfg)
		return
	} else if reqData.Uri == cfg.WebPath+"/captcha" {
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
	if (reqData.FeatureControl & dataType.FeatureExternalMigration) != 0 {
		originalURI, err := validateInternalRedirectPath(r.URL.Query().Get("original_uri"))
		if err != nil {
			utils.LogInfo(reqData, fmt.Sprintf("Invalid external migration redirect target: %v", err), "handleExternalMigration")
			showExternalMigrationError(w, reqData, cfg, "Invalid Original URI")
			return
		}

		if !check.VerifyExternalMigrationSessionIDCookie(reqData, *ruleSet) {
			showExternalMigrationError(w, reqData, cfg, "Migration disabled")
			return
		}
		http.Redirect(w, r, originalURI, http.StatusFound)
		return
	}

	originalURI, err := validateInternalRedirectPath(r.URL.Query().Get("original_uri"))
	if err != nil {
		utils.LogInfo(reqData, fmt.Sprintf("Invalid external migration redirect target: %v", err), "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, "Invalid Original URI")
		return
	}

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

func validateInternalRedirectPath(raw string) (string, error) {

	if raw == "" {
		return "", fmt.Errorf("missing original_uri parameter")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid redirect URL: %v", err)
	}

	if u.Scheme != "" || u.Host != "" {
		return "", fmt.Errorf("redirect target must not contain scheme or host")
	}
	if strings.HasPrefix(u.Path, "//") {
		return "", fmt.Errorf("redirect target must not be scheme-relative")
	}
	if !strings.HasPrefix(u.Path, "/") {
		return "", fmt.Errorf("redirect path must be absolute")
	}

	redirect := u.Path
	if u.RawQuery != "" {
		redirect += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		redirect += "#" + u.Fragment
	}

	return redirect, nil
}

func handleCheckerPages(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {
	if r.URL.Path == cfg.WebPath+"/checker_pages/403" {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
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
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/CAPTCHA" {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/CAPTCHA.html")
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Set-Cookie", "__torii_session_id="+string(check.GenSessionID(reqData, *ruleSet))+"; Path=/; Path=/; Max-Age=86400; Priority=High; HttpOnly;")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusServiceUnavailable)
		if err = tpl.Execute(w, nil); err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/429" {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/429.html")
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
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
		w.WriteHeader(http.StatusTooManyRequests)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err = tpl.Execute(w, data); err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/EXTERNAL" {
		externalMigrationSessionID := check.GenExternalMigrationSessionID(reqData, *ruleSet)

		w.Header().Set("Set-Cookie", "__torii_session_id="+string(externalMigrationSessionID)+"; Path=/;  Max-Age=86400; Priority=High; HttpOnly; SameSite=Lax")

		sessionID := string(externalMigrationSessionID)
		sessionParts := strings.Split(sessionID, ":")
		if len(sessionParts) != 2 {
			utils.LogError(reqData, "Invalid session ID format", "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		timestamp := sessionParts[0]
		hmacValue := check.CalculateRedirectHMAC(reqData.Host, timestamp, reqData.Uri, ruleSet.ExternalMigrationRule.SecretKey)

		w.Header().Set("Location", ruleSet.ExternalMigrationRule.RedirectUrl+"?domain="+reqData.Host+"&session_id="+sessionID+"&original_uri="+reqData.Uri+"&hmac="+hmacValue)
		w.WriteHeader(http.StatusFound)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}

		return
	} else {
		tpl, err := template.ParseFiles(cfg.ErrorPage + "/403.html")
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error parsing template: %v", err), "CheckMain")
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
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
	}
}
