package server

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
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

func CheckTorii(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory, pages *config.ErrorPages) {
	decision := action.NewDecision()

	decision.SetVerdict(action.Continue, action.VerdictBlock)
	if strings.HasPrefix(r.URL.Path, cfg.WebPath+"/checker_pages/") {
		handleCheckerPages(w, r, reqData, ruleSet, cfg, pages)
		return
	} else if reqData.Uri == cfg.WebPath+"/captcha/challenge" {
		handleCaptchaChallenge(w, r, reqData, ruleSet)
		return
	} else if reqData.Uri == cfg.WebPath+"/captcha" {
		check.CheckCaptcha(r, reqData, ruleSet, decision, sharedMem)
	} else if reqData.Uri == cfg.WebPath+"/health_check" {
		handleHealthCheck(w, r, reqData, ruleSet, cfg)
		return
	} else if strings.HasPrefix(reqData.Uri, cfg.WebPath+"/external_migration") {
		handleExternalMigration(w, r, reqData, ruleSet, cfg, pages)
		return
	} else if r.URL.Path == cfg.WebPath+"/gossip" {
		if cfg.EnableGossip && sharedMem.GossipManager != nil {
			sharedMem.GossipManager.HandleGossip(w, r)
			return
		}
	}
	if decision.Verdict == action.VerdictAllow {
		switch decision.Captcha {
		case action.CaptchaBad, action.CaptchaBadSession:
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(decision.Captcha.String())); err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
			}
			return
		case action.CaptchaGood:
			if marker, ok := dataType.TrafficMarkerOf(sharedMem); ok && ruleSet.CAPTCHARule != nil {
				marker.MarkVerified(reqData.RemoteIP, time.Duration(ruleSet.CAPTCHARule.CaptchaValidateTime)*time.Second)
			}
			setToriiCookie(w, "__torii_clearance", string(check.GenClearance(reqData, *ruleSet)), 0)
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(decision.Captcha.String())); err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
			}
		default:
			//should not be here
			w.WriteHeader(http.StatusInternalServerError)
			if _, err := w.Write([]byte("500 - Internal Server Error")); err != nil {
				utils.LogError(reqData, "Error writing response: "+err.Error(), "CheckTorii")
			}
		}
	} else {
		tpl := pages.Get(config.PageForbidden)
		if tpl == nil {
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
		body, err := renderPage(tpl, data)
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckTorii")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeHTML(w, reqData, http.StatusForbidden, body, "CheckTorii")
	}
}

func handleCaptchaChallenge(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !check.IsAltchaProvider(ruleSet.CAPTCHARule) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !check.VerifySessionIDCookie(reqData, *ruleSet) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	challenge, err := check.GenAltchaChallenge(*ruleSet, reqData)
	if err != nil {
		utils.LogError(reqData, fmt.Sprintf("Error generating ALTCHA challenge: %v", err), "handleCaptchaChallenge")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(challenge); err != nil {
		utils.LogError(reqData, fmt.Sprintf("Error writing ALTCHA challenge: %v", err), "handleCaptchaChallenge")
	}
}

func handleHealthCheck(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig) {

	var builder strings.Builder
	builder.WriteString("ok\n")
	builder.WriteString("version=")
	builder.WriteString(dataType.ServerToriiVersion)
	builder.WriteString("\n")
	builder.WriteString("commit=")
	builder.WriteString(dataType.ServerToriiCommit())
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

func handleExternalMigration(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, pages *config.ErrorPages) {
	originalURI, err := validateInternalRedirectPath(r.URL.Query().Get("original_uri"))
	if err != nil {
		utils.LogInfo(reqData, fmt.Sprintf("Invalid external migration redirect target: %v", err), "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, pages, "Invalid Original URI")
		return
	}

	timestampStr := r.URL.Query().Get("timestamp")
	hmacParam := r.URL.Query().Get("hmac")

	if timestampStr == "" || hmacParam == "" {
		utils.LogInfo(reqData, "Missing required parameters for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, pages, "Missing required parameters")
		return
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		utils.LogInfo(reqData, "Invalid timestamp format", fmt.Sprintf("handleExternalMigration: %v", err))
		showExternalMigrationError(w, reqData, cfg, pages, "Invalid timestamp format")
		return
	}

	currentTime := time.Now().Unix()
	if currentTime-timestamp > 30 {
		utils.LogInfo(reqData, fmt.Sprintf("Migration link expired - age: %ds, timeout: 30s", currentTime-timestamp), "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, pages, "Migration link has expired")
		return
	}

	if !check.VerifyExternalMigrationSessionIDCookie(reqData, *ruleSet) {
		utils.LogInfo(reqData, "Session verification failed for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, pages, "Invalid session")
		return
	}

	expectedHMAC := check.CalculateExternalMigrationHMAC(reqData.ToriiSessionID, timestampStr, originalURI, ruleSet.ExternalMigrationRule.SecretKey)
	if !hmac.Equal([]byte(expectedHMAC), []byte(hmacParam)) {
		utils.LogInfo(reqData, "HMAC verification failed for external migration", "handleExternalMigration")
		showExternalMigrationError(w, reqData, cfg, pages, "Invalid migration signature")
		return
	}

	setToriiCookie(w, "__torii_clearance", string(check.GenExternalMigrationClearance(reqData, *ruleSet)), 0)
	http.Redirect(w, r, originalURI, http.StatusFound)
}

func showExternalMigrationError(w http.ResponseWriter, data dataType.UserRequest, cfg *config.MainConfig, pages *config.ErrorPages, errorMsg string) {
	tpl := pages.Get(config.PageError)
	if tpl == nil {
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

	body, err := renderPage(tpl, templateData)
	if err != nil {
		utils.LogError(data, fmt.Sprintf("Error executing template: %v", err), "showExternalMigrationError")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
	writeHTML(w, data, http.StatusBadRequest, body, "showExternalMigrationError")
}

// renderPage executes tpl into memory, so a failure can still be answered with a clean 500
// instead of a truncated page behind an already-sent status line.
func renderPage(tpl *template.Template, data any) ([]byte, error) {
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeHTML(w http.ResponseWriter, reqData dataType.UserRequest, status int, body []byte, caller string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		utils.LogError(reqData, "Error writing response: "+err.Error(), caller)
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
	// Browsers treat a backslash as a slash, so "/\host" would also be scheme-relative.
	if strings.HasPrefix(u.Path, "//") || strings.Contains(u.Path, `\`) {
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

// externalRedirectLocation escapes each value, so a URI with its own query string reaches the provider intact.
func externalRedirectLocation(redirectURL, domain, sessionID, originalURI, hmacValue string) string {
	sep := "?"
	if strings.Contains(redirectURL, "?") {
		sep = "&"
	}
	return redirectURL + sep +
		"domain=" + url.QueryEscape(domain) +
		"&session_id=" + url.QueryEscape(sessionID) +
		"&original_uri=" + url.QueryEscape(originalURI) +
		"&hmac=" + url.QueryEscape(hmacValue)
}

func handleCheckerPages(w http.ResponseWriter, r *http.Request, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, pages *config.ErrorPages) {
	if r.URL.Path == cfg.WebPath+"/checker_pages/403" {
		tpl := pages.Get(config.PageForbidden)
		if tpl == nil {
			utils.LogError(reqData, "Error page 403.html is not loaded", "CheckMain")
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
		body, err := renderPage(tpl, data)
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeHTML(w, reqData, http.StatusForbidden, body, "CheckMain")

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/CAPTCHA" {
		captchaPage := config.PageCaptcha
		if check.IsAltchaProvider(ruleSet.CAPTCHARule) {
			captchaPage = config.PageCaptchaAltcha
		}
		tpl := pages.Get(captchaPage)
		if tpl == nil {
			utils.LogError(reqData, "Error page "+captchaPage.String()+" is not loaded", "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		body, err := renderPage(tpl, nil)
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		setToriiCookie(w, "__torii_session_id", string(check.GenSessionID(reqData, *ruleSet)), 0)
		writeHTML(w, reqData, http.StatusServiceUnavailable, body, "CheckMain")

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/429" {
		tpl := pages.Get(config.PageTooManyRequests)
		if tpl == nil {
			utils.LogError(reqData, "Error page 429.html is not loaded", "CheckMain")
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
		body, err := renderPage(tpl, data)
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeHTML(w, reqData, http.StatusTooManyRequests, body, "CheckMain")

	} else if r.URL.Path == cfg.WebPath+"/checker_pages/EXTERNAL" {
		externalMigrationSessionID := check.GenExternalMigrationSessionID(reqData, *ruleSet)

		setToriiCookie(w, "__torii_session_id", string(externalMigrationSessionID), http.SameSiteLaxMode)

		sessionID := string(externalMigrationSessionID)
		sessionParts := strings.Split(sessionID, ":")
		if len(sessionParts) != 2 {
			utils.LogError(reqData, "Invalid session ID format", "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		timestamp := sessionParts[0]
		hmacValue := check.CalculateRedirectHMAC(reqData.Host, timestamp, reqData.Uri, ruleSet.ExternalMigrationRule.SecretKey)

		w.Header().Set("Location", externalRedirectLocation(ruleSet.ExternalMigrationRule.RedirectUrl, reqData.Host, sessionID, reqData.Uri, hmacValue))
		w.WriteHeader(http.StatusFound)
		_, err := w.Write([]byte("OK"))
		if err != nil {
			return
		}

		return
	} else {
		tpl := pages.Get(config.PageForbidden)
		if tpl == nil {
			utils.LogError(reqData, "Error page 403.html is not loaded", "CheckMain")
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
		body, err := renderPage(tpl, data)
		if err != nil {
			utils.LogError(reqData, fmt.Sprintf("Error executing template: %v", err), "CheckMain")
			http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeHTML(w, reqData, http.StatusForbidden, body, "CheckMain")
	}
}

// setToriiCookie writes a Torii cookie with consistent attributes.
// sameSite 0 omits the attribute so the browser default applies.
func setToriiCookie(w http.ResponseWriter, name, value string, sameSite http.SameSite) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   86400,
		HttpOnly: true,
		SameSite: sameSite,
	})
}
