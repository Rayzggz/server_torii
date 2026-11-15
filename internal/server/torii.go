package server

import (
	"bytes"
	"crypto/hmac"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/version"
	"strconv"
	"strings"
	"time"
)

// servePublicEndpoint answers the endpoints a browser reaches under the address of the protected
// site, selected by the URI the visitor requested. It reports false, writing nothing, for any other URI.
func (s *Server) servePublicEndpoint(w http.ResponseWriter, r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet, pages *config.ErrorPages) bool {
	webPath := s.cfg.WebPath
	// The endpoints of a challenge exist only on a site that uses that kind of challenge.
	captcha := ruleSet.Challenge.ShowsCaptcha()
	external := !captcha
	switch {
	case reqData.Uri == webPath+"/health_check":
		s.handleHealthCheck(w, reqData)
	case captcha && reqData.Uri == webPath+"/captcha/challenge":
		s.handleCaptchaChallenge(w, r, reqData, ruleSet)
	case captcha && reqData.Uri == webPath+"/captcha":
		s.handleCaptchaSubmission(w, r, reqData, ruleSet, pages)
	case external && strings.HasPrefix(reqData.Uri, webPath+"/external_migration"):
		s.handleExternalMigration(w, r, reqData, ruleSet, pages)
	default:
		return false
	}
	return true
}

// handleCaptchaSubmission answers the script of the CAPTCHA page, which acts on the response body.
func (s *Server) handleCaptchaSubmission(w http.ResponseWriter, r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet, pages *config.ErrorPages) {
	outcome := check.CheckCaptcha(r, reqData, ruleSet, s.rt)
	s.rt.Event(reqData, slog.LevelDebug, "CAPTCHA answer", slog.String("outcome", outcome.String()))
	status := http.StatusOK
	switch outcome {
	case check.SubmissionRejected:
		s.serveErrorPage(w, reqData, pages, config.PageForbidden, http.StatusForbidden)
		return
	case check.SubmissionUnavailable:
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		status = http.StatusServiceUnavailable
	case check.SubmissionGood:
		s.rt.MarkVerified(reqData.Site, reqData.ClientKey(), ruleSet.Challenge.ClearanceTTL)
		setToriiCookie(w, "__torii_clearance", string(check.GenClearance(reqData, *ruleSet)), 0)
	}
	w.WriteHeader(status)
	if _, err := w.Write([]byte(outcome.String())); err != nil {
		s.rt.Event(reqData, slog.LevelDebug, "response not written", slog.String("error", err.Error()))
	}
}

func (s *Server) handleCaptchaChallenge(w http.ResponseWriter, r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !check.IsAltcha(ruleSet.Challenge) {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	if !check.VerifySessionIDCookie(reqData, *ruleSet) {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	challenge, err := check.GenAltchaChallenge(*ruleSet, reqData)
	if err != nil {
		s.rt.Error(reqData, "ALTCHA challenge not generated", slog.String("error", err.Error()))
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(challenge); err != nil {
		s.rt.Event(reqData, slog.LevelDebug, "response not written", slog.String("error", err.Error()))
	}
}

func (s *Server) handleHealthCheck(w http.ResponseWriter, reqData request.UserRequest) {

	var builder strings.Builder
	builder.WriteString("ok\n")
	builder.WriteString("version=")
	builder.WriteString(version.Version)
	builder.WriteString("\n")
	builder.WriteString("commit=")
	builder.WriteString(version.Commit())
	builder.WriteString("\n")
	builder.WriteString("time=")
	builder.WriteString(time.Now().Format(time.RFC3339))
	builder.WriteString("\n")
	builder.WriteString("ts=")
	builder.WriteString(strconv.FormatFloat(float64(time.Now().UnixNano())/1e9, 'f', 3, 64))
	builder.WriteString("\n")
	builder.WriteString("sliver=")
	builder.WriteString(s.cfg.NodeName)
	// What became of the request reports of the connector; all zero means none arrive.
	reports := s.reports.Load().Stats()
	fmt.Fprintf(&builder, "\nreports_received=%d\nreports_accepted=%d\nreports_malformed=%d\nreports_unknown_site=%d\nreports_dropped=%d",
		reports.Received, reports.Accepted, reports.Malformed, reports.Unknown, reports.Dropped)

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, err := w.Write([]byte(builder.String()))
	if err != nil {
		s.rt.Log().Debug("health check response not written", "error", err.Error())
		return
	}
}

func (s *Server) handleExternalMigration(w http.ResponseWriter, r *http.Request, reqData request.UserRequest, ruleSet *config.RuleSet, pages *config.ErrorPages) {
	originalURI, err := validateInternalRedirectPath(r.URL.Query().Get("original_uri"))
	if err != nil {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", "invalid original_uri: "+err.Error()))
		s.showExternalMigrationError(w, reqData, pages, "Invalid Original URI")
		return
	}

	timestampStr := r.URL.Query().Get("timestamp")
	hmacParam := r.URL.Query().Get("hmac")

	if timestampStr == "" || hmacParam == "" {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", "timestamp or hmac missing"))
		s.showExternalMigrationError(w, reqData, pages, "Missing required parameters")
		return
	}

	timestamp, err := strconv.ParseInt(timestampStr, 10, 64)
	if err != nil {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", "timestamp is not a number"))
		s.showExternalMigrationError(w, reqData, pages, "Invalid timestamp format")
		return
	}

	currentTime := time.Now().Unix()
	if currentTime-timestamp > 30 {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", fmt.Sprintf("link expired: %ds old, 30s allowed", currentTime-timestamp)))
		s.showExternalMigrationError(w, reqData, pages, "Migration link has expired")
		return
	}

	if !check.VerifySessionIDCookie(reqData, *ruleSet) {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", "invalid session"))
		s.showExternalMigrationError(w, reqData, pages, "Invalid session")
		return
	}

	expectedHMAC := check.CalculateExternalMigrationHMAC(reqData.ToriiSessionID, timestampStr, originalURI, ruleSet.Challenge.ExternalSecret)
	if !hmac.Equal([]byte(expectedHMAC), []byte(hmacParam)) {
		s.rt.Event(reqData, slog.LevelInfo, "external challenge return rejected", slog.String("note", "invalid signature"))
		s.showExternalMigrationError(w, reqData, pages, "Invalid migration signature")
		return
	}

	setToriiCookie(w, "__torii_clearance", string(check.GenClearance(reqData, *ruleSet)), 0)
	http.Redirect(w, r, originalURI, http.StatusFound)
}

func (s *Server) showExternalMigrationError(w http.ResponseWriter, reqData request.UserRequest, pages *config.ErrorPages, errorMsg string) {
	data := struct {
		pageData
		ErrorCode    string
		ErrorTitle   string
		ErrorMessage string
	}{s.pageData(reqData), "400", "Migration Error", errorMsg}
	if body, ok := s.renderPage(w, reqData, pages, config.PageError, data); ok {
		writeHTML(w, s.rt, reqData, http.StatusBadRequest, body)
	}
}

// pageData is what every error page template may show.
type pageData struct {
	EdgeTag   string
	ConnectIP string
	Date      string
}

func (s *Server) pageData(reqData request.UserRequest) pageData {
	return pageData{
		EdgeTag:   s.cfg.NodeName,
		ConnectIP: reqData.RemoteIP,
		Date:      time.Now().Format("2006-01-02 15:04:05"),
	}
}

// serveErrorPage answers with one of the configured error pages.
func (s *Server) serveErrorPage(w http.ResponseWriter, reqData request.UserRequest, pages *config.ErrorPages, page config.Page, status int) {
	if body, ok := s.renderPage(w, reqData, pages, page, s.pageData(reqData)); ok {
		writeHTML(w, s.rt, reqData, status, body)
	}
}

// renderPage executes a page into memory, so a failure can still be answered with a clean 500
// instead of a truncated page behind an already-sent status line. When it reports false the
// 500 has been written.
func (s *Server) renderPage(w http.ResponseWriter, reqData request.UserRequest, pages *config.ErrorPages, page config.Page, data any) ([]byte, bool) {
	tpl := pages.Get(page)
	if tpl == nil {
		s.rt.Error(reqData, "error page not loaded", slog.String("page", page.String()))
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, data); err != nil {
		s.rt.Error(reqData, "error page not rendered", slog.String("page", page.String()), slog.String("error", err.Error()))
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return nil, false
	}
	return buf.Bytes(), true
}

func writeHTML(w http.ResponseWriter, rt *state.Runtime, reqData request.UserRequest, status int, body []byte) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if _, err := w.Write(body); err != nil {
		rt.Event(reqData, slog.LevelDebug, "response not written", slog.String("error", err.Error()))
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

// serveVerdict answers a request the checks did not let through with the response the visitor
// should get: an error page, or the challenge of the site: its CAPTCHA page or the redirect to the external provider.
func (s *Server) serveVerdict(w http.ResponseWriter, reqData request.UserRequest, ruleSet *config.RuleSet, pages *config.ErrorPages, verdict action.Verdict) {
	switch verdict {
	case action.VerdictChallenge:
		if !ruleSet.Challenge.ShowsCaptcha() {
			s.redirectToExternalMigration(w, reqData, ruleSet)
			return
		}
		page := config.PageCaptcha
		if check.IsAltcha(ruleSet.Challenge) {
			page = config.PageCaptchaAltcha
		}
		body, ok := s.renderPage(w, reqData, pages, page, nil)
		if !ok {
			return
		}
		setToriiCookie(w, "__torii_session_id", string(check.GenSessionID(reqData, *ruleSet)), 0)
		writeHTML(w, s.rt, reqData, http.StatusServiceUnavailable, body)

	case action.VerdictRateLimit:
		s.serveErrorPage(w, reqData, pages, config.PageTooManyRequests, http.StatusTooManyRequests)

	default:
		s.serveErrorPage(w, reqData, pages, config.PageForbidden, http.StatusForbidden)
	}
}

// redirectToExternalMigration sends the visitor to the external provider with a signed session.
func (s *Server) redirectToExternalMigration(w http.ResponseWriter, reqData request.UserRequest, ruleSet *config.RuleSet) {
	sessionID := string(check.GenSessionID(reqData, *ruleSet))
	setToriiCookie(w, "__torii_session_id", sessionID, http.SameSiteLaxMode)

	// The redirect is signed with the time the session was issued at.
	timestamp, ok := check.ExternalSessionTimestamp(sessionID)
	if !ok {
		s.rt.Error(reqData, "external session has no timestamp")
		http.Error(w, "500 - Internal Server Error", http.StatusInternalServerError)
		return
	}
	hmacValue := check.CalculateRedirectHMAC(reqData.Host, timestamp, reqData.Uri, ruleSet.Challenge.ExternalSecret)

	w.Header().Set("Location", externalRedirectLocation(ruleSet.Challenge.RedirectURL, reqData.Host, sessionID, reqData.Uri, hmacValue))
	w.WriteHeader(http.StatusFound)
	_, _ = w.Write([]byte("OK"))
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
