package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/analyzer"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/version"
	"strings"
	"testing"
	"time"

	altcha "github.com/altcha-org/altcha-lib-go/v2"
)

func newPagesConfig(t *testing.T) *config.MainConfig {
	t.Helper()
	dir := t.TempDir()
	writePage(t, dir, "403.html", "403|{{.EdgeTag}}|{{.ConnectIP}}")
	writePage(t, dir, "429.html", "429|{{.EdgeTag}}|{{.ConnectIP}}")
	return &config.MainConfig{WebPath: "/torii", ErrorPage: dir, NodeName: "node-a"}
}

func serveTorii(path string, reqData request.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *state.Runtime) *httptest.ResponseRecorder {
	reqData.Uri = path
	rec := httptest.NewRecorder()
	NewServer(cfg, nil, sharedMem, nil).servePublic(rec, httptest.NewRequest(http.MethodGet, path, nil), reqData, ruleSet, pagesFor(cfg))
	return rec
}

// serveVerdictPage answers reqData the way the checker does for a request it did not let through.
func serveVerdictPage(verdict action.Verdict, reqData request.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, pages *config.ErrorPages) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	NewServer(cfg, nil, &state.Runtime{}, nil).serveVerdict(rec, reqData, ruleSet, pages, verdict)
	return rec
}

func TestVerdictPagesRenderTemplates(t *testing.T) {
	cfg := newPagesConfig(t)
	reqData := request.UserRequest{RemoteIP: "203.0.113.5", Host: "example.com"}

	for _, tt := range []struct {
		verdict    action.Verdict
		wantStatus int
		wantBody   string
	}{
		{action.VerdictBlock, http.StatusForbidden, "403|node-a|203.0.113.5"},
		{action.VerdictRateLimit, http.StatusTooManyRequests, "429|node-a|203.0.113.5"},
	} {
		t.Run(tt.verdict.String(), func(t *testing.T) {
			rec := serveVerdictPage(tt.verdict, reqData, &config.RuleSet{}, cfg, pagesFor(cfg))
			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}
		})
	}

	// Anything that is not a Torii endpoint gets the 403 page.
	rec := serveTorii("/torii/not-an-endpoint", reqData, &config.RuleSet{}, cfg, &state.Runtime{})
	if rec.Code != http.StatusForbidden || rec.Body.String() != "403|node-a|203.0.113.5" {
		t.Fatalf("got %d %q, want the 403 page", rec.Code, rec.Body.String())
	}
}

func TestVerdictPagesMissingTemplates(t *testing.T) {
	cfg := &config.MainConfig{WebPath: "/torii", ErrorPage: t.TempDir()}
	ruleSet := captchaPageRuleSet(check.CaptchaProviderAltcha)
	for _, verdict := range []action.Verdict{action.VerdictBlock, action.VerdictRateLimit, action.VerdictCaptcha} {
		t.Run(verdict.String(), func(t *testing.T) {
			rec := serveVerdictPage(verdict, request.UserRequest{}, ruleSet, cfg, pagesFor(cfg))
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
		})
	}
	rec := serveTorii("/torii/not-an-endpoint", request.UserRequest{}, ruleSet, cfg, &state.Runtime{})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestPublicEndpointsRespectWebPath(t *testing.T) {
	cfg := newPagesConfig(t)
	cfg.WebPath = "/custom"
	// An endpoint under the wrong prefix must not be served as one.
	rec := serveTorii("/torii/health_check", request.UserRequest{}, &config.RuleSet{}, cfg, &state.Runtime{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	rec = serveTorii("/custom/health_check", request.UserRequest{}, &config.RuleSet{}, cfg, &state.Runtime{})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestHealthCheck(t *testing.T) {
	cfg := newPagesConfig(t)
	before := time.Now().Add(-time.Second)

	rec := serveTorii("/torii/health_check", request.UserRequest{}, &config.RuleSet{}, cfg, &state.Runtime{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
	lines := strings.Split(rec.Body.String(), "\n")
	if len(lines) != 11 || lines[0] != "ok" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	fields := map[string]string{}
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, "=")
		fields[k] = v
	}
	if fields["version"] != version.Version {
		t.Errorf("version = %q, want %q", fields["version"], version.Version)
	}
	if fields["commit"] != version.Commit() || fields["commit"] == "" {
		t.Errorf("commit = %q, want %q", fields["commit"], version.Commit())
	}
	if fields["sliver"] != "node-a" {
		t.Errorf("sliver = %q, want node-a", fields["sliver"])
	}
	ts, err := time.Parse(time.RFC3339, fields["time"])
	if err != nil || ts.Before(before.Truncate(time.Second)) {
		t.Errorf("time = %q (%v)", fields["time"], err)
	}
	if fields["ts"] == "" {
		t.Error("ts is empty")
	}
	// Without a running report listener the counters are all zero, but present.
	for _, counter := range []string{"reports_received", "reports_accepted", "reports_malformed", "reports_unknown_site", "reports_dropped"} {
		if fields[counter] != "0" {
			t.Errorf("%s = %q, want 0", counter, fields[counter])
		}
	}
}

// The node's own endpoints: the health check answers without the connector, the gossip endpoint
// only exists when gossip is enabled, and the legacy checker is gone.
func TestNodeEndpoints(t *testing.T) {
	cfg := newPagesConfig(t)
	cfg.EnableGossip = false
	s := NewServer(cfg, nil, &state.Runtime{}, nil)
	for path, want := range map[string]int{
		"/torii/health_check":      http.StatusOK,
		"/torii/gossip":            http.StatusNotFound,
		"/torii/checker":           http.StatusNotFound,
		"/torii/checker_pages/403": http.StatusNotFound,
		"/torii/captcha":           http.StatusNotFound,
		"/":                        http.StatusNotFound,
	} {
		if rec := v1Get(s, path, nil); rec.Code != want {
			t.Errorf("%s: status = %d, want %d", path, rec.Code, want)
		}
	}
}

func testAltchaServerRuleSet() *config.RuleSet {
	return &config.RuleSet{CAPTCHARule: &config.CaptchaRule{
		Provider:                       check.CaptchaProviderAltcha,
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            600,
		CaptchaChallengeSessionTimeout: 120,
		AltchaHMACSecret:               "altcha-secret",
		AltchaCost:                     1,
	}}
}

func solveAltcha(t *testing.T, ruleSet *config.RuleSet, reqData request.UserRequest) string {
	t.Helper()
	challenge, err := check.GenAltchaChallenge(*ruleSet, reqData)
	if err != nil {
		t.Fatalf("GenAltchaChallenge: %v", err)
	}
	solution, err := altcha.SolveChallenge(altcha.SolveChallengeOptions{Challenge: challenge, DeriveKey: altcha.DeriveKeyPBKDF2()})
	if err != nil || solution == nil {
		t.Fatalf("SolveChallenge: %v", err)
	}
	payload, err := json.Marshal(altcha.Payload{Challenge: challenge, Solution: *solution})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return base64.StdEncoding.EncodeToString(payload)
}

func postCaptcha(reqData request.UserRequest, ruleSet *config.RuleSet, sharedMem *state.Runtime, altchaValue string) *httptest.ResponseRecorder {
	reqData.Uri = "/torii/captcha"
	form := url.Values{"altcha": {altchaValue}}
	req := httptest.NewRequest(http.MethodPost, "/torii/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	NewServer(&config.MainConfig{WebPath: "/torii"}, nil, sharedMem, nil).servePublic(rec, req, reqData, ruleSet, nil)
	return rec
}

func TestCaptchaSuccessMarksClientVerified(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := request.UserRequest{RemoteIP: "203.0.113.77", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
	sharedMem := &state.Runtime{}
	sharedMem.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(1, 60))
	ata := analyzer.NewAdaptiveTrafficAnalyzer(sharedMem, nil)
	sharedMem.SetAnalyzer(ata)

	rec := postCaptcha(reqData, ruleSet, sharedMem, solveAltcha(t, ruleSet, reqData))

	if rec.Code != http.StatusOK || rec.Body.String() != "good" {
		t.Fatalf("got %d %q, want 200 good", rec.Code, rec.Body.String())
	}
	clearance := clearanceFrom(t, rec)
	if clearance == "" {
		t.Fatal("no clearance cookie set")
	}
	now := time.Now()
	if !ata.Marked(reqData.RemoteIP, now) {
		t.Fatal("solving the CAPTCHA did not exempt the IP from traffic analysis")
	}
	ttl := time.Duration(ruleSet.CAPTCHARule.CaptchaValidateTime) * time.Second
	if ata.Marked(reqData.RemoteIP, now.Add(ttl+time.Second)) {
		t.Fatal("verified mark outlives the CAPTCHA validate time")
	}
	if ata.Marked("203.0.113.78", now) {
		t.Fatal("another IP was marked")
	}
}

func TestCaptchaFailureDoesNotMarkClient(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := request.UserRequest{RemoteIP: "203.0.113.79", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	sharedMem := &state.Runtime{}
	sharedMem.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(1, 60))
	ata := analyzer.NewAdaptiveTrafficAnalyzer(sharedMem, nil)
	sharedMem.SetAnalyzer(ata)

	tests := []struct {
		name     string
		session  bool
		altcha   string
		wantBody string
	}{
		{"no solution", true, "", "bad"},
		{"garbage solution", true, "bm90LWpzb24=", "bad"},
		{"no session", false, "x", "badSession"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := reqData
			if tt.session {
				r.ToriiSessionID = string(check.GenSessionID(r, *ruleSet))
			}
			rec := postCaptcha(r, ruleSet, sharedMem, tt.altcha)
			if rec.Code != http.StatusOK || rec.Body.String() != tt.wantBody {
				t.Fatalf("got %d %q, want 200 %q", rec.Code, rec.Body.String(), tt.wantBody)
			}
			if clearanceFrom(t, rec) != "" {
				t.Fatal("clearance set after a failed CAPTCHA")
			}
			if ata.Marked(r.RemoteIP, time.Now()) {
				t.Fatal("failed CAPTCHA exempted the IP")
			}
		})
	}
}

func TestCaptchaSuccessWithoutAnalyzer(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := request.UserRequest{RemoteIP: "203.0.113.80", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
	sharedMem := &state.Runtime{}

	rec := postCaptcha(reqData, ruleSet, sharedMem, solveAltcha(t, ruleSet, reqData))
	if rec.Code != http.StatusOK || rec.Body.String() != "good" || clearanceFrom(t, rec) == "" {
		t.Fatalf("got %d %q, want 200 good with clearance", rec.Code, rec.Body.String())
	}
}

func TestCaptchaVerifierErrorReturnsRetryableStatus(t *testing.T) {
	solveRuleSet := testAltchaServerRuleSet()
	// Empty secrets make the ALTCHA verifier itself fail, standing in for an unreachable provider.
	brokenRuleSet := testAltchaServerRuleSet()
	brokenRuleSet.CAPTCHARule.SecretKey = ""
	brokenRuleSet.CAPTCHARule.AltchaHMACSecret = ""

	reqData := request.UserRequest{RemoteIP: "203.0.113.81", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *brokenRuleSet))
	sharedMem := &state.Runtime{}
	counter := ratelimit.NewCounter(1, 60)
	sharedMem.CaptchaFailureLimitCounter.Store(counter)

	rec := postCaptcha(reqData, brokenRuleSet, sharedMem, solveAltcha(t, solveRuleSet, reqData))

	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "error" {
		t.Fatalf("got %d %q, want 503 error", rec.Code, rec.Body.String())
	}
	if clearanceFrom(t, rec) != "" {
		t.Fatal("clearance set after a verifier error")
	}
	if got := counter.Query(reqData.RemoteIP, 60); got != 0 {
		t.Fatalf("verifier error counted as a client failure: %d", got)
	}
}

func TestCaptchaEndpointRejectsGet(t *testing.T) {
	cfg := newPagesConfig(t)
	rec := serveTorii("/torii/captcha", request.UserRequest{RemoteIP: "203.0.113.5"}, testAltchaServerRuleSet(), cfg, &state.Runtime{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestRuntimeMarksReachAnalyzer(t *testing.T) {
	// Marking without an analyzer, or without any runtime, is a no-op rather than a panic.
	for _, rt := range []*state.Runtime{nil, {}} {
		rt.MarkVerified("198.51.100.1", time.Minute)
		rt.MarkNeutral("198.51.100.2", time.Minute)
		if rt.HasBrowserEvidence("198.51.100.1") {
			t.Fatal("runtime without analyzer reported browser evidence")
		}
	}

	ata := analyzer.NewAdaptiveTrafficAnalyzer(nil, nil)
	rt := &state.Runtime{}
	rt.SetAnalyzer(ata)

	now := time.Now()
	rt.MarkVerified("198.51.100.1", time.Minute)
	rt.MarkNeutral("198.51.100.2", time.Minute)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if !ata.Marked(ip, now) {
			t.Errorf("%s not marked", ip)
		}
		if ata.Marked(ip, now.Add(2*time.Minute)) {
			t.Errorf("%s mark did not expire", ip)
		}
	}
}

// pagesFor parses cfg's error pages the way a config reload does, so tests exercise the precompiled path.
func pagesFor(cfg *config.MainConfig) *config.ErrorPages {
	if cfg.ErrorPage == "" {
		return nil
	}
	pages, err := config.LoadErrorPages(cfg.ErrorPage)
	if err != nil {
		panic(err)
	}
	return pages
}

func TestErrorPagesAreParsedOnce(t *testing.T) {
	cfg := newPagesConfig(t)
	pages := pagesFor(cfg)
	// Once loaded, the templates no longer depend on the files: deleting them must not matter.
	if err := os.Remove(filepath.Join(cfg.ErrorPage, "403.html")); err != nil {
		t.Fatal(err)
	}
	reqData := request.UserRequest{RemoteIP: "203.0.113.5"}
	rec := serveVerdictPage(action.VerdictBlock, reqData, &config.RuleSet{}, cfg, pages)
	if rec.Code != http.StatusForbidden || rec.Body.String() != "403|node-a|203.0.113.5" {
		t.Fatalf("got %d %q, want precompiled 403 page", rec.Code, rec.Body.String())
	}
}

func TestNilErrorPagesAnswer500(t *testing.T) {
	cfg := newPagesConfig(t)
	rec := serveVerdictPage(action.VerdictBlock, request.UserRequest{}, &config.RuleSet{}, cfg, nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}
