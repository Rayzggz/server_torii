package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
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

func serveTorii(path string, reqData dataType.UserRequest, ruleSet *config.RuleSet, cfg *config.MainConfig, sharedMem *dataType.SharedMemory) *httptest.ResponseRecorder {
	reqData.Uri = path
	rec := httptest.NewRecorder()
	CheckTorii(rec, httptest.NewRequest(http.MethodGet, path, nil), reqData, ruleSet, cfg, sharedMem)
	return rec
}

func TestCheckerPagesRenderTemplates(t *testing.T) {
	cfg := newPagesConfig(t)
	reqData := dataType.UserRequest{RemoteIP: "203.0.113.5", Host: "example.com"}

	tests := []struct {
		path       string
		wantStatus int
		wantBody   string
	}{
		{"/torii/checker_pages/403", http.StatusForbidden, "403|node-a|203.0.113.5"},
		{"/torii/checker_pages/429", http.StatusTooManyRequests, "429|node-a|203.0.113.5"},
		{"/torii/checker_pages/unknown", http.StatusForbidden, "403|node-a|203.0.113.5"},
		// Anything that is not a Torii endpoint falls through to the default 403.
		{"/torii/not-an-endpoint", http.StatusForbidden, "403|node-a|203.0.113.5"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			rec := serveTorii(tt.path, reqData, &config.RuleSet{}, cfg, &dataType.SharedMemory{})
			if rec.Code != tt.wantStatus || rec.Body.String() != tt.wantBody {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Body.String(), tt.wantStatus, tt.wantBody)
			}
		})
	}
}

func TestCheckerPagesMissingTemplates(t *testing.T) {
	cfg := &config.MainConfig{WebPath: "/torii", ErrorPage: t.TempDir()}
	ruleSet := captchaPageRuleSet(check.CaptchaProviderAltcha)
	for _, path := range []string{
		"/torii/checker_pages/403",
		"/torii/checker_pages/429",
		"/torii/checker_pages/CAPTCHA",
		"/torii/checker_pages/unknown",
		"/torii/not-an-endpoint",
	} {
		t.Run(path, func(t *testing.T) {
			rec := serveTorii(path, dataType.UserRequest{}, ruleSet, cfg, &dataType.SharedMemory{})
			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want 500", rec.Code)
			}
		})
	}
}

func TestCheckerPagesRespectWebPath(t *testing.T) {
	cfg := newPagesConfig(t)
	cfg.WebPath = "/custom"
	// A checker page under the wrong prefix must not be served as one.
	rec := serveTorii("/torii/checker_pages/429", dataType.UserRequest{}, &config.RuleSet{}, cfg, &dataType.SharedMemory{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
	rec = serveTorii("/custom/checker_pages/429", dataType.UserRequest{}, &config.RuleSet{}, cfg, &dataType.SharedMemory{})
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429", rec.Code)
	}
}

func TestHealthCheck(t *testing.T) {
	cfg := newPagesConfig(t)
	before := time.Now().Add(-time.Second)

	rec := serveTorii("/torii/health_check", dataType.UserRequest{}, &config.RuleSet{}, cfg, &dataType.SharedMemory{})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("Content-Type = %q", ct)
	}
	lines := strings.Split(rec.Body.String(), "\n")
	if len(lines) != 5 || lines[0] != "ok" {
		t.Fatalf("body = %q", rec.Body.String())
	}
	fields := map[string]string{}
	for _, l := range lines[1:] {
		k, v, _ := strings.Cut(l, "=")
		fields[k] = v
	}
	if fields["version"] != dataType.ServerToriiVersion {
		t.Errorf("version = %q, want %q", fields["version"], dataType.ServerToriiVersion)
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
}

func TestGossipEndpointDisabledFallsThroughTo403(t *testing.T) {
	cfg := newPagesConfig(t)
	cfg.EnableGossip = false
	rec := serveTorii("/torii/gossip", dataType.UserRequest{RemoteIP: "203.0.113.5"}, &config.RuleSet{}, cfg, &dataType.SharedMemory{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func testAltchaServerRuleSet() *config.RuleSet {
	return &config.RuleSet{CAPTCHARule: &dataType.CaptchaRule{
		Provider:                       check.CaptchaProviderAltcha,
		SecretKey:                      "1234567890abcdef",
		CaptchaValidateTime:            600,
		CaptchaChallengeSessionTimeout: 120,
		AltchaHMACSecret:               "altcha-secret",
		AltchaCost:                     1,
	}}
}

func solveAltcha(t *testing.T, ruleSet *config.RuleSet, reqData dataType.UserRequest) string {
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

func postCaptcha(reqData dataType.UserRequest, ruleSet *config.RuleSet, sharedMem *dataType.SharedMemory, altchaValue string) *httptest.ResponseRecorder {
	reqData.Uri = "/torii/captcha"
	form := url.Values{"altcha": {altchaValue}}
	req := httptest.NewRequest(http.MethodPost, "/torii/captcha", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	CheckTorii(rec, req, reqData, ruleSet, &config.MainConfig{WebPath: "/torii"}, sharedMem)
	return rec
}

func TestCaptchaSuccessMarksClientVerified(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := dataType.UserRequest{RemoteIP: "203.0.113.77", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
	sharedMem := &dataType.SharedMemory{}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(1, 60))
	analyzer := NewAdaptiveTrafficAnalyzer(sharedMem)
	sharedMem.AdaptiveTrafficAnalyzer = analyzer

	rec := postCaptcha(reqData, ruleSet, sharedMem, solveAltcha(t, ruleSet, reqData))

	if rec.Code != http.StatusOK || rec.Body.String() != "good" {
		t.Fatalf("got %d %q, want 200 good", rec.Code, rec.Body.String())
	}
	clearance := clearanceFrom(t, rec)
	if clearance == "" {
		t.Fatal("no clearance cookie set")
	}
	now := time.Now()
	if !analyzer.marks.active(reqData.RemoteIP, now) {
		t.Fatal("solving the CAPTCHA did not exempt the IP from traffic analysis")
	}
	ttl := time.Duration(ruleSet.CAPTCHARule.CaptchaValidateTime) * time.Second
	if analyzer.marks.active(reqData.RemoteIP, now.Add(ttl+time.Second)) {
		t.Fatal("verified mark outlives the CAPTCHA validate time")
	}
	if analyzer.marks.active("203.0.113.78", now) {
		t.Fatal("another IP was marked")
	}
}

func TestCaptchaFailureDoesNotMarkClient(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := dataType.UserRequest{RemoteIP: "203.0.113.79", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	sharedMem := &dataType.SharedMemory{}
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(1, 60))
	analyzer := NewAdaptiveTrafficAnalyzer(sharedMem)
	sharedMem.AdaptiveTrafficAnalyzer = analyzer

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
			if analyzer.marks.active(r.RemoteIP, time.Now()) {
				t.Fatal("failed CAPTCHA exempted the IP")
			}
		})
	}
}

func TestCaptchaSuccessWithoutAnalyzer(t *testing.T) {
	ruleSet := testAltchaServerRuleSet()
	reqData := dataType.UserRequest{RemoteIP: "203.0.113.80", Host: "example.com", UserAgent: "Mozilla/5.0 test"}
	reqData.ToriiSessionID = string(check.GenSessionID(reqData, *ruleSet))
	sharedMem := &dataType.SharedMemory{}

	rec := postCaptcha(reqData, ruleSet, sharedMem, solveAltcha(t, ruleSet, reqData))
	if rec.Code != http.StatusOK || rec.Body.String() != "good" || clearanceFrom(t, rec) == "" {
		t.Fatalf("got %d %q, want 200 good with clearance", rec.Code, rec.Body.String())
	}
}

func TestCaptchaEndpointRejectsGet(t *testing.T) {
	cfg := newPagesConfig(t)
	rec := serveTorii("/torii/captcha", dataType.UserRequest{RemoteIP: "203.0.113.5"}, testAltchaServerRuleSet(), cfg, &dataType.SharedMemory{})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}
}

func TestTrafficMarkerOf(t *testing.T) {
	if _, ok := dataType.TrafficMarkerOf(nil); ok {
		t.Fatal("nil shared memory reported a marker")
	}
	if _, ok := dataType.TrafficMarkerOf(&dataType.SharedMemory{}); ok {
		t.Fatal("missing analyzer reported a marker")
	}
	if _, ok := dataType.TrafficMarkerOf(&dataType.SharedMemory{AdaptiveTrafficAnalyzer: "not an analyzer"}); ok {
		t.Fatal("wrong type reported a marker")
	}
	analyzer := NewAdaptiveTrafficAnalyzer(nil)
	marker, ok := dataType.TrafficMarkerOf(&dataType.SharedMemory{AdaptiveTrafficAnalyzer: analyzer})
	if !ok {
		t.Fatal("analyzer is not a TrafficMarker")
	}

	now := time.Now()
	marker.MarkVerified("198.51.100.1", time.Minute)
	marker.MarkNeutral("198.51.100.2", time.Minute)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		if !analyzer.marks.active(ip, now) {
			t.Errorf("%s not marked", ip)
		}
		if analyzer.marks.active(ip, now.Add(2*time.Minute)) {
			t.Errorf("%s mark did not expire", ip)
		}
	}
}
