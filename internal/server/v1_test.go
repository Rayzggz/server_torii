package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"server_torii/internal/urllist"
	"strings"
	"testing"
	"time"
)

// newV1Server serves two sites: "shop", which blocks /blocked, and the default site.
func newV1Server(t *testing.T) *Server {
	t.Helper()
	dir := t.TempDir()
	writePage(t, dir, "403.html", "403|{{.ConnectIP}}")
	writePage(t, dir, "429.html", "429|{{.ConnectIP}}")
	writePage(t, dir, "CAPTCHA.html", "captcha page")
	cfg := &config.MainConfig{WebPath: "/torii", ErrorPage: dir, NodeName: "node-a"}

	shop := config.NewRuleSet()
	shop.ID = "shop"
	fallback := config.NewRuleSet()
	fallback.ID = "default_site"
	shop.URLBlockRule.Enabled = true
	shop.URLBlockRule.List.Append(&urllist.URLRule{Pattern: "/blocked"})
	shop.CAPTCHARule = &config.CaptchaRule{SecretKey: "1234567890abcdef", CaptchaValidateTime: 60, CaptchaChallengeSessionTimeout: 120}

	configs := config.NewManager()
	configs.Set(&config.SiteConfigSnapshot{
		SiteRules:   map[string]*config.RuleSet{"shop": shop, "default_site": fallback},
		DefaultSite: "default_site",
		Pages:       pagesFor(cfg),
	})
	rt := &state.Runtime{}
	rt.CaptchaFailureLimitCounter.Store(ratelimit.NewCounter(16, 1))
	return NewServer(cfg, configs, rt, nil)
}

func v1Get(s *Server, path string, headers map[string]string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, r)
	return rec
}

func TestV1CheckPass(t *testing.T) {
	rec := v1Get(newV1Server(t), v1CheckPath, map[string]string{
		headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/ok", headerHost: "shop.example",
	})
	if rec.Code != http.StatusNoContent || rec.Header().Get(headerDecision) != "pass" || rec.Body.Len() != 0 {
		t.Fatalf("got %d decision %q body %q", rec.Code, rec.Header().Get(headerDecision), rec.Body.String())
	}
}

// A request that is not let through is answered with the page the visitor should see.
func TestV1CheckAnswersWithThePage(t *testing.T) {
	rec := v1Get(newV1Server(t), v1CheckPath, map[string]string{
		headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/blocked",
	})
	if rec.Code != http.StatusForbidden || rec.Body.String() != "403|203.0.113.5" {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get(headerDecision); got != "block" {
		t.Errorf("decision = %q, want block", got)
	}
	if got := rec.Header().Get(headerReason); got != "URLBlock" {
		t.Errorf("reason = %q, want URLBlock", got)
	}
}

func TestV1CheckCaptchaPageSetsSession(t *testing.T) {
	rec := v1Get(newV1Server(t), v1CheckPath, map[string]string{
		headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/ok", headerFeatures: "+captcha",
	})
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != "captcha page" || rec.Header().Get(headerDecision) != "captcha" {
		t.Fatalf("got %d decision %q body %q", rec.Code, rec.Header().Get(headerDecision), rec.Body.String())
	}
	if cookie := rec.Header().Get("Set-Cookie"); !strings.HasPrefix(cookie, "__torii_session_id=") {
		t.Errorf("Set-Cookie = %q, want a challenge session", cookie)
	}
}

func TestV1SiteSelection(t *testing.T) {
	s := newV1Server(t)
	blocked := map[string]string{headerClientIP: "203.0.113.5", headerURI: "/blocked", headerHost: "shop.example"}

	// The host never selects the site: a request that names none belongs to the default site.
	if rec := v1Get(s, v1CheckPath, blocked); rec.Header().Get(headerDecision) != "pass" {
		t.Errorf("default site: got %d decision %q", rec.Code, rec.Header().Get(headerDecision))
	}
	blocked[headerSite] = "shop"
	if rec := v1Get(s, v1CheckPath, blocked); rec.Header().Get(headerDecision) != "block" {
		t.Errorf("named site: got %d decision %q", rec.Code, rec.Header().Get(headerDecision))
	}

	// Without a default site such a request gets no decision.
	snap := *s.configs.Get()
	snap.DefaultSite = ""
	s.configs.Set(&snap)
	delete(blocked, headerSite)
	if rec := v1Get(s, v1CheckPath, blocked); rec.Code != http.StatusInternalServerError || rec.Header().Get(headerDecision) != "" {
		t.Errorf("no default site: got %d decision %q", rec.Code, rec.Header().Get(headerDecision))
	}
}

// Rate counters and temporary blocks of one site do not affect another.
func TestV1SitesAreIsolated(t *testing.T) {
	s := newV1Server(t)
	engine := action.NewActionRuleEngine(time.Minute)
	t.Cleanup(engine.Stop)
	s.rt.ActionRuleEngine = engine

	snap := s.configs.Get()
	for _, rs := range snap.SiteRules {
		rs.HTTPFloodRule.Enabled = true
		rs.HTTPFloodRule.HTTPFloodSpeedLimit = map[int64]int64{10: 2}
		rs.HTTPFloodRule.HTTPFloodSameURILimit = map[int64]int64{10: 100}
		rs.HTTPFloodRule.HTTPFloodFailureLimit = map[int64]int64{10: 100}
	}
	s.rt.ResizeSites(snap.CounterWindows())

	check := func(site string) string {
		return v1Get(s, v1CheckPath, map[string]string{
			headerSite: site, headerClientIP: "203.0.113.5", headerURI: "/ok",
		}).Header().Get(headerDecision)
	}
	for i := 0; i < 2; i++ {
		if got := check("shop"); got != "pass" {
			t.Fatalf("shop request %d: %q", i+1, got)
		}
	}
	if got := check("shop"); got != "rate_limit" {
		t.Fatalf("shop over its limit: %q, want rate_limit", got)
	}
	// The same client has made no request to the other site yet.
	if got := check("default_site"); got != "pass" {
		t.Fatalf("other site: %q, want pass", got)
	}

	// A block on one site stays on that site.
	s.rt.BlockIP("default_site", "203.0.113.9", time.Minute)
	blockedOn := func(site string) string {
		return v1Get(s, v1CheckPath, map[string]string{
			headerSite: site, headerClientIP: "203.0.113.9", headerURI: "/ok",
		}).Header().Get(headerDecision)
	}
	if got := blockedOn("default_site"); got != "block" {
		t.Fatalf("blocked site: %q, want block", got)
	}
	if got := blockedOn("shop"); got != "pass" {
		t.Fatalf("block leaked to another site: %q", got)
	}
}

// Without a Torii-Decision header the connector knows Torii reached no decision.
func TestV1NoDecisionOnErrors(t *testing.T) {
	s := newV1Server(t)
	for name, tt := range map[string]struct {
		headers map[string]string
		want    int
	}{
		"unknown site": {map[string]string{headerSite: "nope", headerClientIP: "203.0.113.5", headerURI: "/"}, http.StatusInternalServerError},
		"missing ip":   {map[string]string{headerSite: "shop", headerURI: "/"}, http.StatusBadRequest},
		"missing uri":  {map[string]string{headerSite: "shop", headerClientIP: "203.0.113.5"}, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			rec := v1Get(s, v1CheckPath, tt.headers)
			if rec.Code != tt.want || rec.Header().Get(headerDecision) != "" {
				t.Fatalf("got %d decision %q, want %d and none", rec.Code, rec.Header().Get(headerDecision), tt.want)
			}
		})
	}

	s.configs.Set(nil)
	rec := v1Get(s, v1CheckPath, map[string]string{headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/"})
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get(headerDecision) != "" {
		t.Fatalf("no snapshot: got %d decision %q", rec.Code, rec.Header().Get(headerDecision))
	}
}

func TestV1PublicEndpoints(t *testing.T) {
	s := newV1Server(t)
	headers := map[string]string{headerSite: "shop", headerClientIP: "203.0.113.5", headerURI: "/torii/health_check"}
	rec := v1Get(s, v1PublicPrefix+"health_check", headers)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "sliver=node-a") {
		t.Fatalf("health check: got %d %q", rec.Code, rec.Body.String())
	}

	headers[headerURI] = "/torii/not-an-endpoint"
	rec = v1Get(s, v1PublicPrefix+"not-an-endpoint", headers)
	if rec.Code != http.StatusForbidden || rec.Body.String() != "403|203.0.113.5" {
		t.Fatalf("unknown endpoint: got %d %q", rec.Code, rec.Body.String())
	}
}

func TestApplyFeatureOverrides(t *testing.T) {
	base := uint16(request.FeatureHTTPFlood | request.FeatureCaptcha)
	for _, tt := range []struct {
		header  string
		want    uint16
		unknown int
	}{
		{"", base, 0},
		{"-captcha", request.FeatureHTTPFlood, 0},
		{"-Captcha, +ip_block", request.FeatureHTTPFlood | request.FeatureIPBlock, 0},
		{"+HTTPFlood +http-flood", base, 0},
		{"-http_flood,-captcha", 0, 0},
		// Entries without a sign, unknown names and checks without a switch are reported.
		{"captcha +nope -ActionRule +", base, 4},
	} {
		got, unknown := applyFeatureOverrides(base, tt.header)
		if got != tt.want || len(unknown) != tt.unknown {
			t.Errorf("%q: bits %b unknown %v, want %b and %d unknown", tt.header, got, unknown, tt.want, tt.unknown)
		}
	}
}

func TestListenUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.sock")

	// A socket file left by a crashed process does not prevent the next start.
	stale, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	}
	stale.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = stale.Close()

	ln, err := listen(config.UnixListenPrefix+path, 0o660)
	if err != nil {
		t.Fatalf("listen over a stale socket: %v", err)
	}
	// A socket that still answers belongs to a running process and is left alone.
	if _, err := listen(config.UnixListenPrefix+path, 0o660); err == nil {
		t.Fatal("listened on a socket that is in use")
	}
	_ = ln.Close()

	// Anything that is not a socket is never deleted.
	file := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(file, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := listen(config.UnixListenPrefix+file, 0o660); err == nil {
		t.Fatal("listened on a regular file")
	}
	if data, _ := os.ReadFile(file); string(data) != "keep" {
		t.Fatal("regular file was modified")
	}
}

func TestListenAllClosesOnFailure(t *testing.T) {
	if _, err := listenAll([]string{"127.0.0.1:0", "127.0.0.1:notaport"}, 0o660); err == nil {
		t.Fatal("expected an error for the invalid address")
	}
}

// Run serves the same handler on a TCP port and a Unix socket at once.
func TestRunServesTCPAndUnix(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "t.sock")
	if probe, err := net.Listen("unix", sock); err != nil {
		t.Skipf("unix sockets unavailable: %v", err)
	} else {
		_ = probe.Close()
	}
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcpAddr := tcp.Addr().String()
	_ = tcp.Close()

	s := newV1Server(t)
	_, port, _ := net.SplitHostPort(tcpAddr)
	s.cfg.Port = port
	s.cfg.Listen = []string{tcpAddr, config.UnixListenPrefix + sock}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()

	clients := map[string]*http.Client{
		"tcp": {Timeout: 2 * time.Second},
		"unix": {Timeout: 2 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		}},
	}
	for name, client := range clients {
		var body string
		deadline := time.Now().Add(5 * time.Second)
		for {
			req, _ := http.NewRequest(http.MethodGet, "http://"+tcpAddr+v1PublicPrefix+"health_check", nil)
			req.Header.Set(headerClientIP, "203.0.113.5")
			req.Header.Set(headerURI, "/torii/health_check")
			resp, err := client.Do(req)
			if err == nil {
				data, _ := io.ReadAll(resp.Body)
				_ = resp.Body.Close()
				body = string(data)
				break
			}
			if time.Now().After(deadline) {
				cancel()
				t.Fatalf("%s: server not reachable: %v", name, err)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if !strings.Contains(body, "sliver=node-a") {
			t.Errorf("%s: body %q", name, body)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("Run did not stop")
	}
	if _, err := os.Lstat(sock); !os.IsNotExist(err) {
		t.Errorf("socket file still present after shutdown: %v", err)
	}
}
