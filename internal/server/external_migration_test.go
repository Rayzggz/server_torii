package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"server_torii/internal/action"
	"server_torii/internal/check"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateInternalRedirectPath(t *testing.T) {
	tests := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "/", want: "/"},
		{raw: "/return", want: "/return"},
		{raw: "/a/b?x=1&y=2#top", want: "/a/b?x=1&y=2#top"},
		{raw: "/caf%C3%A9", want: "/café"},
		{raw: "", wantErr: true},
		{raw: "return", wantErr: true},
		{raw: "../etc", wantErr: true},
		{raw: "?x=1", wantErr: true},
		{raw: "https://evil.example/", wantErr: true},
		{raw: "javascript:alert(1)", wantErr: true},
		{raw: "//evil.example/", wantErr: true},
		{raw: "///evil.example/", wantErr: true},
		{raw: "/%2Fevil.example/", wantErr: true},
		// Browsers read a backslash as a slash, so these become scheme-relative.
		{raw: `/\evil.example/`, wantErr: true},
		{raw: "/%5Cevil.example/", wantErr: true},
		{raw: `\\evil.example/`, wantErr: true},
		{raw: "/\nLocation: x", wantErr: true},
		{raw: "%zz", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := validateInternalRedirectPath(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("validateInternalRedirectPath(%q) = %q, want error", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateInternalRedirectPath(%q) error: %v", tt.raw, err)
			}
			if got != tt.want {
				t.Fatalf("validateInternalRedirectPath(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

type externalFixture struct {
	ruleSet *config.RuleSet
	cfg     *config.MainConfig
	reqData dataType.UserRequest
}

func newExternalFixture(t *testing.T) *externalFixture {
	t.Helper()
	dir := t.TempDir()
	writePage(t, dir, "error.html", "{{.ErrorCode}}|{{.ErrorTitle}}|{{.ErrorMessage}}|{{.EdgeTag}}|{{.ConnectIP}}")
	f := &externalFixture{
		ruleSet: &config.RuleSet{ExternalMigrationRule: &dataType.ExternalMigrationRule{
			Enabled:        true,
			RedirectUrl:    "https://mitigation.invalid/verify",
			SecretKey:      "external-secret-0123456789",
			SessionTimeout: 600,
		}},
		cfg: &config.MainConfig{WebPath: "/torii", ErrorPage: dir, NodeName: "node-a"},
		reqData: dataType.UserRequest{
			RemoteIP:       "203.0.113.10",
			Host:           "example.com",
			UserAgent:      "Mozilla/5.0 test-agent",
			FeatureControl: dataType.FeatureExternalMigration,
		},
	}
	f.reqData.ToriiSessionID = string(check.GenExternalMigrationSessionID(f.reqData, *f.ruleSet))
	return f
}

func writePage(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// migrate calls the callback endpoint the mitigation provider redirects back to.
func (f *externalFixture) migrate(t *testing.T, reqData dataType.UserRequest, q url.Values) *httptest.ResponseRecorder {
	t.Helper()
	target := "/torii/external_migration?" + q.Encode()
	reqData.Uri = target
	rec := httptest.NewRecorder()
	CheckTorii(rec, httptest.NewRequest(http.MethodGet, target, nil), reqData, f.ruleSet, f.cfg, &dataType.SharedMemory{}, pagesFor(f.cfg))
	return rec
}

func (f *externalFixture) signedQuery(originalURI string, ts int64) url.Values {
	stamp := strconv.FormatInt(ts, 10)
	return url.Values{
		"original_uri": {originalURI},
		"timestamp":    {stamp},
		"hmac":         {check.CalculateExternalMigrationHMAC(f.reqData.ToriiSessionID, stamp, originalURI, f.ruleSet.ExternalMigrationRule.SecretKey)},
	}
}

func clearanceFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__torii_clearance" {
			return c.Value
		}
	}
	return ""
}

func TestExternalMigrationCallbackGrantsClearance(t *testing.T) {
	f := newExternalFixture(t)
	const originalURI = "/return/path?x=1&y=2"

	rec := f.migrate(t, f.reqData, f.signedQuery(originalURI, time.Now().Unix()))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302, body=%s", rec.Code, rec.Body.String())
	}
	if loc := rec.Header().Get("Location"); loc != originalURI {
		t.Fatalf("Location = %q, want %q", loc, originalURI)
	}
	clearance := clearanceFrom(t, rec)
	if clearance == "" {
		t.Fatal("no clearance cookie set")
	}

	// The issued clearance must pass the ExternalMigration check on the next request.
	next := f.reqData
	next.ToriiClearance = clearance
	decision := action.NewDecision()
	check.ExternalMigration(next, f.ruleSet, decision, &dataType.SharedMemory{})
	if decision.State != action.Continue {
		t.Fatalf("clearance rejected: state=%v code=%q", decision.State, decision.Verdict)
	}
}

func TestExternalMigrationCallbackRejections(t *testing.T) {
	f := newExternalFixture(t)
	now := time.Now().Unix()

	tests := []struct {
		name    string
		reqData func() dataType.UserRequest
		query   func() url.Values
		wantMsg string
	}{
		{
			name:    "missing original_uri",
			query:   func() url.Values { q := f.signedQuery("/r", now); q.Del("original_uri"); return q },
			wantMsg: "Invalid Original URI",
		},
		{
			name:    "absolute original_uri",
			query:   func() url.Values { return f.signedQuery("https://evil.example/", now) },
			wantMsg: "Invalid Original URI",
		},
		{
			name:    "backslash original_uri",
			query:   func() url.Values { return f.signedQuery(`/\evil.example/`, now) },
			wantMsg: "Invalid Original URI",
		},
		{
			name:    "missing timestamp",
			query:   func() url.Values { q := f.signedQuery("/r", now); q.Del("timestamp"); return q },
			wantMsg: "Missing required parameters",
		},
		{
			name:    "missing hmac",
			query:   func() url.Values { q := f.signedQuery("/r", now); q.Del("hmac"); return q },
			wantMsg: "Missing required parameters",
		},
		{
			name:    "non-numeric timestamp",
			query:   func() url.Values { q := f.signedQuery("/r", now); q.Set("timestamp", "soon"); return q },
			wantMsg: "Invalid timestamp format",
		},
		{
			name:    "expired link",
			query:   func() url.Values { return f.signedQuery("/r", now-31) },
			wantMsg: "Migration link has expired",
		},
		{
			name:    "missing session",
			reqData: func() dataType.UserRequest { r := f.reqData; r.ToriiSessionID = ""; return r },
			query:   func() url.Values { return f.signedQuery("/r", now) },
			wantMsg: "Invalid session",
		},
		{
			name:    "session from another host",
			reqData: func() dataType.UserRequest { r := f.reqData; r.Host = "other.example.com"; return r },
			query:   func() url.Values { return f.signedQuery("/r", now) },
			wantMsg: "Invalid session",
		},
		{
			name:    "tampered hmac",
			query:   func() url.Values { q := f.signedQuery("/r", now); q.Set("hmac", strings.Repeat("0", 128)); return q },
			wantMsg: "Invalid migration signature",
		},
		{
			name: "redirect target swapped after signing",
			query: func() url.Values {
				q := f.signedQuery("/r", now)
				q.Set("original_uri", "/admin")
				return q
			},
			wantMsg: "Invalid migration signature",
		},
		{
			name: "timestamp changed after signing",
			query: func() url.Values {
				q := f.signedQuery("/r", now)
				q.Set("timestamp", strconv.FormatInt(now-1, 10))
				return q
			},
			wantMsg: "Invalid migration signature",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqData := f.reqData
			if tt.reqData != nil {
				reqData = tt.reqData()
			}
			rec := f.migrate(t, reqData, tt.query())
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400", rec.Code)
			}
			if clearanceFrom(t, rec) != "" {
				t.Fatal("clearance cookie set on a rejected migration")
			}
			want := "400|Migration Error|" + tt.wantMsg + "|node-a|" + reqData.RemoteIP
			if body := rec.Body.String(); body != want {
				t.Fatalf("body = %q, want %q", body, want)
			}
		})
	}
}

func TestExternalMigrationErrorPageMissingTemplate(t *testing.T) {
	f := newExternalFixture(t)
	f.cfg.ErrorPage = t.TempDir()

	rec := f.migrate(t, f.reqData, url.Values{})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
}

func TestCheckerPageExternalRedirectsToProvider(t *testing.T) {
	f := newExternalFixture(t)
	reqData := f.reqData
	reqData.ToriiSessionID = ""
	reqData.Uri = "/protected"

	rec := httptest.NewRecorder()
	CheckTorii(rec, httptest.NewRequest(http.MethodGet, "/torii/checker_pages/EXTERNAL", nil), reqData, f.ruleSet, f.cfg, &dataType.SharedMemory{}, pagesFor(f.cfg))

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	var session string
	for _, c := range rec.Result().Cookies() {
		if c.Name == "__torii_session_id" {
			session = c.Value
		}
	}
	if session == "" {
		t.Fatal("no external session cookie set")
	}
	withSession := reqData
	withSession.ToriiSessionID = session
	if !check.VerifyExternalMigrationSessionIDCookie(withSession, *f.ruleSet) {
		t.Fatalf("issued session %q does not verify", session)
	}

	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("Location is not a URL: %v", err)
	}
	if got := loc.Scheme + "://" + loc.Host + loc.Path; got != f.ruleSet.ExternalMigrationRule.RedirectUrl {
		t.Fatalf("redirect base = %q, want %q", got, f.ruleSet.ExternalMigrationRule.RedirectUrl)
	}
	q := loc.Query()
	if q.Get("domain") != "example.com" || q.Get("session_id") != session || q.Get("original_uri") != "/protected" {
		t.Fatalf("redirect query = %v", q)
	}
	stamp, _, _ := strings.Cut(session, ":")
	wantHMAC := check.CalculateRedirectHMAC("example.com", stamp, "/protected", f.ruleSet.ExternalMigrationRule.SecretKey)
	if q.Get("hmac") != wantHMAC {
		t.Fatalf("hmac = %q, want %q", q.Get("hmac"), wantHMAC)
	}
}

// The whole round trip: challenge page → provider → signed callback → clearance.
func TestExternalMigrationRoundTrip(t *testing.T) {
	f := newExternalFixture(t)
	reqData := f.reqData
	reqData.ToriiSessionID = ""
	reqData.Uri = "/protected"

	rec := httptest.NewRecorder()
	CheckTorii(rec, httptest.NewRequest(http.MethodGet, "/torii/checker_pages/EXTERNAL", nil), reqData, f.ruleSet, f.cfg, &dataType.SharedMemory{}, pagesFor(f.cfg))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	provider := loc.Query()

	// The provider verifies Torii's signature, then signs its own callback.
	stamp, _, _ := strings.Cut(provider.Get("session_id"), ":")
	key := f.ruleSet.ExternalMigrationRule.SecretKey
	if provider.Get("hmac") != check.CalculateRedirectHMAC(provider.Get("domain"), stamp, provider.Get("original_uri"), key) {
		t.Fatal("provider could not verify the redirect signature")
	}
	f.reqData.ToriiSessionID = provider.Get("session_id")
	cb := f.migrate(t, f.reqData, f.signedQuery(provider.Get("original_uri"), time.Now().Unix()))
	if cb.Code != http.StatusFound || cb.Header().Get("Location") != "/protected" {
		t.Fatalf("callback = %d %q, want 302 /protected", cb.Code, cb.Header().Get("Location"))
	}

	next := f.reqData
	next.ToriiClearance = clearanceFrom(t, cb)
	decision := action.NewDecision()
	check.ExternalMigration(next, f.ruleSet, decision, &dataType.SharedMemory{})
	if decision.State != action.Continue {
		t.Fatalf("clearance rejected after round trip: %v %q", decision.State, decision.Verdict)
	}
}

func TestCheckerPageExternalEscapesRedirectQuery(t *testing.T) {
	tests := []struct {
		name        string
		redirectURL string
		uri         string
		wantQuery   url.Values
	}{
		{
			name:        "original URI with its own query",
			redirectURL: "https://mitigation.invalid/verify",
			uri:         "/search?q=a b&page=2#frag",
		},
		{
			name:        "original URI that injects provider parameters",
			redirectURL: "https://mitigation.invalid/verify",
			uri:         "/x?domain=evil.example&hmac=0",
		},
		{
			name:        "redirect URL that already has a query",
			redirectURL: "https://mitigation.invalid/verify?tenant=42",
			uri:         "/a?b=1",
			wantQuery:   url.Values{"tenant": {"42"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newExternalFixture(t)
			f.ruleSet.ExternalMigrationRule.RedirectUrl = tt.redirectURL
			reqData := f.reqData
			reqData.Uri = tt.uri

			rec := httptest.NewRecorder()
			CheckTorii(rec, httptest.NewRequest(http.MethodGet, "/torii/checker_pages/EXTERNAL", nil), reqData, f.ruleSet, f.cfg, &dataType.SharedMemory{}, pagesFor(f.cfg))

			loc, err := url.Parse(rec.Header().Get("Location"))
			if err != nil {
				t.Fatalf("Location is not a URL: %v", err)
			}
			if loc.Fragment != "" {
				t.Fatalf("fragment leaked into the provider URL: %q", loc.Fragment)
			}
			q := loc.Query()
			for _, key := range []string{"domain", "session_id", "original_uri", "hmac"} {
				if len(q[key]) != 1 {
					t.Fatalf("%s appears %d times in %q", key, len(q[key]), loc.RawQuery)
				}
			}
			if q.Get("original_uri") != tt.uri || q.Get("domain") != "example.com" {
				t.Fatalf("provider sees original_uri=%q domain=%q", q.Get("original_uri"), q.Get("domain"))
			}
			for k, v := range tt.wantQuery {
				if q.Get(k) != v[0] {
					t.Fatalf("%s = %q, want %q", k, q.Get(k), v[0])
				}
			}
			// The provider must be able to verify the signature from the decoded values.
			stamp, _, _ := strings.Cut(q.Get("session_id"), ":")
			want := check.CalculateRedirectHMAC(q.Get("domain"), stamp, q.Get("original_uri"), f.ruleSet.ExternalMigrationRule.SecretKey)
			if q.Get("hmac") != want {
				t.Fatal("provider cannot verify the redirect signature")
			}
		})
	}
}
