package analyzer

import (
	"fmt"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"testing"
	"time"
)

func decided(ip, uri string, status int, decision string) LogEntry {
	return LogEntry{IP: ip, URI: uri, Status: status, Decision: decision}
}

// A response Torii produced says what Torii decided, not how the site reacted. Counting it as a
// failure would let a block feed the score that caused it.
func TestDetectorIgnoresToriiResponsesAsFailures(t *testing.T) {
	h := newDetectorHarness(t, nil)
	var logs []LogEntry
	for i := 0; i < 40; i++ {
		// Rejected by Torii on every request: no failure of the client.
		logs = append(logs, decided("1.1.1.1", "/login", 403, "block"))
		logs = append(logs, decided("2.2.2.2", "/login", 429, "rate_limit"))
		logs = append(logs, decided("3.3.3.3", fmt.Sprintf("/p%d", i), 403, "block")) // nor a scan
		// The site itself rejected these, whether or not Torii checked the request first.
		logs = append(logs, decided("4.4.4.4", "/login", 401, "pass"))
		logs = append(logs, decided("5.5.5.5", "/login", 401, ""))
		// Torii's answers do not dilute what the site answered either.
		logs = append(logs, decided("6.6.6.6", "/login", 401, "pass"), decided("6.6.6.6", "/x", 503, "captcha"), decided("6.6.6.6", "/x", 503, "captcha"))
	}
	h.run(logs)

	for ip, want := range map[string]action.ActionType{
		"1.1.1.1": action.ActionNone,
		"2.2.2.2": action.ActionNone,
		"3.3.3.3": action.ActionNone,
		"4.4.4.4": action.ActionCaptcha,
		"5.5.5.5": action.ActionCaptcha,
		"6.6.6.6": action.ActionCaptcha,
	} {
		if got := h.ipAction(ip); got != want {
			t.Errorf("%s: got %v, want %v", ip, got, want)
		}
	}
}

// Torii's own redirect or challenge on an asset URI is no sign that the client is a browser.
func TestToriiResponsesAreNoBrowserEvidence(t *testing.T) {
	h := newDetectorHarness(t, nil)
	h.run([]LogEntry{
		decided("1.1.1.1", "/static/app.js", 302, "external"),
		decided("2.2.2.2", "/static/app.js", 200, "pass"),
		decided("3.3.3.3", "/static/app.js", 200, ""),
	})
	for ip, want := range map[string]bool{"1.1.1.1": false, "2.2.2.2": true, "3.3.3.3": true} {
		if got := h.evidence.active(ip, h.now); got != want {
			t.Errorf("%s: evidence %v, want %v", ip, got, want)
		}
	}

	configs := config.NewManager()
	configs.Set(&config.SiteConfigSnapshot{SiteRules: map[string]*config.RuleSet{
		"site": {ID: "site", AdaptiveTrafficAnalyzerRule: &config.AdaptiveTrafficAnalyzerRule{Enabled: true}},
	}})
	a := NewAdaptiveTrafficAnalyzer(nil, configs)
	a.AddLog(LogEntry{Site: "site", IP: "1.1.1.1", URI: "/static/app.js", Status: 302, Decision: "external"})
	if a.HasBrowserEvidence("site", "1.1.1.1") {
		t.Error("a redirect by Torii was recorded as browser evidence on arrival")
	}
}

// Hot URI detection must keep seeing an attack that Torii is already answering, or the rule
// would lapse while the attack goes on.
func TestChallengedRequestsStillCountTowardsHotURIs(t *testing.T) {
	h := newDetectorHarness(t, nil)
	var logs []LogEntry
	for i := 0; i < 5; i++ {
		logs = append(logs, decided("1.1.1.1", "/search", 503, "captcha"))
	}
	h.run(logs)
	ib := h.state.buckets[0].ips["1.1.1.1"]
	if ib.pageTotal != 5 || ib.pages["/search"].all != 5 || ib.pages["/search"].served != 0 {
		t.Fatalf("page hits = %d, %+v; want 5 hits, none served", ib.pageTotal, ib.pages["/search"])
	}
	if ib.total != 0 || ib.clientErr != 0 {
		t.Fatalf("total = %d, clientErr = %d; want none answered by the site", ib.total, ib.clientErr)
	}
}

// What a client did or proved on one site says nothing about its traffic to another.
func TestEvidenceAndMarksArePerSite(t *testing.T) {
	a, _, start := scheduleFixture(t, map[string]*config.RuleSet{"shop": scheduledRule(10), "blog": scheduledRule(10)})

	a.AddLog(LogEntry{Site: "shop", IP: "1.1.1.1", URI: "/static/app.js", Status: 200})
	if !a.HasBrowserEvidence("shop", "1.1.1.1") || a.HasBrowserEvidence("blog", "1.1.1.1") {
		t.Fatal("browser evidence is not limited to the site it was seen on")
	}
	if a.HasBrowserEvidence("nowhere", "1.1.1.1") {
		t.Fatal("evidence on an unknown site")
	}

	a.MarkVerified("shop", "2.2.2.2", time.Hour)
	a.MarkNeutral("blog", "3.3.3.3", time.Hour)
	now := time.Now()
	for _, tt := range []struct {
		site, ip string
		want     bool
	}{
		{"shop", "2.2.2.2", true}, {"blog", "2.2.2.2", false},
		{"blog", "3.3.3.3", true}, {"shop", "3.3.3.3", false},
	} {
		if got := a.Marked(tt.site, tt.ip, now); got != tt.want {
			t.Errorf("Marked(%s, %s) = %v, want %v", tt.site, tt.ip, got, tt.want)
		}
	}

	// Each site's detector is handed that site's sets only.
	seen := map[string]bool{}
	a.analyzers = []Analyzer{analyzerFunc(func(ctx *analysisContext) {
		site := ctx.Rule.ID
		seen[site] = true
		if got := ctx.Evidence.active("1.1.1.1", now); got != (site == "shop") {
			t.Errorf("%s: detector sees evidence %v", site, got)
		}
		if got := ctx.Marks.active("2.2.2.2", now); got != (site == "shop") {
			t.Errorf("%s: detector sees mark %v", site, got)
		}
	})}
	a.AddLog(LogEntry{Site: "blog", IP: "9.9.9.9", URI: "/", Status: 200})
	a.processBatchAt(start.Add(10 * time.Second))
	if !seen["shop"] || !seen["blog"] {
		t.Fatalf("analyzed %v, want both sites", seen)
	}
}

func TestSiteExpirySweep(t *testing.T) {
	s := newSiteExpiry(2)
	now := time.Unix(1000, 0)
	s.site("a").set("1.1.1.1", now.Add(time.Minute))
	s.site("b").set("1.1.1.1", now.Add(time.Hour))
	// Each site has its own limit.
	s.site("a").set("2.2.2.2", now.Add(time.Minute))
	s.site("a").set("3.3.3.3", now.Add(time.Minute))
	s.site("b").set("2.2.2.2", now.Add(time.Hour))
	if s.existing("a").active("3.3.3.3", now) || !s.existing("b").active("2.2.2.2", now) {
		t.Fatal("the limit is not applied per site")
	}

	s.sweep(now.Add(2 * time.Minute))
	if s.existing("a") != nil {
		t.Fatal("a site without entries was kept")
	}
	if !s.existing("b").active("1.1.1.1", now.Add(2*time.Minute)) {
		t.Fatal("live entries were swept")
	}
	if s.existing("missing").active("1.1.1.1", now) {
		t.Fatal("unknown site reported an entry")
	}
}
