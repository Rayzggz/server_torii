package server

import (
	"fmt"
	"math"
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"
)

type detectorHarness struct {
	t        *testing.T
	rules    *config.RuleSet
	state    *siteState
	marks    *ipExpiry
	evidence *ipExpiry
	engine   *action.ActionRuleEngine
	shared   *dataType.SharedMemory
	now      time.Time
	tick     int
}

// newDetectorHarness uses small thresholds so scenarios stay readable.
func newDetectorHarness(t *testing.T, mutate func(r *dataType.AdaptiveTrafficAnalyzerRule)) *detectorHarness {
	t.Helper()
	rule := &dataType.AdaptiveTrafficAnalyzerRule{
		Enabled: true,
		Tag:     "test",
		URIDetection: dataType.URIDetectionRule{
			MinRequests: 30, MinDistinctIPs: 10,
			Baseline: dataType.BaselineRule{Warmup: 1, MinReferenceRequests: 20},
		},
		IPDetection: dataType.IPDetectionRule{
			Enabled: true,
			Action:  dataType.AnalyzerCaptcha,
		},
	}
	if mutate != nil {
		mutate(rule)
	}
	engine := action.NewActionRuleEngine(time.Minute)
	t.Cleanup(engine.Stop)
	start := time.Unix(1_700_000_000, 0)
	return &detectorHarness{
		t: t,
		rules: &config.RuleSet{
			AdaptiveTrafficAnalyzerRule: rule,
			IPAllowRule:                 &dataType.IPAllowRule{Trie: &dataType.TrieNode{}},
			URLAllowRule:                &dataType.URLAllowRule{List: &dataType.URLRuleList{}},
		},
		state:    newSiteState(start),
		marks:    newIPExpiry(maxMarkedClients),
		evidence: newIPExpiry(maxEvidenceEntries),
		engine:   engine,
		shared:   &dataType.SharedMemory{ActionRuleEngine: engine},
		now:      start,
	}
}

func (h *detectorHarness) run(logs []LogEntry) {
	h.tick++
	h.now = h.now.Add(10 * time.Second)
	(&trafficDetector{}).Analyze(&analysisContext{
		Logs: logs, Rule: h.rules, State: h.state, SharedMem: h.shared,
		Marks: h.marks, Evidence: h.evidence, Now: h.now, Interval: 10 * time.Second,
	})
}

func (h *detectorHarness) ipAction(ip string) action.ActionType {
	return h.engine.Check(ip, "", "/__unused__")
}

// browse is a real browser loading a page and its assets.
func browse(ip, page string) []LogEntry {
	return []LogEntry{
		{IP: ip, URI: page, Status: 200},
		{IP: ip, URI: "/static/app.js", Status: 200},
		{IP: ip, URI: "/static/app.css", Status: 304},
	}
}

func hit(ip, uri string, status int) LogEntry {
	return LogEntry{IP: ip, URI: uri, Status: status}
}

var testPages = []string{"/", "/news", "/about", "/search"}

// humanIP is real user i during the one-minute session that contains tick.
func humanIP(tick, i int) string {
	return fmt.Sprintf("10.0.%d.%d", (tick/6)%250, i)
}

// humanTraffic is 40 real users per minute browsing the site's pages, plus a few
// non-browser clients that make up the normal mix. Odd users never fetch assets
// (served from another domain or cached), so only their browsing pattern shows.
func humanTraffic(tick int) []LogEntry {
	var logs []LogEntry
	for i := 0; i < 40; i++ {
		page := testPages[(i+tick)%len(testPages)]
		if i%2 == 0 {
			logs = append(logs, browse(humanIP(tick, i), page)...)
		} else {
			logs = append(logs, hit(humanIP(tick, i), page, 200))
		}
	}
	for i := 0; i < 4; i++ {
		logs = append(logs, hit(fmt.Sprintf("10.9.0.%d", i), testPages[i], 200))
	}
	return logs
}

// botTraffic is 200 low-rate bots, each hitting /search once every 5 intervals.
func botTraffic(tick int) []LogEntry {
	var logs []LogEntry
	for i := 0; i < 200; i++ {
		if (i+tick)%5 == 0 {
			logs = append(logs, hit(fmt.Sprintf("172.16.%d.%d", i/250, i%250), "/search", 200))
		}
	}
	return logs
}

func TestDetectorSustainedAttack(t *testing.T) {
	h := newDetectorHarness(t, nil)
	control := newDetectorHarness(t, nil) // same real users, no attack
	for i := 0; i < 60; i++ {
		h.run(humanTraffic(h.tick))
		control.run(humanTraffic(control.tick))
	}

	for i := 0; i < 60; i++ {
		control.run(humanTraffic(control.tick))
		logs := append(humanTraffic(h.tick), botTraffic(h.tick)...)
		// A returning visitor whose assets are cached after the first page, one whose
		// browser revalidated a page (304), a searcher with no evidence at all, and a
		// user retrying a challenge on the hot URI (answered 503 by the CAPTCHA page).
		logs = append(logs, hit("10.1.0.5", "/search", 503))
		if i == 0 {
			logs = append(logs, browse("10.1.0.1", "/")...)
			logs = append(logs, hit("10.1.0.3", "/news", 304))
		}
		if i%5 == 0 {
			logs = append(logs, hit("10.1.0.1", "/search", 200), hit("10.1.0.3", "/search", 200))
		}
		if i%15 == 0 {
			logs = append(logs, hit("10.1.0.4", "/search", 200))
		}
		h.run(logs)
	}

	if h.state.mode != modeBaseline {
		t.Fatalf("detection mode %q, want baseline", h.state.mode)
	}
	// Only the extra real visitor may add to the /search baseline, never the bots.
	attacked := h.state.baseline["/search"].at(h.now, 6*time.Hour)
	clean := control.state.baseline["/search"].at(control.now, 6*time.Hour)
	if attacked > clean*1.1 || attacked < clean {
		t.Fatalf("baseline polluted by attack: %.4f vs clean %.4f", attacked, clean)
	}
	for i := 0; i < 200; i++ {
		ip := fmt.Sprintf("172.16.%d.%d", i/250, i%250)
		if got := h.ipAction(ip); got != action.ActionCaptcha {
			t.Fatalf("bot %s: got %v, want CAPTCHA", ip, got)
		}
	}
	last := h.tick - 1
	for _, ip := range []string{humanIP(0, 0), humanIP(0, 1), humanIP(last, 0), humanIP(last, 39),
		"10.1.0.1", "10.1.0.3", "10.1.0.4", "10.1.0.5", "10.9.0.0"} {
		if got := h.ipAction(ip); got != action.ActionNone {
			t.Fatalf("legitimate client %s: got %v", ip, got)
		}
	}
	if got := h.engine.Check("", "", "/search"); got != action.ActionNone {
		t.Fatalf("observe URI action wrote a rule: %v", got)
	}
	if _, ok := h.state.uriRules["/search"]; !ok {
		t.Fatal("/search was not detected as hot")
	}
	if _, ok := h.state.uriRules["/news"]; ok {
		t.Fatal("/news falsely detected as hot")
	}
}

func TestDetectorURIActionAndExemptions(t *testing.T) {
	h := newDetectorHarness(t, func(r *dataType.AdaptiveTrafficAnalyzerRule) {
		r.URIDetection.Action = dataType.AnalyzerCaptcha
	})
	h.rules.URLAllowRule.List.Append(&dataType.URLRule{Pattern: "/api/feed"})
	_, allowNet, _ := net.ParseCIDR("192.168.5.0/24")
	h.rules.IPAllowRule.Trie.Insert(allowNet)
	h.marks.set("10.2.0.1", h.now.Add(time.Hour)) // verified crawler or CAPTCHA pass

	for i := 0; i < 60; i++ {
		h.run(humanTraffic(h.tick))
	}
	for i := 0; i < 30; i++ {
		logs := append(humanTraffic(h.tick), botTraffic(h.tick)...)
		for j := 0; j < 3; j++ {
			logs = append(logs,
				hit("192.168.5.7", "/search", 200),
				hit("10.2.0.1", "/search", 200))
		}
		for j := 0; j < 50; j++ {
			logs = append(logs, hit(fmt.Sprintf("10.4.0.%d", j), "/api/feed", 200))
		}
		h.run(logs)
	}
	if got := h.engine.Check("", "", "/search"); got != action.ActionCaptcha {
		t.Fatalf("hot URI: got %v, want CAPTCHA", got)
	}
	if got := h.engine.Check("", "", "/api/feed"); got != action.ActionNone {
		t.Fatalf("allowlisted URI got %v", got)
	}
	for _, ip := range []string{"192.168.5.7", "10.2.0.1", "10.4.0.1"} {
		if got := h.ipAction(ip); got != action.ActionNone {
			t.Fatalf("exempt client %s got %v", ip, got)
		}
	}
}

func TestDetectorWarmupFallback(t *testing.T) {
	h := newDetectorHarness(t, func(r *dataType.AdaptiveTrafficAnalyzerRule) {
		r.URIDetection.Baseline.Warmup = 3600
		r.URIDetection.FallbackShare = 0.7
	})
	// Paused for one window while browser evidence accumulates.
	for i := 0; i < 29; i++ {
		h.run(append(humanTraffic(h.tick), botTraffic(h.tick)...))
	}
	if h.state.mode != modePaused || len(h.state.uriRules) != 0 {
		t.Fatalf("mode %q with %d URI rules before evidence warmed up", h.state.mode, len(h.state.uriRules))
	}
	for i := 0; i < 31; i++ {
		h.run(append(humanTraffic(h.tick), botTraffic(h.tick)...))
	}
	if h.state.mode != modeFallback {
		t.Fatalf("mode %q, want fallback", h.state.mode)
	}
	if _, ok := h.state.uriRules["/search"]; !ok {
		t.Fatal("/search not detected by share before the baseline was ready")
	}
	if len(h.state.uriRules) != 1 {
		t.Fatalf("unexpected hot URIs: %v", h.state.uriRules)
	}
}

func TestDetectorHotURIMustBeSustained(t *testing.T) {
	// Production-sized min_requests so each interval must carry a real share of the traffic.
	h := newDetectorHarness(t, func(r *dataType.AdaptiveTrafficAnalyzerRule) { r.URIDetection.MinRequests = 300 })
	for i := 0; i < 60; i++ {
		h.run(humanTraffic(h.tick))
	}
	burst := func() []LogEntry {
		logs := humanTraffic(h.tick)
		for i := 0; i < 200; i++ {
			logs = append(logs, hit(fmt.Sprintf("172.16.0.%d", i), "/search", 200))
		}
		return logs
	}
	for i := 0; i < 3; i++ {
		h.run(burst())
	}
	for i := 0; i < 30; i++ {
		h.run(humanTraffic(h.tick))
	}
	if _, ok := h.state.uriRules["/search"]; ok {
		t.Fatal("a 30 second burst was treated as a hot URI")
	}
	for i := 0; i < 6; i++ {
		h.run(burst())
	}
	if _, ok := h.state.uriRules["/search"]; !ok {
		t.Fatal("a sustained attack was not treated as a hot URI")
	}
}

func TestDetectorIPSignals(t *testing.T) {
	h := newDetectorHarness(t, nil)
	var logs []LogEntry
	for i := 0; i < 40; i++ {
		logs = append(logs, hit("1.1.1.1", fmt.Sprintf("/wp-%d.php", i), 404)) // scanner
	}
	for i := 0; i < 50; i++ {
		status := []int{304, 302, 206, 204, 301}[i%5]
		logs = append(logs, hit("2.2.2.2", testPages[i%len(testPages)], status)) // normal non-200 traffic
	}
	logs = append(logs, hit("3.3.3.3", "/", 404)) // a single miss
	for i := 0; i < 60; i++ {
		logs = append(logs, hit("4.4.4.4", "/search", 503)) // backend outage
	}
	for i := 0; i < 40; i++ {
		logs = append(logs, hit("5.5.5.5", "/login", 401)) // high failure rate
	}
	h.run(logs)

	want := map[string]action.ActionType{
		"1.1.1.1": action.ActionCaptcha,
		"2.2.2.2": action.ActionNone,
		"3.3.3.3": action.ActionNone,
		"4.4.4.4": action.ActionNone,
		"5.5.5.5": action.ActionCaptcha,
	}
	for ip, w := range want {
		if got := h.ipAction(ip); got != w {
			t.Errorf("%s: got %v, want %v", ip, got, w)
		}
	}
	if got := h.engine.Check("", "", "/search"); got != action.ActionNone {
		t.Errorf("5xx outage produced URI rule %v", got)
	}
}

func TestDetectorActions(t *testing.T) {
	scanner := func() []LogEntry {
		var logs []LogEntry
		for i := 0; i < 40; i++ {
			logs = append(logs, hit("1.1.1.1", fmt.Sprintf("/x%d", i), 404))
		}
		return logs
	}
	for _, tc := range []struct {
		act  dataType.AnalyzerAction
		want action.ActionType
	}{
		{dataType.AnalyzerObserve, action.ActionNone},
		{dataType.AnalyzerCaptcha, action.ActionCaptcha},
		{dataType.AnalyzerBlock, action.ActionBlock},
	} {
		t.Run(string(tc.act), func(t *testing.T) {
			h := newDetectorHarness(t, func(r *dataType.AdaptiveTrafficAnalyzerRule) { r.IPDetection.Action = tc.act })
			h.run(scanner())
			if got := h.ipAction("1.1.1.1"); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			off := h.state.offenders["1.1.1.1"]
			if off == nil || len(off.times) != 1 {
				t.Fatal("offense not recorded")
			}
			// Observe mode must not re-flag the IP every interval.
			h.run(scanner())
			if len(off.times) != 1 {
				t.Fatal("IP re-flagged while its previous action was still active")
			}
		})
	}
}

func TestDetectorEscalation(t *testing.T) {
	h := newDetectorHarness(t, func(r *dataType.AdaptiveTrafficAnalyzerRule) {
		r.IPDetection.Action = dataType.AnalyzerObserve
		r.IPDetection.BlockDuration = 60
		r.IPDetection.MaxBlockDuration = 200
	})
	var durations []time.Duration
	for len(durations) < 4 {
		var logs []LogEntry
		for i := 0; i < 40; i++ {
			logs = append(logs, hit("1.1.1.1", fmt.Sprintf("/x%d", i), 404))
		}
		h.run(logs)
		if off := h.state.offenders["1.1.1.1"]; off != nil && off.times[len(off.times)-1].Equal(h.now) {
			durations = append(durations, off.until.Sub(h.now))
		}
	}
	want := []time.Duration{60 * time.Second, 120 * time.Second, 200 * time.Second, 200 * time.Second}
	for i := range want {
		if durations[i] != want[i] {
			t.Fatalf("durations %v, want %v", durations, want)
		}
	}
}

func TestEnforcerBroadcastLimit(t *testing.T) {
	engine := action.NewActionRuleEngine(time.Minute)
	defer engine.Stop()
	gossip := make(chan dataType.GossipMessage, 10)
	e := newEnforcer(&dataType.SharedMemory{ActionRuleEngine: engine, GossipChan: gossip}, 2)
	for i := 0; i < 5; i++ {
		e.apply("IP", fmt.Sprintf("9.9.9.%d", i), dataType.AnalyzerBlock, time.Minute, true)
	}
	e.apply("URI", "/search", dataType.AnalyzerCaptchaUnverified, time.Minute, false)
	if got := engine.Check("", "", "/search"); got != action.ActionCaptchaUnverified {
		t.Fatalf("URI rule %v, want CAPTCHA_UNVERIFIED", got)
	}
	if len(gossip) != 3 || e.suppressed != 3 {
		t.Fatalf("broadcasts %d, suppressed %d; want 3 and 3", len(gossip), e.suppressed)
	}
	for i := 0; i < 5; i++ {
		if !engine.HasIPRule(fmt.Sprintf("9.9.9.%d", i)) {
			t.Fatal("suppressed broadcast must still apply locally")
		}
	}
}

func TestAnalyzerStatsHelpers(t *testing.T) {
	if got := wilsonLower(1, 1); got > 0.3 {
		t.Errorf("wilsonLower(1,1) = %.3f, want small", got)
	}
	if got := wilsonLower(50, 60); got < 0.7 || got > 0.75 {
		t.Errorf("wilsonLower(50,60) = %.3f", got)
	}
	if got := wilsonLower(0, 0); got != 0 {
		t.Errorf("wilsonLower(0,0) = %v", got)
	}
	if got := weightedMedian([]float64{100, 1, 2}, []float64{1, 11, 10}); got != 1 {
		t.Errorf("weightedMedian = %v, want 1", got)
	}

	var e ewma
	start := time.Unix(0, 0)
	e.updated = start
	for i := 1; i <= 6000; i++ {
		e.observe(start.Add(time.Duration(i)*10*time.Second), 3, 10*time.Second, time.Hour)
	}
	end := start.Add(6000 * 10 * time.Second)
	if got := e.at(end, time.Hour); math.Abs(got-3) > 0.05 {
		t.Errorf("ewma converged to %.3f, want 3", got)
	}
	if got := e.at(end.Add(time.Hour), time.Hour); math.Abs(got-1.5) > 0.05 {
		t.Errorf("ewma after one idle half-life = %.3f, want 1.5", got)
	}

	s := newSiteState(start)
	for i := 1; i <= 5; i++ {
		s.push(&bucket{at: start.Add(time.Duration(i) * 10 * time.Second)}, 30*time.Second, 3)
	}
	if len(s.buckets) != 3 || !s.buckets[0].at.Equal(start.Add(30*time.Second)) {
		t.Errorf("ring kept %d buckets starting at %v", len(s.buckets), s.buckets[0].at)
	}
	s.push(&bucket{at: start.Add(500 * time.Second)}, 30*time.Second, 3)
	if len(s.buckets) != 1 {
		t.Errorf("stale buckets survived a gap: %d", len(s.buckets))
	}

	if got := escalate(time.Minute, time.Hour, 0); got != time.Minute {
		t.Errorf("escalate(0) = %v", got)
	}
	if got := escalate(time.Minute, time.Hour, 20); got != time.Hour {
		t.Errorf("escalate(20) = %v", got)
	}
}

func TestNormalizeAnalyzerRule(t *testing.T) {
	r := &dataType.AdaptiveTrafficAnalyzerRule{
		BrowserEvidence: dataType.BrowserEvidenceRule{AssetExtensions: []string{"JS", ".css"}},
		IPDetection:     dataType.IPDetectionRule{Action: "Bogus"},
		URIDetection:    dataType.URIDetectionRule{Action: "Captcha_Unverified"},
	}
	config.NormalizeAdaptiveTrafficAnalyzerRule(r)
	if r.IPDetection.Action != dataType.AnalyzerObserve || r.URIDetection.Action != dataType.AnalyzerCaptchaUnverified {
		t.Errorf("actions: %q %q", r.IPDetection.Action, r.URIDetection.Action)
	}
	if len(r.BrowserEvidence.AssetExtensions) != 2 || r.BrowserEvidence.AssetExtensions[0] != ".js" {
		t.Errorf("asset extensions: %v", r.BrowserEvidence.AssetExtensions)
	}
	if r.AnalysisInterval != config.DefaultATAAnalysisInterval || r.IPDetection.ScoreThreshold != config.DefaultATAScoreThreshold {
		t.Error("defaults not applied")
	}
}

func TestHotHitThresholdsFollowRealUsers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	rule := dataType.AdaptiveTrafficAnalyzerRule{IPDetection: dataType.IPDetectionRule{HotURIMinHits: 3}}
	config.NormalizeAdaptiveTrafficAnalyzerRule(&rule)
	det := &detection{ctx: &analysisContext{Evidence: newIPExpiry(100)}, rule: rule, state: newSiteState(now), now: now}
	win := make(map[string]*ipWindow)
	for i := 1; i <= 30; i++ {
		ip := fmt.Sprintf("10.0.0.%d", i)
		det.ctx.Evidence.set(ip, now.Add(time.Hour))
		// Challenged requests (all > served) do not count toward the threshold.
		win[ip] = &ipWindow{pages: map[string]pageHits{"/busy": {all: int64(i) + 100, served: int64(i)}}}
		if i <= 10 {
			win[ip].pages["/quiet"] = pageHits{50, 50} // too few samples to trust
		}
	}
	win["172.16.0.1"] = &ipWindow{pages: map[string]pageHits{"/busy": {1000, 1000}}} // non-browser hits are ignored
	got := det.hotHitThresholds(win, map[string]bool{"/busy": true, "/quiet": true, "/none": true})
	want := map[string]int64{"/busy": 30, "/quiet": 3, "/none": 3}
	for u, w := range want {
		if got[u] != w {
			t.Errorf("%s threshold = %d, want %d", u, got[u], w)
		}
	}
}

func TestRecordEvidenceAtIngest(t *testing.T) {
	prev := config.Manager
	config.Manager = &config.ConfigManager{}
	t.Cleanup(func() { config.Manager = prev })
	config.Manager.Set(&config.SiteConfigSnapshot{SiteRules: map[string]*config.RuleSet{
		"site": {AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{Enabled: true, Tag: "nginx"}},
	}})
	a := NewAdaptiveTrafficAnalyzer(nil)
	for _, tc := range []struct {
		entry LogEntry
		want  bool
	}{
		{LogEntry{Tag: "nginx", IP: "1.0.0.1", URI: "/js/app.js?_v=1", Status: 200}, true},
		{LogEntry{Tag: "nginx", IP: "1.0.0.2", URI: "/threads/1/", Status: 304}, true},
		{LogEntry{Tag: "nginx", IP: "1.0.0.3", URI: "/js/missing.js", Status: 404}, false},
		{LogEntry{Tag: "nginx", IP: "1.0.0.4", URI: "/members/1/", Status: 200}, false},
		{LogEntry{Tag: "other", IP: "1.0.0.5", URI: "/js/app.js", Status: 200}, false},
	} {
		a.AddLog(tc.entry)
		if got := a.HasBrowserEvidence(tc.entry.IP); got != tc.want {
			t.Errorf("%+v: evidence %v, want %v", tc.entry, got, tc.want)
		}
	}
}

func TestGossipAcceptsCaptchaUnverified(t *testing.T) {
	payload := dataType.ActionRulePayload{RuleType: "URI", Value: "/members/:id", Action: string(action.ActionCaptchaUnverified),
		ExpiresAt: time.Now().Add(time.Minute).Unix()}
	if err := validateActionRule(payload, time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestDistinctPagesUseRawPaths(t *testing.T) {
	h := newDetectorHarness(t, nil)
	// A reader paging through one thread: grouped as one URI, but three distinct pages.
	h.run([]LogEntry{hit("9.0.0.1", "/threads/7/page-1", 200), hit("9.0.0.1", "/threads/7/page-2", 200), hit("9.0.0.1", "/threads/7/page-3", 200)})
	// A bot following a redirect: the 301 is not a page it was served.
	h.run([]LogEntry{hit("9.0.0.2", "/threads/7/post-1", 301), hit("9.0.0.2", "/threads/7/page-9", 200), hit("9.0.0.2", "/members/1/", 301)})
	if !h.evidence.active("9.0.0.1", h.now) {
		t.Error("reader paging through a thread has no browser evidence")
	}
	if h.evidence.active("9.0.0.2", h.now) {
		t.Error("redirects counted as browsing")
	}
}
