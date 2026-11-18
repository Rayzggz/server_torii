package analyzer

import (
	"net"
	"path/filepath"
	"runtime"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseReport(t *testing.T) {
	entry, err := parseReport([]byte(`{"v":1,"ts":1700000000123,"site":"shop","ip":"203.0.113.5","host":"shop.example",` +
		`"method":"GET","uri":"/a b?x=\"1\"","status":404,"decision":"pass","reason":"","ua":"Mozilla/5.0 (X11)",` +
		`"referer":"https://shop.example/","proto":"HTTP/2.0","conn_reqs":7,"fetch":"document/navigate/same-origin",` +
		`"lang":true,"ctype":"text/html","rt":12,"urt":9,"ustatus":404,"cache":"MISS","bytes":512,"req_len":321}`))
	if err != nil {
		t.Fatal(err)
	}
	want := LogEntry{
		Site: "shop", IP: "203.0.113.5", URI: `/a b?x="1"`, Status: 404, Timestamp: 1700000000123,
		Host: "shop.example", Method: "GET", Decision: "pass",
		UserAgent: "Mozilla/5.0 (X11)", Referer: "https://shop.example/", Proto: "HTTP/2.0", ConnRequests: 7,
		Fetch: "document/navigate/same-origin", HasLanguage: true, ContentType: "text/html",
		RequestTime: 12 * time.Millisecond, UpstreamTime: 9 * time.Millisecond, UpstreamStatus: 404,
		Cache: "MISS", Bytes: 512, RequestLength: 321,
	}
	if entry != want {
		t.Fatalf("got  %+v\nwant %+v", entry, want)
	}

	// Only the essentials are required, and a syslog header in front of the object is ignored.
	entry, err = parseReport([]byte(`<190>Jan  1 00:00:00 torii: {"v":1,"ip":"203.0.113.5","status":200}`))
	if err != nil || entry.IP != "203.0.113.5" || entry.Status != 200 || entry.Site != "" {
		t.Fatalf("minimal report: %+v, %v", entry, err)
	}

	for name, data := range map[string]string{
		"not json":        `203.0.113.5 - - [01/Jan/2026] "GET / HTTP/1.1" 200 0`,
		"truncated":       `{"v":1,"ip":"203.0.113.5","sta`,
		"other version":   `{"v":2,"ip":"203.0.113.5","status":200}`,
		"no version":      `{"ip":"203.0.113.5","status":200}`,
		"no address":      `{"v":1,"status":200}`,
		"status range":    `{"v":1,"ip":"203.0.113.5","status":1000}`,
		"site characters": `{"v":1,"site":"../shop","ip":"203.0.113.5","status":200}`,
		"wrong type":      `{"v":1,"ip":"203.0.113.5","status":"200"}`,
	} {
		if _, err := parseReport([]byte(data)); err == nil {
			t.Errorf("%s: accepted %s", name, data)
		}
	}
}

func reportConfigs() *config.Manager {
	enabled := func(id string, on bool) *config.RuleSet {
		return &config.RuleSet{ID: id, AdaptiveTrafficAnalyzerRule: &config.AdaptiveTrafficAnalyzerRule{Enabled: on}}
	}
	configs := config.NewManager()
	configs.Set(&config.SiteConfigSnapshot{
		SiteRules:   map[string]*config.RuleSet{"shop": enabled("shop", true), "blog": enabled("blog", true), "quiet": enabled("quiet", false)},
		DefaultSite: "blog",
	})
	return configs
}

// A client on an allow list is exempt by its own address. Its key is the network it is in,
// which a list entry for one address does not hold.
func TestSubmitLeavesOutAllowListedClients(t *testing.T) {
	configs := reportConfigs()
	configs.Get().Site("shop").Lists = config.NewListSet(
		config.MustNewList("ip_allow", config.ListIP, action.ActionAllow, "2001:db8:1:2:aaaa::5", "192.0.2.7"),
	)
	a := NewAdaptiveTrafficAnalyzer(nil, configs)
	for _, ip := range []string{"2001:db8:1:2:aaaa::5", "192.0.2.7", "2001:db8:1:2:aaaa::6", "192.0.2.8"} {
		if !a.submit(LogEntry{Site: "shop", IP: ip, URI: "/", Status: 200}) {
			t.Fatalf("report of %s refused", ip)
		}
	}
	var kept []string
	for _, entry := range a.buffer.entries {
		kept = append(kept, entry.IP)
	}
	// The neighbour in the same /64 is analyzed, under the key of the network.
	if want := []string{"2001:db8:1:2::", "192.0.2.8"}; !slices.Equal(kept, want) {
		t.Fatalf("analyzed clients = %v, want %v", kept, want)
	}
}

func bufferedSites(a *AdaptiveTrafficAnalyzer) map[string]int {
	a.buffer.mu.Lock()
	defer a.buffer.mu.Unlock()
	sites := make(map[string]int)
	for _, entry := range a.buffer.entries {
		sites[entry.Site]++
	}
	return sites
}

func waitStats(t *testing.T, l *ReportListener, done func(ReportStats) bool) ReportStats {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		stats := l.Stats()
		if done(stats) {
			return stats
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out; stats %+v", stats)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A report belongs to the site it names, to the default site when it names none, and to no site
// when the one it names does not exist or is not analyzed.
func TestReportListenerRoutesBySite(t *testing.T) {
	a := NewAdaptiveTrafficAnalyzer(nil, reportConfigs())
	l := NewReportListener([]string{"127.0.0.1:0"}, 0o660, a)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	client, err := net.Dial("udp", l.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for _, datagram := range []string{
		`{"v":1,"site":"shop","ip":"203.0.113.1","uri":"/","status":200}`,
		`{"v":1,"site":"shop","ip":"203.0.113.2","uri":"/","status":200}`,
		`{"v":1,"ip":"203.0.113.3","uri":"/","status":200}`,
		`{"v":1,"site":"quiet","ip":"203.0.113.4","uri":"/","status":200}`,
		`{"v":1,"site":"nope","ip":"203.0.113.5","uri":"/","status":200}`,
		`not a report`,
	} {
		if _, err := client.Write([]byte(datagram)); err != nil {
			t.Fatal(err)
		}
	}

	stats := waitStats(t, l, func(s ReportStats) bool { return s.Accepted+s.Malformed+s.Unknown == 6 })
	if want := (ReportStats{Received: 6, Accepted: 3, Malformed: 1, Unknown: 2}); stats != want {
		t.Fatalf("stats = %+v, want %+v", stats, want)
	}
	sites := bufferedSites(a)
	if sites["shop"] != 2 || sites["blog"] != 1 || len(sites) != 2 {
		t.Fatalf("buffered by site: %v", sites)
	}
}

func TestReportListenerUnixSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log.sock")
	a := NewAdaptiveTrafficAnalyzer(nil, reportConfigs())
	l := NewReportListener([]string{config.UnixListenPrefix + path, "127.0.0.1:0"}, 0o660, a)
	if err := l.Start(); err != nil {
		// Windows has no Unix datagram sockets.
		if strings.Contains(err.Error(), "unixgram") || strings.Contains(err.Error(), "not supported") {
			t.Skipf("unix datagram sockets unavailable: %v", err)
		}
		t.Fatal(err)
	}

	client, err := net.Dial("unixgram", path)
	if err != nil {
		l.Stop()
		t.Fatal(err)
	}
	if _, err := client.Write([]byte(`{"v":1,"site":"shop","ip":"203.0.113.1","uri":"/","status":200}`)); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	waitStats(t, l, func(s ReportStats) bool { return s.Accepted == 1 })

	// A second listener must not take over a socket that is in use.
	if err := NewReportListener([]string{config.UnixListenPrefix + path}, 0o660, a).Start(); err == nil {
		t.Fatal("listened on a socket that is in use")
	}

	l.Stop()
	if _, err := net.Dial("unixgram", path); err == nil {
		t.Fatal("socket still accepts datagrams after Stop")
	}
}

// More datagrams than the queue holds must not block the reader or crash; they are counted.
func TestReportListenerUnderLoad(t *testing.T) {
	a := NewAdaptiveTrafficAnalyzer(nil, reportConfigs())
	l := NewReportListener([]string{"127.0.0.1:0"}, 0o660, a)
	if err := l.Start(); err != nil {
		t.Fatal(err)
	}
	defer l.Stop()

	client, err := net.Dial("udp", l.conns[0].LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	message := []byte(`{"v":1,"site":"shop","ip":"127.0.0.1","uri":"/","status":200,"ua":"Mozilla/5.0"}`)
	for i := 0; i < 15000; i++ {
		if _, err := client.Write(message); err != nil {
			t.Fatalf("write: %v", err)
		}
	}

	// A report is buffered a moment before it is counted, so the two are compared once they agree
	// and not at the first instant the counters add up.
	stats := waitStats(t, l, func(s ReportStats) bool {
		return s.Received > 0 && s.Accepted+s.Dropped == s.Received && uint64(bufferedSites(a)["shop"]) == s.Accepted
	})
	if stats.Accepted == 0 || stats.Malformed != 0 || stats.Unknown != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestIsAssetContentType(t *testing.T) {
	for contentType, want := range map[string]bool{
		"image/png":                true,
		"IMAGE/SVG+XML":            true,
		"font/woff2":               true,
		"text/css; charset=utf-8":  true,
		"application/javascript":   true,
		"text/html; charset=utf-8": false,
		"application/json":         false,
		"application/octet-stream": false,
		"":                         false,
	} {
		if got := isAssetContentType(contentType); got != want {
			t.Errorf("isAssetContentType(%q) = %v, want %v", contentType, got, want)
		}
	}
}

// A flood of reports is not held in memory for a whole interval: what does not fit is counted
// and left out, and the analysis runs on what was kept.
func TestAnalyzerKeepsALimitedNumberOfReports(t *testing.T) {
	a := NewAdaptiveTrafficAnalyzer(nil, reportConfigs())
	a.reportsPerInterval = 100
	a.buffer.limit = 250

	entry := LogEntry{
		Site: "shop", IP: "203.0.113.9", URI: "/", Status: 200, ContentType: "text/html",
		UserAgent: strings.Repeat("u", 512), Referer: strings.Repeat("r", 512), Host: "shop.example",
	}
	for i := 0; i < 300; i++ {
		a.AddLog(entry)
	}
	if got := a.Discarded(); got != 50 {
		t.Fatalf("discarded at the buffer = %d, want 50", got)
	}
	// Nothing the analysis does not read is kept.
	if kept := a.buffer.entries[0]; kept.UserAgent != "" || kept.Referer != "" || kept.Host != "" ||
		kept.IP != entry.IP || kept.URI != entry.URI || kept.Status != 200 || kept.ContentType != "text/html" {
		t.Fatalf("kept entry = %+v", kept)
	}

	a.processBatchAt(time.Now())
	if got := len(a.windows["shop"].logs); got != 100 {
		t.Fatalf("reports kept for the interval = %d, want the limit of 100", got)
	}
	if got := a.Discarded(); got != 50+150 {
		t.Fatalf("discarded = %d, want 200", got)
	}
}

// TestAnalyzerMemoryUnderAFlood feeds an interval's worth of flood, every report as large as a
// report can be, and measures what the analyzer holds of it.
func TestAnalyzerMemoryUnderAFlood(t *testing.T) {
	if testing.Short() {
		t.Skip("feeds two million reports")
	}
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	a := NewAdaptiveTrafficAnalyzer(nil, reportConfigs())
	ua, referer := strings.Repeat("u", 512), strings.Repeat("r", 512)
	now := time.Now()
	a.processBatchAt(now) // opens the interval of the site

	before := heap()
	const reports = 2_000_000
	var raw uint64
	for i := 0; i < reports; i++ {
		// Every report has strings of its own, as reports read from the network do.
		uri := "/search?q=" + strconv.Itoa(i) + strings.Repeat("x", 200)
		entry := LogEntry{
			Site: "shop", IP: "203.0.113." + strconv.Itoa(i%250), URI: uri, Status: 200, ContentType: "text/html",
			UserAgent: ua + strconv.Itoa(i), Referer: referer + strconv.Itoa(i), Host: "shop.example", Method: "GET",
		}
		raw += uint64(len(entry.URI) + len(entry.UserAgent) + len(entry.Referer) + 200)
		a.AddLog(entry)
		if i%100_000 == 99_999 {
			a.processBatchAt(now) // the tick of every second, within the interval
		}
	}
	held := heap() - before
	runtime.KeepAlive(a)
	kept := len(a.windows["shop"].logs)
	t.Logf("%d reports, about %d MB as received: the analyzer holds %d of them in %d MB and discarded %d",
		reports, raw>>20, kept, held>>20, a.Discarded())
	if kept != maxReportsPerInterval || a.Discarded() != reports-maxReportsPerInterval {
		t.Fatalf("kept %d, discarded %d", kept, a.Discarded())
	}
	if held > raw/10 {
		t.Fatalf("the analyzer holds %d MB of a %d MB flood", held>>20, raw>>20)
	}
}
