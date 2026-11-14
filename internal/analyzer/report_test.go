package analyzer

import (
	"net"
	"path/filepath"
	"server_torii/internal/config"
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

	stats := waitStats(t, l, func(s ReportStats) bool { return s.Received > 0 && s.Accepted+s.Dropped == s.Received })
	if stats.Accepted == 0 || stats.Malformed != 0 || stats.Unknown != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if got := uint64(bufferedSites(a)["shop"]); got != stats.Accepted {
		t.Fatalf("buffered %d entries, accepted %d", got, stats.Accepted)
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
