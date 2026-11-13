package server

import (
	"net"
	"net/http"
	"net/http/httptest"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/state"
	"strings"
	"testing"
	"time"
)

// Published crawler addresses that forward- and reverse-resolve to their operator.
// Baidu and Sogou are left out: their crawler hostnames do not reliably resolve forward.
var liveCrawlers = []struct {
	name string
	ip   string
	ua   string
}{
	{"Googlebot", "66.249.66.1", "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"},
	{"Bingbot", "157.55.39.1", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"},
	{"Applebot", "17.58.98.1", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"},
	{"YandexBot", "5.255.253.1", "Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots)"},
}

// requireCrawlerDNS skips, rather than fails, when this machine cannot verify the address itself.
func requireCrawlerDNS(t *testing.T, ip string) {
	t.Helper()
	if testing.Short() {
		t.Skip("live DNS test skipped in -short mode")
	}
	names, err := net.LookupAddr(ip)
	if err != nil {
		t.Skipf("DEPENDENCY: reverse DNS for %s unavailable: %v", ip, err)
	}
	for _, name := range names {
		addrs, _ := net.LookupIP(name)
		for _, a := range addrs {
			if a.String() == ip {
				return
			}
		}
	}
	t.Skipf("DEPENDENCY: %s %v does not forward-resolve back from this network", ip, names)
}

func verifyBotRuleSet() *config.RuleSet {
	rs := featureControlRuleSet()
	rs.CountryRule.Enabled = false
	rs.VerifyBotRule = &dataType.VerifyBotRule{
		Enabled:         true,
		VerifyGoogleBot: true,
		VerifyBingBot:   true,
		VerifyBaiduBot:  true,
		VerifyYandexBot: true,
		VerifySogouBot:  true,
		VerifyAppleBot:  true,
	}
	// CAPTCHA runs after VerifyBot, so a pass proves VerifyBot short-circuited the chain.
	rs.CAPTCHARule = &dataType.CaptchaRule{Enabled: true, SecretKey: "1234567890abcdef", CaptchaValidateTime: 600}
	return rs
}

// serveChecker mirrors Server.ServeHTTP for the nginx auth_request endpoint.
func serveChecker(cfg *config.MainConfig, rs *config.RuleSet, sharedMem *state.Runtime, header http.Header, remoteAddr string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, "/torii/checker", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range header {
		r.Header[k] = v
	}
	reqData := processRequestData(cfg, r)
	reqData.FeatureControl = processFeatureControl(cfg, r, rs)
	rec := httptest.NewRecorder()
	NewServer(cfg, nil, sharedMem, nil).CheckMain(rec, reqData, rs)
	return rec
}

func crawlerHeader(ip, ua string) http.Header {
	return http.Header{
		"Torii-Real-Ip":   {ip},
		"Torii-Real-Host": {"example.com"},
		"User-Agent":      {ua},
	}
}

func newVerifyBotEnv() (*config.MainConfig, *state.Runtime, *AdaptiveTrafficAnalyzer) {
	cfg := config.DefaultMainConfig()
	cfg.WebPath = "/torii"
	sharedMem := &state.Runtime{}
	// Captcha lets requests through when its counter is missing, which would hide a VerifyBot miss.
	sharedMem.CaptchaFailureLimitCounter.Store(dataType.NewCounter(1, 60))
	analyzer := NewAdaptiveTrafficAnalyzer(sharedMem, nil)
	sharedMem.SetAnalyzer(analyzer)
	return cfg, sharedMem, analyzer
}

func TestVerifyBotLiveAcceptsRealCrawlers(t *testing.T) {
	for _, c := range liveCrawlers {
		t.Run(c.name, func(t *testing.T) {
			requireCrawlerDNS(t, c.ip)
			cfg, sharedMem, analyzer := newVerifyBotEnv()

			// Nginx connects from a private address; the crawler IP only arrives in the header.
			rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, crawlerHeader(c.ip, c.ua), "10.0.0.2:40000")

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d Torii-Action=%q, want 200", rec.Code, rec.Header().Get("Torii-Action"))
			}
			if !analyzer.marks.active(c.ip, time.Now()) {
				t.Fatal("verified crawler was not exempted from traffic analysis")
			}
			if analyzer.marks.active("10.0.0.2", time.Now()) {
				t.Fatal("the proxy address was marked instead of the crawler")
			}
		})
	}
}

func TestVerifyBotLiveUsesFirstForwardedAddress(t *testing.T) {
	c := liveCrawlers[0]
	requireCrawlerDNS(t, c.ip)
	cfg, sharedMem, _ := newVerifyBotEnv()

	header := crawlerHeader(c.ip+", 10.0.0.3", c.ua)
	rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, header, "10.0.0.2:40000")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d Torii-Action=%q, want 200", rec.Code, rec.Header().Get("Torii-Action"))
	}

	// The client is the first entry; a crawler address later in the chain proves nothing.
	header = crawlerHeader("10.0.0.3, "+c.ip, c.ua)
	rec = serveChecker(cfg, verifyBotRuleSet(), sharedMem, header, "10.0.0.2:40000")
	if rec.Code != 445 || rec.Header().Get("Torii-Action") != "403" {
		t.Fatalf("got %d %q, want 445 403", rec.Code, rec.Header().Get("Torii-Action"))
	}
}

func TestVerifyBotLiveRejectsMismatchedCrawlers(t *testing.T) {
	google, bing := liveCrawlers[0], liveCrawlers[1]
	requireCrawlerDNS(t, google.ip)
	requireCrawlerDNS(t, bing.ip)

	tests := []struct {
		name string
		ip   string
		ua   string
	}{
		// A genuine crawler of one operator does not vouch for another operator's user agent.
		{"Googlebot UA from a Bing crawler", bing.ip, google.ua},
		{"Bingbot UA from a Google crawler", google.ip, bing.ua},
		{"Googlebot UA from a non-crawler", "192.0.2.1", google.ua},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, sharedMem, analyzer := newVerifyBotEnv()
			rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, crawlerHeader(tt.ip, tt.ua), "10.0.0.2:40000")
			if rec.Code != 445 || rec.Header().Get("Torii-Action") != "403" {
				t.Fatalf("got %d %q, want 445 403", rec.Code, rec.Header().Get("Torii-Action"))
			}
			if analyzer.marks.active(tt.ip, time.Now()) {
				t.Fatal("rejected client was exempted from traffic analysis")
			}
		})
	}
}

func TestVerifyBotLiveFeatureControl(t *testing.T) {
	c := liveCrawlers[0]
	requireCrawlerDNS(t, c.ip)

	tests := []struct {
		name       string
		feature    string
		enabled    bool
		wantStatus int
		wantAction string
	}{
		// Without VerifyBot the crawler falls through to CAPTCHA like any client.
		{"disabled in config", "", false, 445, "CAPTCHA"},
		{"forced off by header", "____0", true, 445, "CAPTCHA"},
		{"forced on by header", "____1", false, http.StatusOK, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, sharedMem, analyzer := newVerifyBotEnv()
			rs := verifyBotRuleSet()
			rs.VerifyBotRule.Enabled = tt.enabled
			header := crawlerHeader(c.ip, c.ua)
			if tt.feature != "" {
				header.Set("Torii-Feature-Control", tt.feature)
			}

			rec := serveChecker(cfg, rs, sharedMem, header, "10.0.0.2:40000")
			if rec.Code != tt.wantStatus || rec.Header().Get("Torii-Action") != tt.wantAction {
				t.Fatalf("got %d %q, want %d %q", rec.Code, rec.Header().Get("Torii-Action"), tt.wantStatus, tt.wantAction)
			}
			if marked := analyzer.marks.active(c.ip, time.Now()); marked != (tt.wantStatus == http.StatusOK) {
				t.Fatalf("marked = %v", marked)
			}
		})
	}
}

func TestVerifyBotLiveIgnoresHeaderWhenNotConfigured(t *testing.T) {
	c := liveCrawlers[0]
	requireCrawlerDNS(t, c.ip)
	cfg, sharedMem, _ := newVerifyBotEnv()
	cfg.ConnectingIPHeaders = []string{"X-Other-Header"}

	// Torii-Real-IP is not trusted here, so the socket address is the client.
	rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, crawlerHeader(c.ip, c.ua), "192.0.2.1:40000")
	if rec.Code != 445 || rec.Header().Get("Torii-Action") != "403" {
		t.Fatalf("got %d %q, want 445 403", rec.Code, rec.Header().Get("Torii-Action"))
	}
	if !strings.Contains(c.ua, "Googlebot") {
		t.Fatal("fixture drifted")
	}
}

// Fake crawlers: a crawler user agent from an address its operator does not crawl from.
// Several of these belong to the same company, so ownership alone must not be enough.
var fakeCrawlers = []struct {
	name string
	ip   string
	ua   string
}{
	{"Googlebot from Google Public DNS (dns.google)", "8.8.8.8", liveCrawlers[0].ua},
	{"Googlebot from a Google frontend (1e100.net)", "142.250.80.46", liveCrawlers[0].ua},
	{"Googlebot from Cloudflare DNS", "1.1.1.1", liveCrawlers[0].ua},
	{"Googlebot from Quad9 DNS", "9.9.9.9", liveCrawlers[0].ua},
	{"Googlebot from an address without reverse DNS", "192.0.2.1", liveCrawlers[0].ua},
	// Rentable Google Cloud VMs: their reverse DNS (*.bc.googleusercontent.com) resolves back to them.
	{"Googlebot from a Google Cloud VM (34.120.177.193)", "34.120.177.193", liveCrawlers[0].ua},
	{"Googlebot from a Google Cloud VM (35.186.224.25)", "35.186.224.25", liveCrawlers[0].ua},
	{"Googlebot from a Google Cloud VM (34.102.136.180)", "34.102.136.180", liveCrawlers[0].ua},
	{"upper-case GOOGLEBOT from Quad9 DNS", "9.9.9.9", "MOZILLA/5.0 (COMPATIBLE; GOOGLEBOT/2.1)"},
	{"Bingbot from a Microsoft edge server (msedge.net)", "204.79.197.200", liveCrawlers[1].ua},
	{"Bingbot from a Microsoft address without reverse DNS", "13.107.21.200", liveCrawlers[1].ua},
	{"Applebot from an Apple address (appleid.org)", "17.172.224.47", liveCrawlers[2].ua},
	{"YandexBot from Yandex DNS (dns.yandex.ru)", "77.88.8.8", liveCrawlers[3].ua},
	{"YandexBot from a Yandex frontend (ya.ru)", "5.255.255.242", liveCrawlers[3].ua},
	{"Baiduspider from Google Public DNS", "8.8.8.8", "Mozilla/5.0 (compatible; Baiduspider/2.0; +http://www.baidu.com/search/spider.html)"},
	{"Sogou spider from Google Public DNS", "8.8.8.8", "Sogou web spider/4.0(+http://www.sogou.com/docs/help/webmasters.htm#07)"},
}

func TestVerifyBotLiveBlocksFakeCrawlers(t *testing.T) {
	// A rejection only means something when DNS works, so require one real crawler to verify first.
	requireCrawlerDNS(t, liveCrawlers[0].ip)

	for _, f := range fakeCrawlers {
		t.Run(f.name, func(t *testing.T) {
			cfg, sharedMem, analyzer := newVerifyBotEnv()
			rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, crawlerHeader(f.ip, f.ua), "10.0.0.2:40000")
			if rec.Code != 445 || rec.Header().Get("Torii-Action") != "403" {
				t.Fatalf("got %d %q, want 445 403", rec.Code, rec.Header().Get("Torii-Action"))
			}
			if analyzer.marks.active(f.ip, time.Now()) {
				t.Fatal("fake crawler was exempted from traffic analysis")
			}
		})
	}
}

// User agents that only look like a crawler are not verified, so they get no crawler privileges
// and continue to the normal checks; a real crawler address does not change that.
func TestVerifyBotLiveLookalikeUserAgentsGetNoBypass(t *testing.T) {
	requireCrawlerDNS(t, liveCrawlers[0].ip)

	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Goog1ebot/2.1)",
		"Mozilla/5.0 (compatible; Google-bot/2.1)",
		"Mozilla/5.0 (compatible; Bing-bot/2.0)",
		"Mozilla/5.0 (compatible; YandexBot/3.0)", // no "yandex.com/bots" marker
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0 Safari/537.36",
	} {
		t.Run(ua, func(t *testing.T) {
			cfg, sharedMem, analyzer := newVerifyBotEnv()
			rec := serveChecker(cfg, verifyBotRuleSet(), sharedMem, crawlerHeader(liveCrawlers[0].ip, ua), "10.0.0.2:40000")
			if rec.Code != 445 || rec.Header().Get("Torii-Action") != "CAPTCHA" {
				t.Fatalf("got %d %q, want 445 CAPTCHA", rec.Code, rec.Header().Get("Torii-Action"))
			}
			if analyzer.marks.active(liveCrawlers[0].ip, time.Now()) {
				t.Fatal("unverified client was exempted from traffic analysis")
			}
		})
	}
}
