package integrity

import (
	"net/http"
	"slices"
	"testing"
)

const (
	uaChrome     = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36"
	uaChrome142  = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
	uaFirefox147 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:147.0) Gecko/20100101 Firefox/147.0"
	uaEdge       = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
	uaAndroid    = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36"
	uaWebView    = "Mozilla/5.0 (Linux; Android 14; Pixel 8 Build/UQ1A; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/135.0.0.0 Mobile Safari/537.36"
	uaFirefox    = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0"
	uaSafari     = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15"
	uaIPhone     = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"
	uaCriOS      = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/135.0.0.0 Mobile/15E148 Safari/604.1"

	chromeTLS  = "0303|0a0a,1301,1302,1303,c02b|0a0a,0000,0017,ff01,000a,000b,0023,0010,0005,000d,0012,0033,002d,002b,001b,44cd,fe0d,0a0a|0a0a,0304,0303|0a0a,11ec,001d,0017,0018|00|0403,0804,0401|h2,http/1.1"
	firefoxTLS = "0303|1301,1303,1302,c02b|0000,0017,ff01,000a,000b,0023,0010,0005,0022,0033,002b,000d,002d,001c|0304,0303|11ec,001d,0017,0018|00|0403,0503,0603|h2,http/1.1"
	// What the TLS library of a script sends: TLS 1.3 and HTTP/2, but no reserved values.
	scriptTLS = "0303|1302,1303,1301,c02c|0000,000b,000a,0023,0016,0017,000d,002b,002d,0033|0304,0303|001d,0017,0018|00,01,02|0403,0503|h2,http/1.1"
)

// navigation returns the headers of a page view as the connector passes them on: what the
// browser sends over HTTPS, and what the connector adds about the connection.
func navigation(ua string) http.Header {
	h := http.Header{}
	h.Set("User-Agent", ua)
	h.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	h.Set("Accept-Language", "en-US,en;q=0.9")
	h.Set("Accept-Encoding", "gzip, deflate, br, zstd")
	h.Set("Sec-Fetch-Site", "none")
	h.Set("Sec-Fetch-Mode", "navigate")
	h.Set("Sec-Fetch-Dest", "document")
	h.Set(headerScheme, "https")
	h.Set(headerProto, "HTTP/2.0")
	claim := parseBrowserClaim(ua)
	switch claim.family {
	case familyChromium:
		h.Set("Sec-CH-UA", `"Google Chrome";v="135", "Not-A.Brand";v="8", "Chromium";v="135"`)
		h.Set("Sec-CH-UA-Mobile", "?0")
		h.Set("Sec-CH-UA-Platform", `"`+claim.system+`"`)
		h.Set(headerHeaderOrder, "sec-ch-ua,sec-ch-ua-mobile,sec-ch-ua-platform,upgrade-insecure-requests,user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-user,sec-fetch-dest,accept-encoding,accept-language,cookie,priority")
		h.Set(headerTLS, chromeTLS)
	case familyFirefox:
		h.Set(headerHeaderOrder, "user-agent,accept,accept-language,accept-encoding,upgrade-insecure-requests,sec-fetch-dest,sec-fetch-mode,sec-fetch-site,sec-fetch-user,priority,te,cookie")
		h.Set(headerTLS, firefoxTLS)
	default:
		h.Set(headerHeaderOrder, "sec-fetch-dest,user-agent,accept,sec-fetch-site,sec-fetch-mode,accept-language,priority,accept-encoding,cookie")
		h.Set(headerTLS, chromeTLS)
	}
	return h
}

// finding returns the first rule the request breaks, leaving out the ones named.
func finding(h http.Header, without ...string) (rule, note string) {
	return New(h.Get("User-Agent"), h).Finding(func(rule string) bool { return !slices.Contains(without, rule) })
}

func TestBrowsersBreakNoRule(t *testing.T) {
	headers := map[string]http.Header{
		"chrome":          navigation(uaChrome),
		"edge":            navigation(uaEdge),
		"firefox":         navigation(uaFirefox),
		"safari":          navigation(uaSafari),
		"safari on iOS":   navigation(uaIPhone),
		"chrome on iOS":   navigation(uaCriOS),
		"android webview": navigation(uaWebView),
	}

	h := navigation(uaAndroid)
	h.Set("Sec-CH-UA-Platform", `"Android"`)
	headers["chrome on android"] = h

	// The user asked for the desktop site: the User-Agent says Linux, the platform Android.
	h = navigation("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36")
	h.Set("Sec-CH-UA-Platform", `"Android"`)
	headers["desktop site on android"] = h

	// A brand of Chromium that does not name the engine.
	h = navigation(uaChrome)
	h.Set("Sec-CH-UA", `"Not A;Brand";v="99", "Some Browser";v="135"`)
	headers["brand without chromium"] = h

	// An application decides what its WebView sends.
	h = navigation(uaWebView)
	h.Del("Sec-CH-UA")
	headers["webview without client hints"] = h

	// A script on the page asks for data: no navigation, headers in an order of its own.
	h = navigation(uaChrome)
	h.Set("Sec-Fetch-Mode", "cors")
	h.Set("Sec-Fetch-Dest", "empty")
	h.Set("Accept", "application/json")
	h.Set(headerHeaderOrder, "accept-language,accept,user-agent,accept-encoding")
	headers["fetch from a page"] = h

	// Plain HTTP: browsers send neither Sec-Fetch-* nor client hints, and there is no TLS.
	h = navigation(uaChrome)
	for _, name := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-CH-UA", "Sec-CH-UA-Mobile", "Sec-CH-UA-Platform", headerTLS} {
		h.Del(name)
	}
	h.Set(headerScheme, "http")
	headers["plain http"] = h

	// A connector that says nothing about the connection: nothing is known, nothing is found.
	h = http.Header{}
	h.Set("User-Agent", uaChrome)
	h.Set("Accept", "*/*")
	h.Set("Accept-Language", "en")
	headers["connector without the new headers"] = h

	h = http.Header{}
	h.Set("User-Agent", uaChrome)
	h.Set("Upgrade", "websocket")
	h.Set(headerScheme, "https")
	headers["websocket handshake"] = h

	// Before the versions that fixed them, a browser may lack the newer parts of the handshake:
	// Chrome 110 sent no encrypted_client_hello, Chrome 135 could have the post-quantum group
	// switched off. A connection for HTTP/1.1 alone announces no HTTP/2 settings.
	h = navigation("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")
	h.Set("Sec-CH-UA", `"Chromium";v="110"`)
	h.Set(headerTLS, "0303|0a0a,1301|0a0a,0000,0010,002b,000a,001b,4469|0304,0303|0a0a,001d|00|0403|h2,http/1.1")
	headers["older chrome"] = h
	h = navigation(uaChrome)
	h.Set(headerTLS, "0303|0a0a,1301|0a0a,0000,0010,002b,000a,001b,44cd,fe0d|0304,0303|0a0a,001d|00|0403|h2,http/1.1")
	headers["chrome with the post-quantum group switched off"] = h
	// Safari is not judged by the post-quantum group, whatever its version.
	h = navigation("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.0 Safari/605.1.15")
	h.Set(headerTLS, "0303|0a0a,1301|0a0a,0000,0010,002b,000a,001b|0304,0303|0a0a,001d|00|0403|h2,http/1.1")
	headers["safari without the post-quantum group"] = h

	// HTTP/3 has a ClientHello of its own.
	h = navigation(uaChrome)
	h.Set(headerProto, "HTTP/3.0")
	h.Set(headerTLS, "0303|1301,1302,1303|0000,0010,002b|0304|001d|00|0403|h3")
	headers["http/3"] = h

	// Clients that do not claim to be a current browser are not this check's business.
	for name, ua := range map[string]string{
		"curl":             "curl/8.5.0",
		"script":           "python-requests/2.32.0",
		"old chrome":       "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36",
		"old edge":         "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edge/18.19041",
		"rendering spider": "Mozilla/5.0 (Linux; Android 6.0.1; Nexus 5X Build/MMB29P) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"old iOS":          "Mozilla/5.0 (iPhone; CPU iPhone OS 15_8 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Mobile/15E148 Safari/604.1",
	} {
		h := http.Header{}
		h.Set("User-Agent", ua)
		h.Set(headerScheme, "https")
		h.Set(headerTLS, scriptTLS)
		headers[name] = h
	}

	for name, h := range headers {
		t.Run(name, func(t *testing.T) {
			if rule, note := finding(h); rule != "" {
				t.Fatalf("found %s: %s", rule, note)
			}
		})
	}
}

func TestFindings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		ua     string
		change func(http.Header)
		want   string
		note   string
	}{
		{"no user agent", uaChrome, func(h http.Header) { h.Del("User-Agent") }, NoUserAgent, ""},
		{"blank user agent", uaChrome, func(h http.Header) { h.Set("User-Agent", "  ") }, NoUserAgent, ""},
		{"no accept", uaChrome, func(h http.Header) {
			h.Set("Sec-Fetch-Mode", "no-cors")
			h.Set("Sec-Fetch-Dest", "image")
			h.Del("Accept")
		}, MissingHeaders, "chromium 135 without Accept"},
		{"no accept-language", uaFirefox, func(h http.Header) { h.Del("Accept-Language") }, MissingHeaders, "firefox 128 without Accept-Language"},
		{"only the user agent copied", uaChrome, func(h http.Header) {
			for _, name := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
				h.Del(name)
			}
		}, NoFetchMetadata, "chromium 135 without Sec-Fetch-*"},
		{"safari without fetch metadata", uaIPhone, func(h http.Header) {
			for _, name := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
				h.Del(name)
			}
		}, NoFetchMetadata, "safari 17 without Sec-Fetch-*"},
		{"some fetch metadata", uaChrome, func(h http.Header) { h.Del("Sec-Fetch-Dest") }, FetchMetadataMismatch, "chromium 135 with only some of Sec-Fetch-*"},
		{"invented fetch site", uaChrome, func(h http.Header) { h.Set("Sec-Fetch-Site", "same") }, FetchMetadataMismatch, `chromium 135 with Sec-Fetch-Site "same"`},
		{"invented fetch mode", uaChrome, func(h http.Header) { h.Set("Sec-Fetch-Mode", "get") }, FetchMetadataMismatch, `chromium 135 with Sec-Fetch-Mode "get"`},
		{"navigation that accepts no page", uaFirefox, func(h http.Header) { h.Set("Accept", "*/*") }, FetchMetadataMismatch, "firefox 128 navigates to a document it does not accept"},
		{"chrome without client hints", uaChrome, func(h http.Header) { h.Del("Sec-CH-UA") }, NoClientHints, "chromium 135 without Sec-CH-UA"},
		{"client hints of another version", uaChrome, func(h http.Header) {
			h.Set("Sec-CH-UA", `"Chromium";v="120", "Not A;Brand";v="135"`)
		}, ClientHintsMismatch, "chromium 135 with Sec-CH-UA of version 120"},
		{"client hints of another system", uaChrome, func(h http.Header) { h.Set("Sec-CH-UA-Platform", `"Linux"`) }, ClientHintsMismatch, `chromium 135 with Sec-CH-UA-Platform "Linux"`},
		{"firefox with client hints", uaFirefox, func(h http.Header) { h.Set("Sec-CH-UA", `"Chromium";v="135"`) }, ClientHintsMismatch, "firefox 128 with Sec-CH-UA"},
		{"chrome on iOS with client hints", uaCriOS, func(h http.Header) { h.Set("Sec-CH-UA", `"Chromium";v="135"`) }, ClientHintsMismatch, "safari 17 with Sec-CH-UA"},
		{"chrome with the header order of a script", uaChrome, func(h http.Header) {
			h.Set(headerHeaderOrder, "Host,User-Agent,Accept-Encoding,Accept,Connection,Accept-Language,Sec-Fetch-Site,Sec-Fetch-Mode,Sec-Fetch-Dest,sec-ch-ua")
		}, HeaderOrder, "chromium 135 sends accept-encoding before accept"},
		{"firefox with the header order of chrome", uaFirefox, func(h http.Header) {
			h.Set(headerHeaderOrder, "user-agent,accept,sec-fetch-site,sec-fetch-mode,sec-fetch-dest,accept-encoding,accept-language")
		}, HeaderOrder, "firefox 128 sends accept-encoding before accept-language"},
		{"chrome without reserved values", uaChrome, func(h http.Header) {
			h.Set(headerTLS, "0303|1301,1302|0000,0010,002b,000a,001b,44cd,fe0d|0304,0303|11ec,001d|00|0403|h2,http/1.1")
		}, TLS, "chromium 135 has no reserved value among its cipher suites"},
		{"no TLS 1.3", uaFirefox, func(h http.Header) {
			h.Set(headerTLS, "0303|c02f,00ff|0000,000b,000a,000d,0010||0017|00|0401|h2,http/1.1")
		}, TLS, "firefox 128 does not offer TLS 1.3"},
		// The handshake of a library built to pass for Chromium by its cipher suites alone.
		{"chrome without certificate compression", uaChrome, func(h http.Header) {
			h.Set(headerTLS, "0303|0a0a,1301,1302|0a0a,0000,0010,002b,000a,44cd,fe0d|0304,0303|0a0a,11ec,001d|00|0403|h2,http/1.1")
		}, TLSExtensions, "chromium 135 does not offer certificate compression"},
		{"chrome without ALPS", uaChrome, func(h http.Header) {
			h.Set(headerTLS, "0303|0a0a,1301,1302|0a0a,0000,0010,002b,000a,001b,fe0d|0304,0303|0a0a,11ec,001d|00|0403|h2,http/1.1")
		}, TLSExtensions, "chromium 135 does not announce its HTTP/2 settings in the handshake"},
		{"chrome without encrypted client hello", uaChrome, func(h http.Header) {
			h.Set(headerTLS, "0303|0a0a,1301,1302|0a0a,0000,0010,002b,000a,001b,4469|0304,0303|0a0a,11ec,001d|00|0403|h2,http/1.1")
		}, TLSExtensions, "chromium 135 sends no encrypted_client_hello"},
		{"chrome without post-quantum key exchange", uaChrome142, func(h http.Header) {
			h.Set("Sec-CH-UA", `"Chromium";v="142"`)
			h.Set(headerTLS, "0303|0a0a,1301,1302|0a0a,0000,0010,002b,000a,001b,44cd,fe0d|0304,0303|0a0a,001d,0017|00|0403|h2,http/1.1")
		}, TLSPostQuantum, "chromium 142 offers no post-quantum key exchange"},
		{"firefox without post-quantum key exchange", uaFirefox147, func(h http.Header) {
			h.Set(headerTLS, "0303|1301,1303|0000,0010,002b,000a|0304,0303|001d,0017|00|0403|h2,http/1.1")
		}, TLSPostQuantum, "firefox 147 offers no post-quantum key exchange"},
		{"no HTTP/2", uaSafari, func(h http.Header) {
			h.Set(headerTLS, "0303|0a0a,1301|0000,002b,0010|0304,0303|001d|00|0403|http/1.1")
		}, TLS, "safari 17 does not offer HTTP/2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := navigation(tc.ua)
			tc.change(h)
			if rule, note := finding(h); rule != tc.want || note != tc.note {
				t.Fatalf("found %q (%s), want %q (%s)", rule, note, tc.want, tc.note)
			}
			// Each rule answers for itself, as a custom rule asks it.
			if note, broken := New(h.Get("User-Agent"), h).Breaks(tc.want); !broken || note != tc.note {
				t.Fatalf("Breaks(%s) = %q, %v", tc.want, note, broken)
			}
			// The same request breaks no other rule.
			if rule, note := finding(h, tc.want); rule != "" {
				t.Fatalf("without %s: found %s (%s)", tc.want, rule, note)
			}
		})
	}
}

func TestBreaksUnknownRule(t *testing.T) {
	h := navigation(uaChrome)
	h.Del("Accept")
	if note, broken := New(uaChrome, h).Breaks("no_such_rule"); broken || note != "" {
		t.Fatalf("Breaks = %q, %v", note, broken)
	}
}

func TestParseBrowserClaim(t *testing.T) {
	for ua, want := range map[string]browserClaim{
		uaChrome:  {family: familyChromium, major: 135, system: "Windows"},
		uaEdge:    {family: familyChromium, major: 135, system: "Windows"},
		uaAndroid: {family: familyChromium, major: 135, system: "Android"},
		uaWebView: {family: familyChromium, major: 135, system: "Android", webview: true},
		uaFirefox: {family: familyFirefox, major: 128, system: "Windows"},
		uaSafari:  {family: familySafari, major: 17, system: "macOS"},
		uaIPhone:  {family: familySafari, major: 17, system: "iOS"},
		uaCriOS:   {family: familySafari, major: 17, system: "iOS"},
		"Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36": {family: familyChromium, major: 135, system: "Chrome OS"},
		"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0":                                 {family: familyFirefox, major: 128, system: "Linux"},
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/ Safari/537.36":         {system: "Windows"},
		"Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)":                                        {},
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)":                                                             {},
		"Chrome/135.0.0.0": {},
		"":                 {},
	} {
		if got := parseBrowserClaim(ua); got != want {
			t.Errorf("%q:\n got %+v\nwant %+v", ua, got, want)
		}
	}
}

func TestReportedClientHello(t *testing.T) {
	cases := []struct {
		name, header string
		want         ClientHello
	}{
		{"TLS 1.3", "0303|0a0a,1301|0000,002b|0a0a,0303,0304|001d|00|0403|h2,http/1.1",
			ClientHello{Version: "0304", Ciphers: "0a0a,1301", Extensions: "0000,002b", Groups: "001d", ALPN: "h2,http/1.1"}},
		{"no supported_versions", "0303|c02b|0000||0017|00|0403|",
			ClientHello{Version: "0303", Ciphers: "c02b", Extensions: "0000", Groups: "0017"}},
		{"only a reserved version", "0303|c02b|002b|0a0a||||", ClientHello{Version: "0303", Ciphers: "c02b", Extensions: "002b"}},
		{"not reported", "", ClientHello{}},
		{"another format", "0303|c02b|0000", ClientHello{}},
	}
	for _, tc := range cases {
		h := http.Header{}
		if tc.header != "" {
			h.Set(headerTLS, tc.header)
		}
		if got := ReportedClientHello(h); got != tc.want {
			t.Errorf("%s: ReportedClientHello = %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
