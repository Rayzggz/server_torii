package rules

import (
	"net/http"
	"net/netip"
	"server_torii/internal/dataType"
	"strings"
	"testing"
)

type stubResolver struct{ country string }

func (r stubResolver) Country(netip.Addr) (string, error) { return r.country, nil }

type stubEvidence struct{ ip string }

func (e stubEvidence) HasBrowserEvidence(ip string) bool { return ip == e.ip }

func testRequest() *dataType.UserRequest {
	headers := http.Header{}
	headers.Set("Referer", "https://evil.example/page")
	headers.Set("Accept-Language", "zh-CN,zh;q=0.9")
	headers.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	headers.Add("Cookie", "session=abc; theme=dark")
	return &dataType.UserRequest{
		RemoteIP:  "8.8.8.8",
		Uri:       "/wp-admin/Setup.PHP?step=2&lang=en%20US",
		UserAgent: "Mozilla/5.0 (compatible; Googlebot/2.1)",
		Host:      "www.example.com",
		Method:    "post",
		Headers:   headers,
	}
}

func TestEval(t *testing.T) {
	cases := []struct {
		expr string
		want bool
	}{
		{`http.host eq "www.example.com"`, true},
		{`http.host == "example.com"`, false},
		{`http.host ne "example.com"`, true},
		{`http.request.uri eq "/wp-admin/Setup.PHP?step=2&lang=en%20US"`, true},
		{`http.request.uri.path eq "/wp-admin/Setup.PHP"`, true},
		{`http.request.uri.query eq "step=2&lang=en%20US"`, true},
		{`http.request.uri.path.extension eq "php"`, true},
		{`http.request.uri.args["step"] eq "2"`, true},
		{`http.request.uri.args["lang"] eq "en US"`, true},
		{`http.request.uri.args["missing"] eq ""`, true},
		{`http.request.method eq "POST"`, true},
		{`http.user_agent contains "Googlebot"`, true},
		{`http.user_agent contains "googlebot"`, false},
		{`http.referer wildcard "https://EVIL.example/*"`, true},
		{`http.referer strict wildcard "https://EVIL.example/*"`, false},
		{`http.referer strict wildcard "https://evil.example/*"`, true},
		{`http.request.uri.path wildcard "/wp-*"`, true},
		{`http.request.uri.path wildcard "/wp-"`, false},
		{`http.request.uri.path matches "^/wp-(admin|login)"`, true},
		{`http.request.uri.path ~ "^/api/"`, false},
		{`http.request.headers["accept-language"] contains "zh"`, true},
		{`http.request.headers["X-Missing"] eq ""`, true},
		{`http.request.cookies["session"] eq "abc"`, true},
		{`http.request.cookies["theme"] in {"dark" "light"}`, true},
		{`http.cookie contains "theme=dark"`, true},
		{`http.x_forwarded_for contains "203.0.113.9"`, true},
		{`ip.src eq 8.8.8.8`, true},
		{`ip.src ne 8.8.4.4`, true},
		{`ip.src in {10.0.0.0/8 8.8.8.0/24}`, true},
		{`ip.src in {10.0.0.0/8, 192.168.0.0/16}`, false},
		{`ip.src in {2001:db8::/32 8.8.8.8}`, true},
		{`ip.src.country eq "US"`, true},
		{`ip.geoip.country in {"CN" "RU"}`, false},
		{`torii.browser_evidence`, true},
		{`not torii.browser_evidence`, false},
		{`lower(http.request.uri.path) eq "/wp-admin/setup.php"`, true},
		{`upper(http.host) eq "WWW.EXAMPLE.COM"`, true},
		{`url_decode(http.request.uri.query) contains "en US"`, true},
		{`starts_with(http.request.uri.path, "/wp-")`, true},
		{`ends_with(lower(http.request.uri.path), ".php")`, true},
		{`len(http.host) eq 15`, true},
		{`len(http.host) gt 20`, false},
		{`len(http.request.headers["x-missing"]) le 0`, true},
		{`true`, true},
		{`false or true`, true},
		// precedence: not > and > xor > or
		{`true or false and false`, true},
		{`(true or false) and false`, false},
		{`true xor true or true`, true},
		{`true xor true and false`, true},
		{`not true and false`, false},
		{`! (http.host eq "a") && http.host != "b"`, true},
		{`http.host eq "www.example.com" ^^ ip.src eq 8.8.8.8`, false},
		{`http.request.uri.path wildcard "/wp-*" and not ip.src in {10.0.0.0/8}`, true},
	}
	sharedMem := &dataType.SharedMemory{
		CountryResolver:         stubResolver{country: "us"},
		AdaptiveTrafficAnalyzer: stubEvidence{ip: "8.8.8.8"},
	}
	for _, tc := range cases {
		prog, err := Compile(tc.expr)
		if err != nil {
			t.Errorf("Compile(%q) error: %v", tc.expr, err)
			continue
		}
		if got := prog.Eval(NewContext(testRequest(), sharedMem)); got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestEvalMissingData(t *testing.T) {
	req := &dataType.UserRequest{RemoteIP: "not-an-ip", Uri: "/"}
	cases := []struct {
		expr string
		want bool
	}{
		{`ip.src eq 1.2.3.4`, false},
		{`ip.src ne 1.2.3.4`, true},
		{`ip.src in {0.0.0.0/0}`, false},
		{`ip.src.country eq ""`, true},
		{`http.referer eq ""`, true},
		{`http.request.cookies["a"] eq ""`, true},
		{`torii.browser_evidence`, false},
		{`http.request.uri.path.extension eq ""`, true},
	}
	for _, tc := range cases {
		prog, err := Compile(tc.expr)
		if err != nil {
			t.Fatalf("Compile(%q) error: %v", tc.expr, err)
		}
		if got := prog.Eval(NewContext(req, nil)); got != tc.want {
			t.Errorf("Eval(%q) = %v, want %v", tc.expr, got, tc.want)
		}
	}
}

func TestIPv4MappedAddress(t *testing.T) {
	prog, err := Compile(`ip.src in {192.0.2.0/24}`)
	if err != nil {
		t.Fatal(err)
	}
	req := &dataType.UserRequest{RemoteIP: "::ffff:192.0.2.1"}
	if !prog.Eval(NewContext(req, nil)) {
		t.Error("IPv4-mapped address should match its IPv4 prefix")
	}
}

func TestCompileErrors(t *testing.T) {
	cases := []struct {
		expr    string
		wantErr string
	}{
		{``, "empty"},
		{`http.host`, "col 10: expected a comparison operator"},
		{`http.hots eq "a"`, `col 1: unknown field "http.hots"`},
		{`http.host eq a`, "expected a string literal"},
		{`http.host eq "a`, "unterminated string"},
		{`http.host eq "a\n"`, "invalid escape"},
		{`http.host lt "a"`, `operator "lt" cannot be used with string values`},
		{`ip.src contains "1"`, `operator "contains" cannot be used with IP values`},
		{`ip.src eq "1.2.3.4"`, "expected an IP address or CIDR"},
		{`ip.src in {1.2.3.4/33}`, "expected an IP address or CIDR"},
		{`http.host in {}`, "set must not be empty"},
		{`http.host in {"a" 1}`, "expected a string literal"},
		{`http.host matches "("`, "invalid regular expression"},
		{`(http.host eq "a"`, `expected ")"`},
		{`http.host eq "a" http.host eq "b"`, "unexpected"},
		{`http.host eq "a" and`, "expected a field or function"},
		{`foo(http.host) eq "a"`, `unknown function "foo"`},
		{`len(ip.src) eq 1`, "expects a string argument"},
		{`starts_with(http.host "a")`, `expected ","`},
		{`http.request.headers eq "a"`, `expected "["`},
		{`torii.browser_evidence eq "a"`, "cannot be used with boolean values"},
		{`len(http.host) gt x`, "expected an integer"},
		{`http.host eq "a" @`, "unexpected character"},
	}
	for _, tc := range cases {
		_, err := Compile(tc.expr)
		if err == nil {
			t.Errorf("Compile(%q) succeeded, want error containing %q", tc.expr, tc.wantErr)
			continue
		}
		if !strings.Contains(err.Error(), tc.wantErr) {
			t.Errorf("Compile(%q) error = %q, want it to contain %q", tc.expr, err, tc.wantErr)
		}
	}
}

func TestWildcardEscapes(t *testing.T) {
	cases := []struct {
		pattern, input string
		want           bool
	}{
		{`/a\*b`, "/a*b", true},
		{`/a\*b`, "/axb", false},
		{`*.php`, "/x/y.PHP", true},
		{`/a.b`, "/axb", false},
		{`*`, "", true},
	}
	for _, tc := range cases {
		re, err := compileWildcard(tc.pattern, false)
		if err != nil {
			t.Fatalf("compileWildcard(%q) error: %v", tc.pattern, err)
		}
		if got := re.MatchString(tc.input); got != tc.want {
			t.Errorf("wildcard %q on %q = %v, want %v", tc.pattern, tc.input, got, tc.want)
		}
	}
}

func TestParseSkipTargets(t *testing.T) {
	mask, err := ParseSkipTargets([]string{"HTTPFlood", "Captcha"})
	if err != nil || mask != SkipHTTPFlood|SkipCaptcha {
		t.Fatalf("ParseSkipTargets = %b, %v", mask, err)
	}
	if _, err := ParseSkipTargets([]string{"IPAllow"}); err == nil {
		t.Fatal("IPAllow runs before CustomRules and must not be a skip target")
	}
}
