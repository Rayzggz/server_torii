// Package integrity looks at one request by itself and asks whether the browser its User-Agent
// names could have sent it. A current browser sends headers no script sends unless it is
// written to: a request that claims to be such a browser and lacks them, or contradicts them,
// did not come from it.
//
// The rules find clients that only copied a User-Agent. A client that copies everything a
// browser sends, or is a browser driven by a script, breaks none: they are no proof of a
// browser, only of its absence. They know nothing about the client beyond the request, so they
// need no warm-up and nothing a client did before changes what they find.
//
// The BrowserIntegrity check applies the rules a site lists, and custom rules read each of them
// as a field.
package integrity

import (
	"net/http"
	"slices"
	"strconv"
	"strings"
)

// What the connector says about how the client reached it. A connector that does not send one
// of them leaves the rules that need it without a finding: unknown is never suspicious.
const (
	headerScheme      = "Torii-Scheme"
	headerProto       = "Torii-Proto"
	headerHeaderOrder = "Torii-Header-Order"
	headerTLS         = "Torii-TLS"
)

// The rules, by the name the configuration, custom rules and Torii-Reason use.
const (
	// NoUserAgent: the request has no User-Agent.
	NoUserAgent = "no_user_agent"
	// MissingHeaders: a browser that sends neither Accept nor Accept-Language.
	MissingHeaders = "missing_headers"
	// NoFetchMetadata: a browser that has sent Sec-Fetch-* for years sends none.
	NoFetchMetadata = "no_fetch_metadata"
	// FetchMetadataMismatch: the Sec-Fetch-* headers contradict themselves or the request.
	FetchMetadataMismatch = "fetch_metadata_mismatch"
	// NoClientHints: a Chromium browser without Sec-CH-UA.
	NoClientHints = "no_client_hints"
	// ClientHintsMismatch: Sec-CH-UA* names another browser, version or system than User-Agent.
	ClientHintsMismatch = "client_hints_mismatch"
	// HeaderOrder: the headers of a navigation are not in the order the browser sends them.
	HeaderOrder = "header_order"
	// TLS: the TLS ClientHello lacks what the browser always offers.
	TLS = "tls"
	// TLSExtensions: the ClientHello lacks extensions only Chromium sends.
	TLSExtensions = "tls_extensions"
	// TLSPostQuantum: the ClientHello offers no post-quantum key exchange.
	TLSPostQuantum = "tls_post_quantum"
)

// Rules are all the rules, in the order Finding tries them.
var Rules = []string{
	NoUserAgent, MissingHeaders, NoFetchMetadata, FetchMetadataMismatch, NoClientHints,
	ClientHintsMismatch, HeaderOrder, TLS, TLSExtensions, TLSPostQuantum,
}

// finders has what each rule but NoUserAgent looks for in the request of a current browser.
// A finder returns what is wrong with the request, or "".
var finders = map[string]func(browserClaim, http.Header) string{
	MissingHeaders:        findMissingHeaders,
	NoFetchMetadata:       findNoFetchMetadata,
	FetchMetadataMismatch: findFetchMetadataMismatch,
	NoClientHints:         findNoClientHints,
	ClientHintsMismatch:   findClientHintsMismatch,
	HeaderOrder:           findHeaderOrder,
	TLS:                   findTLS,
	TLSExtensions:         findTLSExtensions,
	TLSPostQuantum:        findTLSPostQuantum,
}

// Request is one request to be judged. Its User-Agent is read once, however many rules are
// asked about. It is not safe for concurrent use.
type Request struct {
	userAgent string
	headers   http.Header

	parsed bool
	claim  browserClaim
	// judged reports whether the rules that compare the request with a browser apply to it.
	judged bool
}

// New returns the request with the given User-Agent and headers, as the connector passed them on.
func New(userAgent string, headers http.Header) *Request {
	return &Request{userAgent: userAgent, headers: headers}
}

// Breaks reports whether the request breaks the rule, and what about the request does. It
// reports false for a rule that does not exist.
func (r *Request) Breaks(rule string) (note string, broken bool) {
	if rule == NoUserAgent {
		return "", strings.TrimSpace(r.userAgent) == ""
	}
	find, known := finders[rule]
	if !known || !r.judge() {
		return "", false
	}
	if note := find(r.claim, r.headers); note != "" {
		return r.claim.String() + " " + note, true
	}
	return "", false
}

// judge reads the User-Agent. Every rule but NoUserAgent compares the request with what a
// browser is known to send, which is only known of the current versions of the browsers most
// clients use; and the handshake of a WebSocket is the one request a browser sends without
// the headers the rules look for.
func (r *Request) judge() bool {
	if !r.parsed {
		r.parsed = true
		r.claim = parseBrowserClaim(r.userAgent)
		r.judged = r.claim.current() && !strings.EqualFold(r.headers.Get("Upgrade"), "websocket")
	}
	return r.judged
}

// Finding returns the first of the rules applies picks that the request breaks, and what about
// the request broke it. It returns "" for a request that breaks none of them.
func (r *Request) Finding(applies func(rule string) bool) (rule, note string) {
	for _, rule := range Rules {
		if !applies(rule) {
			continue
		}
		if note, broken := r.Breaks(rule); broken {
			return rule, note
		}
	}
	return "", ""
}

// Browsers send Accept and Accept-Language with every request.
func findMissingHeaders(_ browserClaim, h http.Header) string {
	for _, name := range []string{"Accept", "Accept-Language"} {
		if h.Get(name) == "" {
			return "without " + name
		}
	}
	return ""
}

// secure reports whether the client is known to have asked over HTTPS. Browsers send
// Sec-Fetch-* and Sec-CH-UA only then.
func secure(h http.Header) bool {
	return h.Get(headerScheme) == "https"
}

func findNoFetchMetadata(_ browserClaim, h http.Header) string {
	if !secure(h) {
		return ""
	}
	if h.Get("Sec-Fetch-Site") == "" && h.Get("Sec-Fetch-Mode") == "" && h.Get("Sec-Fetch-Dest") == "" {
		return "without Sec-Fetch-*"
	}
	return ""
}

var (
	fetchSites = []string{"cross-site", "same-origin", "same-site", "none"}
	fetchModes = []string{"cors", "navigate", "no-cors", "same-origin", "websocket"}
)

// A browser sends the three headers together and with values out of a fixed set; the
// destinations are not checked, because new ones are still being added.
func findFetchMetadataMismatch(_ browserClaim, h http.Header) string {
	site, mode, dest := h.Get("Sec-Fetch-Site"), h.Get("Sec-Fetch-Mode"), h.Get("Sec-Fetch-Dest")
	switch {
	case site == "" && mode == "" && dest == "":
		return ""
	case site == "" || mode == "" || dest == "":
		return "with only some of Sec-Fetch-*"
	case !slices.Contains(fetchSites, site):
		return "with Sec-Fetch-Site " + strconv.Quote(clip(site))
	case !slices.Contains(fetchModes, mode):
		return "with Sec-Fetch-Mode " + strconv.Quote(clip(mode))
	case mode == "navigate" && dest == "document" && !strings.Contains(h.Get("Accept"), "text/html"):
		return "navigates to a document it does not accept"
	}
	return ""
}

// Android WebView is left out: the application decides whether it sends client hints.
func findNoClientHints(claim browserClaim, h http.Header) string {
	if claim.family == familyChromium && !claim.webview && secure(h) && h.Get("Sec-CH-UA") == "" {
		return "without Sec-CH-UA"
	}
	return ""
}

func findClientHintsMismatch(claim browserClaim, h http.Header) string {
	brands := h.Get("Sec-CH-UA")
	if brands == "" {
		return ""
	}
	// Only Chromium sends client hints.
	if claim.family != familyChromium {
		return "with Sec-CH-UA"
	}
	if version, found := clientHintsVersion(brands, claim.major); found && version != claim.major {
		return "with Sec-CH-UA of version " + strconv.Itoa(version)
	}
	if platform := strings.Trim(h.Get("Sec-CH-UA-Platform"), `"`); !samePlatform(claim.system, platform) {
		return "with Sec-CH-UA-Platform " + strconv.Quote(clip(platform))
	}
	return ""
}

// clientHintsVersion returns the version Sec-CH-UA gives for Chromium, the engine every brand
// of it names besides its own. Without that brand it returns want when any brand has it, and
// otherwise the version of the first brand. found is false when the header names no version.
func clientHintsVersion(brands string, want int) (version int, found bool) {
	for _, item := range strings.Split(brands, ",") {
		// "Brand";v="123"
		parts := strings.Split(item, `"`)
		if len(parts) < 4 || !strings.HasSuffix(strings.TrimSpace(parts[len(parts)-3]), "v=") {
			continue
		}
		major, _, _ := strings.Cut(parts[len(parts)-2], ".")
		v, err := strconv.Atoi(major)
		if err != nil {
			continue
		}
		if strings.EqualFold(parts[1], "Chromium") {
			return v, true
		}
		if !found || v == want {
			version, found = v, true
		}
	}
	return version, found
}

// samePlatform reports whether the system of the User-Agent and Sec-CH-UA-Platform can be the
// same. A platform this does not know is not judged. Linux and Android count as one: Chrome on
// Android calls itself a Linux desktop when the user asks for the desktop site.
func samePlatform(system, platform string) bool {
	if platform == "Chromium OS" {
		platform = "Chrome OS"
	}
	if system == "" || !slices.Contains([]string{"Windows", "macOS", "Linux", "Android", "Chrome OS", "iOS"}, platform) {
		return true
	}
	if system == platform {
		return true
	}
	return (system == "Linux" || system == "Android") && (platform == "Linux" || platform == "Android")
}

// A browser builds the headers of a navigation itself, always in the same order. A script that
// sets the same headers sends them in the order of its HTTP library.
func findHeaderOrder(claim browserClaim, h http.Header) string {
	order := h.Get(headerHeaderOrder)
	if order == "" || h.Get("Sec-Fetch-Mode") != "navigate" {
		return ""
	}
	var want []string
	switch claim.family {
	case familyChromium:
		want = []string{"user-agent", "accept", "accept-encoding", "accept-language"}
	case familyFirefox:
		want = []string{"user-agent", "accept", "accept-language", "accept-encoding"}
	default:
		return ""
	}
	position := make(map[string]int)
	for i, name := range strings.Split(strings.ToLower(order), ",") {
		if _, seen := position[name]; !seen {
			position[name] = i
		}
	}
	// The list of the connector may end before a header: only the ones it names are compared.
	last, lastName := -1, ""
	for _, name := range want {
		at, listed := position[name]
		if !listed {
			continue
		}
		if at < last {
			return "sends " + name + " before " + lastName
		}
		last, lastName = at, name
	}
	return ""
}

// The fields of Torii-TLS this check reads, see the README of the connector.
const (
	tlsFields            = 8
	tlsCiphers           = 1
	tlsExtensions        = 2
	tlsSupportedVersions = 3
	tlsGroups            = 4
	tlsALPN              = 7
)

// clientHello returns the fields of the ClientHello the connector reported, each a list. It
// returns nil when there is none to judge: no TLS, a connector that does not report it, or
// HTTP/3, whose ClientHello offers another protocol and other extensions.
func clientHello(h http.Header) [][]string {
	fields := strings.Split(h.Get(headerTLS), "|")
	if len(fields) != tlsFields || h.Get(headerProto) == "HTTP/3.0" {
		return nil
	}
	hello := make([][]string, tlsFields)
	for i, field := range fields {
		hello[i] = strings.Split(field, ",")
	}
	return hello
}

// The extensions and the group the rules below look for, as the connector writes them.
const (
	extCompressCertificate = "001b"
	extALPS                = "4469" // application_settings
	extALPSNew             = "44cd" // the code point Chromium moved it to
	extECH                 = "fe0d" // encrypted_client_hello
	groupX25519MLKEM768    = "11ec"
)

// The versions from which a browser is known to send what the two rules below look for.
// Chromium has compressed certificates and announced its settings in the handshake (ALPS)
// since long before the versions this check judges at all. The others are set later than the
// version that made them the default, where one could still switch them off:
//   - encrypted_client_hello, sent with random content where it is not used: Chromium 117
//   - X25519MLKEM768: Chromium 131 on desktops, 133 on Android, fixed from 138;
//     Firefox 132 on desktops, 145 on Android
//
// Safari offers the group from version 26, but the User-Agent of an iPhone no longer names its
// system version, and the system can be told to leave the group out: Safari is not judged.
const (
	chromiumECH         = 120
	chromiumPostQuantum = 140
	firefoxPostQuantum  = 146
)

// Chromium sends extensions no other TLS library does. Android WebView is left out: it is
// Chromium, but the application it is part of configures it.
func findTLSExtensions(claim browserClaim, h http.Header) string {
	hello := clientHello(h)
	if hello == nil || claim.family != familyChromium || claim.webview {
		return ""
	}
	has := func(extension string) bool { return slices.Contains(hello[tlsExtensions], extension) }
	switch {
	case !has(extCompressCertificate):
		return "does not offer certificate compression"
	// The settings are those of HTTP/2: a connection that does not offer it has none.
	case slices.Contains(hello[tlsALPN], "h2") && !has(extALPS) && !has(extALPSNew):
		return "does not announce its HTTP/2 settings in the handshake"
	case claim.major >= chromiumECH && !has(extECH):
		return "sends no encrypted_client_hello"
	}
	return ""
}

func findTLSPostQuantum(claim browserClaim, h http.Header) string {
	hello := clientHello(h)
	if hello == nil {
		return ""
	}
	current := claim.family == familyChromium && !claim.webview && claim.major >= chromiumPostQuantum ||
		claim.family == familyFirefox && claim.major >= firefoxPostQuantum
	if current && !slices.Contains(hello[tlsGroups], groupX25519MLKEM768) {
		return "offers no post-quantum key exchange"
	}
	return ""
}

// Every current browser offers TLS 1.3 and HTTP/2, and Chromium puts a reserved value
// (RFC 8701, written 0a0a by the connector) into its cipher suites. The TLS libraries scripts
// use differ in at least one of these unless they are built to imitate a browser.
func findTLS(claim browserClaim, h http.Header) string {
	hello := clientHello(h)
	if hello == nil {
		return ""
	}
	switch {
	case !slices.Contains(hello[tlsSupportedVersions], "0304"):
		return "does not offer TLS 1.3"
	case !slices.Contains(hello[tlsALPN], "h2"):
		return "does not offer HTTP/2"
	case claim.family == familyChromium && !slices.Contains(hello[tlsCiphers], "0a0a"):
		return "has no reserved value among its cipher suites"
	}
	return ""
}

type browserFamily uint8

const (
	familyNone browserFamily = iota
	familyChromium
	familyFirefox
	familySafari
)

// browserClaim is the browser a User-Agent names.
type browserClaim struct {
	family browserFamily
	major  int
	// system is Windows, macOS, Linux, Android, Chrome OS or iOS, as Sec-CH-UA-Platform names
	// them, or empty.
	system string
	// webview is Android WebView, the browser inside an application.
	webview bool
}

// The versions from which the rules hold. Each browser has sent what the rules look for since
// well before: Chromium since 89, Firefox since 90, Safari since 16.4.
const (
	currentChromium = 100
	currentFirefox  = 100
	currentSafari   = 17
)

// current reports whether the claim is a browser recent enough for the rules to judge.
func (c browserClaim) current() bool {
	switch c.family {
	case familyChromium:
		return c.major >= currentChromium
	case familyFirefox:
		return c.major >= currentFirefox
	case familySafari:
		return c.major >= currentSafari
	}
	return false
}

func (c browserClaim) String() string {
	name := [...]string{familyNone: "unknown", familyChromium: "chromium", familyFirefox: "firefox", familySafari: "safari"}[c.family]
	return name + " " + strconv.Itoa(c.major)
}

// notBrowsers mark a User-Agent that says, in so many words, that it is not a browser:
// crawlers that render pages name the browser they use besides themselves.
var notBrowsers = []string{"compatible;", "bot", "spider", "crawl", "http://", "https://"}

// parseBrowserClaim reads the browser a User-Agent names. It returns the zero claim for
// anything that is not plainly one of the three engines: an unknown client is not judged.
func parseBrowserClaim(ua string) browserClaim {
	var claim browserClaim
	if !strings.HasPrefix(ua, "Mozilla/5.0 (") {
		return claim
	}
	lower := strings.ToLower(ua)
	for _, mark := range notBrowsers {
		if strings.Contains(lower, mark) {
			return claim
		}
	}

	webkit := strings.Contains(ua, "AppleWebKit/")
	// Every browser on iOS is Safari underneath, whatever it calls itself.
	if webkit && strings.Contains(ua, "like Mac OS X") &&
		(strings.Contains(ua, "iPhone") || strings.Contains(ua, "iPad") || strings.Contains(ua, "iPod")) {
		if major, ok := versionAfter(ua, " OS "); ok {
			return browserClaim{family: familySafari, major: major, system: "iOS"}
		}
		return claim
	}

	switch {
	case strings.Contains(ua, "Android"):
		claim.system = "Android"
	case strings.Contains(ua, "Windows NT"):
		claim.system = "Windows"
	case strings.Contains(ua, "CrOS"):
		claim.system = "Chrome OS"
	case strings.Contains(ua, "Macintosh"):
		claim.system = "macOS"
	case strings.Contains(ua, "Linux"), strings.Contains(ua, "X11"):
		claim.system = "Linux"
	}

	switch {
	// The Edge that was not Chromium named a Chrome version too.
	case strings.Contains(ua, "Edge/"):
	case webkit && strings.Contains(ua, "Chrome/"):
		if major, ok := versionAfter(ua, "Chrome/"); ok {
			claim.family, claim.major = familyChromium, major
			claim.webview = strings.Contains(ua, "; wv)")
		}
	case strings.Contains(ua, "Gecko/") && strings.Contains(ua, "Firefox/"):
		if major, ok := versionAfter(ua, "Firefox/"); ok {
			claim.family, claim.major = familyFirefox, major
		}
	case webkit && claim.system == "macOS" && strings.Contains(ua, "Safari/"):
		if major, ok := versionAfter(ua, "Version/"); ok {
			claim.family, claim.major = familySafari, major
		}
	}
	return claim
}

// versionAfter returns the number that follows the first mark in ua.
func versionAfter(ua, mark string) (int, bool) {
	_, rest, found := strings.Cut(ua, mark)
	if !found {
		return 0, false
	}
	end := 0
	for end < len(rest) && end < 4 && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	major, err := strconv.Atoi(rest[:end])
	return major, err == nil
}

// clip shortens a value of the client for the decision log.
func clip(s string) string {
	if len(s) > 32 {
		return s[:32]
	}
	return s
}
