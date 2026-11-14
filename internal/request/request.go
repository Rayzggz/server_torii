// Package request holds the per-request data every check works on.
package request

import (
	"net/http"
	"net/netip"
	"strings"
)

type UserRequest struct {
	// Site is the ID of the site the request belongs to.
	Site string
	// RemoteIP is the client address as the connector sent it, for logs and error pages. Checks
	// that need the address itself use ClientAddr; anything that counts or remembers clients
	// uses ClientKey.
	RemoteIP string
	// Addr is RemoteIP parsed once when the request arrives. It is the zero Addr when RemoteIP
	// is not an IP address.
	Addr netip.Addr
	// Country is the upper-case ISO code of the client's country, found once when the request
	// arrives. It is empty when the country is not known; CountryUnknown then says why, with one
	// of the Country constants.
	Country        string
	CountryUnknown string
	// Key identifies the client wherever clients are counted or remembered: rate counters,
	// temporary rules, the traffic analyzer. See Key.
	Key string
	Uri string
	// FeatureControl has the feature.Check control bit of every check that is switched on.
	FeatureControl uint16
	// ListOverrides switches lists of the site on or off for this request, by name, whatever
	// the site configuration says. It is nil when the connector asked for none.
	ListOverrides  map[string]bool
	ToriiClearance string
	ToriiSessionID string
	UserAgent      string
	Host           string
	Method         string
	Headers        http.Header // original request headers inherited by the subrequest

	// lookups remembers what HasBrowserEvidence found, so every check of the pipeline shares one
	// lookup. It is nil until ShareLookups; the answer is then not remembered.
	lookups *lookups
}

type lookups struct {
	evidenceDone bool
	evidence     bool
}

// CountryResolver maps an address to its ISO country code.
type CountryResolver interface {
	Country(netip.Addr) (string, error)
}

// BrowserEvidence reports whether an IP has recently behaved like a browser on a site.
type BrowserEvidence interface {
	HasBrowserEvidence(site, ip string) bool
}

// Why ResolveCountry could not name a country.
const (
	CountryInvalidIP       = "invalid_ip"
	CountryNonRoutableIP   = "non_routable_ip"
	CountryMissingResolver = "missing_resolver"
	CountryLookupError     = "lookup_error"
	CountryUnresolved      = "unresolved" // the database has no country for the address
)

// ShareLookups makes the request, and every copy made of it afterwards, remember the answer of
// HasBrowserEvidence. The server calls it once for each request it receives.
func (r *UserRequest) ShareLookups() {
	r.lookups = &lookups{}
}

// ResolveCountry fills Country and CountryUnknown from the client address. The resolver is only
// asked about a public address. The server calls it once for each request it receives, before
// any check runs.
func (r *UserRequest) ResolveCountry(resolver CountryResolver) {
	r.Country, r.CountryUnknown = "", ""
	addr := r.ClientAddr()
	switch {
	case !addr.IsValid():
		r.CountryUnknown = CountryInvalidIP
	case !addr.IsGlobalUnicast() || addr.IsPrivate():
		r.CountryUnknown = CountryNonRoutableIP
	case resolver == nil:
		r.CountryUnknown = CountryMissingResolver
	default:
		country, err := resolver.Country(addr)
		switch {
		case err != nil:
			r.CountryUnknown = CountryLookupError
		case country == "":
			r.CountryUnknown = CountryUnresolved
		default:
			r.Country = strings.ToUpper(country)
		}
	}
}

// HasBrowserEvidence reports whether evidence has recently seen the client behave like a
// browser on the request's site. A nil evidence has seen nothing.
func (r UserRequest) HasBrowserEvidence(evidence BrowserEvidence) bool {
	if r.lookups != nil && r.lookups.evidenceDone {
		return r.lookups.evidence
	}
	found := evidence != nil && evidence.HasBrowserEvidence(r.Site, r.ClientKey())
	if r.lookups != nil {
		r.lookups.evidenceDone, r.lookups.evidence = true, found
	}
	return found
}

// DefaultIPv6PrefixBits is the size of the IPv6 network that counts as one client. A /64 is what
// one subscriber is usually given, and a client can take any address within it at will.
const DefaultIPv6PrefixBits = 64

// Key returns what identifies the client at addr wherever clients are counted or remembered.
//
// An IPv4 address is its own key. An IPv6 address is keyed by the network of v6Bits bits it lies
// in, written as the first address of that network, so every address a client can give itself
// shares one rate counter and one temporary rule. raw, the address as it was received, is the
// key of a client whose address does not parse.
func Key(addr netip.Addr, raw string, v6Bits int) string {
	switch {
	case !addr.IsValid():
		return raw
	case addr.Is4():
		return addr.String()
	}
	network, err := addr.Prefix(v6Bits)
	if err != nil {
		return addr.String()
	}
	return network.Addr().String()
}

// ClientKey returns the client's Key. The server fills it for every request it receives; for a
// request built without it the key is worked out here, with the default IPv6 network size.
func (r UserRequest) ClientKey() string {
	if r.Key != "" {
		return r.Key
	}
	return Key(r.ClientAddr(), r.RemoteIP, DefaultIPv6PrefixBits)
}

// ListEnabled reports whether the action of the list called name applies to the request:
// configured, unless the connector switched the list for this request.
func (r UserRequest) ListEnabled(name string, configured bool) bool {
	if override, ok := r.ListOverrides[name]; ok {
		return override
	}
	return configured
}

// ParseAddr parses a client address. An IPv4-mapped IPv6 address becomes the IPv4 address it
// stands for and a zone is dropped. It returns the zero Addr when s is not an IP address.
func ParseAddr(s string) netip.Addr {
	addr, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return addr.Unmap().WithZone("")
}

// ClientAddr returns the client address, or the zero Addr when the client sent none that parses.
// The server fills Addr for every request it receives; a request built without it is parsed here.
func (r UserRequest) ClientAddr() netip.Addr {
	if r.Addr.IsValid() {
		return r.Addr
	}
	return ParseAddr(r.RemoteIP)
}
