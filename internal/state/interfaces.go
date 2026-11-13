package state

import (
	"net/netip"
	"time"
)

// CountryResolver maps an address to its ISO country code.
type CountryResolver interface {
	Country(netip.Addr) (string, error)
}

// TrafficMarker lets request handlers report clients the traffic analyzer must not punish.
type TrafficMarker interface {
	MarkVerified(ip string, ttl time.Duration)
	MarkNeutral(ip string, ttl time.Duration)
}

// BrowserEvidence reports whether the traffic analyzer has recently seen an IP behave like a browser.
type BrowserEvidence interface {
	HasBrowserEvidence(ip string) bool
}
