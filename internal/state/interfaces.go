package state

import (
	"net/netip"
	"server_torii/internal/action"
	"server_torii/internal/request"
	"time"
)

// CountryResolver maps an address to its ISO country code.
type CountryResolver = request.CountryResolver

// TrafficMarker lets request handlers report clients the traffic analyzer must not punish.
type TrafficMarker interface {
	MarkVerified(site, ip string, ttl time.Duration)
	MarkNeutral(site, ip string, ttl time.Duration)
}

// BrowserEvidence reports whether the traffic analyzer has recently seen an IP behave like a
// browser on a site.
type BrowserEvidence = request.BrowserEvidence

// RuleSharer tells the other nodes of the cluster about a rule this node installed. It never
// blocks: a rule that cannot be shared now stays local.
type RuleSharer interface {
	ShareRule(site string, kind action.RuleKind, value string, act action.Action, ttl time.Duration)
}

// CrawlerVerifier confirms by DNS that an address belongs to the crawler it claims to be: bot
// names the crawler, domains are the ones its hosts are under. err says why a lookup failed.
type CrawlerVerifier interface {
	Verify(ip netip.Addr, bot string, domains []string) (verified bool, err error)
}
