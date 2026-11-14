// Package state holds the mutable runtime state shared by request handlers and background workers.
package state

import (
	"server_torii/internal/action"
	"server_torii/internal/gossip"
	"time"
)

// Analyzer is what request handlers need from the traffic analyzer.
type Analyzer interface {
	TrafficMarker
	BrowserEvidence
}

// Runtime is created once at startup and shared for the life of the process.
// Every field is optional: a missing component disables the behavior that depends on it.
type Runtime struct {
	SiteLimiters

	ActionRuleEngine *action.ActionRuleEngine
	CountryResolver  CountryResolver

	// TrafficMarker and BrowserEvidence are both served by the traffic analyzer once it runs.
	TrafficMarker   TrafficMarker
	BrowserEvidence BrowserEvidence

	// NodeName and GossipChan are used to share action rules with peers; a nil channel keeps rules local.
	NodeName   string
	GossipChan chan gossip.Message
}

// SetAnalyzer registers the running traffic analyzer.
func (rt *Runtime) SetAnalyzer(a Analyzer) {
	rt.TrafficMarker = a
	rt.BrowserEvidence = a
}

// MarkVerified tells the analyzer that ip solved a CAPTCHA on site.
func (rt *Runtime) MarkVerified(site, ip string, ttl time.Duration) {
	if rt != nil && rt.TrafficMarker != nil {
		rt.TrafficMarker.MarkVerified(site, ip, ttl)
	}
}

// MarkNeutral tells the analyzer that site trusts ip for another reason, such as a verified crawler.
func (rt *Runtime) MarkNeutral(site, ip string, ttl time.Duration) {
	if rt != nil && rt.TrafficMarker != nil {
		rt.TrafficMarker.MarkNeutral(site, ip, ttl)
	}
}

// HasBrowserEvidence reports whether the analyzer recently saw ip behave like a browser on site.
func (rt *Runtime) HasBrowserEvidence(site, ip string) bool {
	return rt != nil && rt.BrowserEvidence != nil && rt.BrowserEvidence.HasBrowserEvidence(site, ip)
}

// Rule targets understood by ApplyRule.
const (
	RuleTargetIP  = "IP"
	RuleTargetURI = "URI"
)

// ApplyRule installs a temporary action rule for one site on this node and, when broadcast is set,
// shares it with peers. It reports false, doing nothing, when no rule engine is running.
func (rt *Runtime) ApplyRule(site, target, value string, act action.ActionType, ttl time.Duration, broadcast bool) bool {
	if rt == nil || rt.ActionRuleEngine == nil {
		return false
	}
	if target == RuleTargetIP {
		rt.ActionRuleEngine.AddIPRule(site, value, act, ttl)
	} else {
		rt.ActionRuleEngine.AddURIRule(site, value, act, ttl)
	}
	if broadcast {
		gossip.BroadcastActionRule(rt.NodeName, site, target, value, string(act), ttl, rt.GossipChan)
	}
	return true
}

// BlockIP blocks ip on one site of this node and shares the block with peers.
func (rt *Runtime) BlockIP(site, ip string, ttl time.Duration) bool {
	return rt.ApplyRule(site, RuleTargetIP, ip, action.ActionBlock, ttl, true)
}
