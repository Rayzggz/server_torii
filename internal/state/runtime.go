// Package state holds the mutable runtime state shared by request handlers and background workers.
package state

import (
	"server_torii/internal/action"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"time"
)

// Analyzer is what request handlers need from the traffic analyzer.
type Analyzer interface {
	dataType.TrafficMarker
	dataType.BrowserEvidence
}

// Runtime is created once at startup and shared for the life of the process.
// Every field is optional: a missing component disables the behavior that depends on it.
type Runtime struct {
	Limiters

	ActionRuleEngine *action.ActionRuleEngine
	CountryResolver  dataType.CountryResolver

	// TrafficMarker and BrowserEvidence are both served by the traffic analyzer once it runs.
	TrafficMarker   dataType.TrafficMarker
	BrowserEvidence dataType.BrowserEvidence

	// NodeName and GossipChan are used to share action rules with peers; a nil channel keeps rules local.
	NodeName   string
	GossipChan chan dataType.GossipMessage
}

// SetAnalyzer registers the running traffic analyzer.
func (rt *Runtime) SetAnalyzer(a Analyzer) {
	rt.TrafficMarker = a
	rt.BrowserEvidence = a
}

// MarkVerified tells the analyzer that ip solved a CAPTCHA.
func (rt *Runtime) MarkVerified(ip string, ttl time.Duration) {
	if rt != nil && rt.TrafficMarker != nil {
		rt.TrafficMarker.MarkVerified(ip, ttl)
	}
}

// MarkNeutral tells the analyzer that ip is trusted for another reason, such as a verified crawler.
func (rt *Runtime) MarkNeutral(ip string, ttl time.Duration) {
	if rt != nil && rt.TrafficMarker != nil {
		rt.TrafficMarker.MarkNeutral(ip, ttl)
	}
}

// HasBrowserEvidence reports whether the analyzer recently saw ip behave like a browser.
func (rt *Runtime) HasBrowserEvidence(ip string) bool {
	return rt != nil && rt.BrowserEvidence != nil && rt.BrowserEvidence.HasBrowserEvidence(ip)
}

// Rule targets understood by ApplyRule.
const (
	RuleTargetIP  = "IP"
	RuleTargetURI = "URI"
)

// ApplyRule installs a temporary action rule on this node and, when broadcast is set, shares it with peers.
// It reports false, doing nothing, when no rule engine is running.
func (rt *Runtime) ApplyRule(target, value string, act action.ActionType, ttl time.Duration, broadcast bool) bool {
	if rt == nil || rt.ActionRuleEngine == nil {
		return false
	}
	if target == RuleTargetIP {
		rt.ActionRuleEngine.AddIPRule(value, act, ttl)
	} else {
		rt.ActionRuleEngine.AddURIRule(value, act, ttl)
	}
	if broadcast {
		utils.BroadcastActionRule(rt.NodeName, target, value, string(act), ttl, rt.GossipChan)
	}
	return true
}

// BlockIP blocks ip on this node and shares the block with peers.
func (rt *Runtime) BlockIP(ip string, ttl time.Duration) bool {
	return rt.ApplyRule(RuleTargetIP, ip, action.ActionBlock, ttl, true)
}
