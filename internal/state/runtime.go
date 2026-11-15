// Package state holds the mutable runtime state shared by request handlers and background workers.
package state

import (
	"context"
	"log/slog"
	"server_torii/internal/action"
	"server_torii/internal/logx"
	"server_torii/internal/ratelimit"
	"server_torii/internal/request"
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

	// Crawlers verifies the clients that claim to be crawlers; nil leaves the claims unchecked.
	Crawlers CrawlerVerifier

	// Peers shares the rules this node installs with the other nodes of the cluster; nil keeps
	// them local.
	Peers RuleSharer

	// Logs are the log files of the node; nil logs nothing.
	Logs *logx.Logs
}

// Log returns the logger of the node itself. It is never nil.
func (rt *Runtime) Log() *slog.Logger {
	if rt == nil {
		return (*logx.Logs)(nil).Node()
	}
	return rt.Logs.Node()
}

// SiteLog returns the event logger of one site. It is never nil.
func (rt *Runtime) SiteLog(site string) *slog.Logger {
	if rt == nil {
		return (*logx.Logs)(nil).Site(site)
	}
	return rt.Logs.Site(site)
}

// Event writes one line about a request to the events of its site: the client, then attrs,
// then what the client asked for. The user agent is last: it is the longest and the least read.
func (rt *Runtime) Event(req request.UserRequest, level slog.Level, msg string, attrs ...slog.Attr) {
	logger := rt.SiteLog(req.Site)
	ctx := context.Background()
	if !logger.Enabled(ctx, level) {
		return
	}
	all := make([]slog.Attr, 0, 6+len(attrs))
	all = append(all, slog.String("ip", req.RemoteIP))
	if req.Country != "" {
		all = append(all, slog.String("country", req.Country))
	}
	all = append(all, attrs...)
	all = append(all, slog.String("method", req.Method), slog.String("host", req.Host),
		slog.String("uri", req.Uri), slog.String("ua", req.UserAgent))
	logger.LogAttrs(ctx, level, msg, all...)
}

// Error writes an error met while serving a request to the events of its site.
func (rt *Runtime) Error(req request.UserRequest, msg string, attrs ...slog.Attr) {
	rt.Event(req, slog.LevelError, msg, attrs...)
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

// ApplyRule installs a temporary action rule for one site on this node and, when broadcast is set,
// shares it with peers. It reports false, doing nothing, when no rule engine is running.
func (rt *Runtime) ApplyRule(site string, kind action.RuleKind, value string, act action.Action, ttl time.Duration, broadcast bool) bool {
	if rt == nil || rt.ActionRuleEngine == nil {
		return false
	}
	rt.ActionRuleEngine.AddRule(site, kind, value, act, ttl)
	if broadcast && rt.Peers != nil {
		rt.Peers.ShareRule(site, kind, value, act, ttl)
	}
	return true
}

// BlockIP blocks ip on one site of this node and shares the block with peers.
func (rt *Runtime) BlockIP(site, ip string, ttl time.Duration) bool {
	return rt.ApplyRule(site, action.RuleIP, ip, action.ActionBlock, ttl, true)
}

// RunGC drops expired records from the rate counters every interval until ctx is done, and
// logs when the counters were full since the last time.
func (rt *Runtime) RunGC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var reported uint64
	for {
		select {
		case <-ticker.C:
			rt.GC()
			if total := rt.Untracked(); total > reported {
				rt.Log().Warn("rate counters full: requests of new clients were not counted and not limited",
					"requests", total-reported, "keys_per_counter", ratelimit.DefaultMaxKeys)
				reported = total
			} else {
				reported = total
			}
		case <-ctx.Done():
			return
		}
	}
}
