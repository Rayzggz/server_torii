package server

import (
	"fmt"
	"log"
	"math"
	"net"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"sort"
	"strings"
	"time"
)

// IP score weights.
const (
	scoreHotURIBot      = 50
	scoreNoBrowser      = 10
	scoreHighFail       = 50
	scoreScanner        = 50
	scoreRepeatOffense  = 20
	scoreRepeatMax      = 40
	scoreBrowserLike    = -40
	hotURIFocusRatio    = 0.8
	browserHitQuantile  = 0.95
	minQuantileSamples  = 20
	maxDetailedLogLines = 20
)

// trafficDetector separates browser-like clients from bots that hammer a few URIs.
// Browser-like clients form the reference population, so a long-running attack does not
// become the baseline, and no CAPTCHA pass is needed to count as a real user.
type trafficDetector struct{}

type detection struct {
	ctx      *analysisContext
	rule     dataType.AdaptiveTrafficAnalyzerRule
	state    *siteState
	now      time.Time
	window   time.Duration
	halfLife time.Duration
	assets   map[string]struct{}
	enforce  *enforcer
}

func (d *trafficDetector) Analyze(ctx *analysisContext) {
	if ctx.State == nil || ctx.Rule == nil || ctx.Rule.AdaptiveTrafficAnalyzerRule == nil {
		return
	}
	rule := *ctx.Rule.AdaptiveTrafficAnalyzerRule
	config.NormalizeAdaptiveTrafficAnalyzerRule(&rule)
	det := &detection{
		ctx:      ctx,
		rule:     rule,
		state:    ctx.State,
		now:      ctx.Now,
		window:   ctx.Interval * time.Duration(rule.WindowBuckets),
		halfLife: time.Duration(rule.URIDetection.Baseline.HalfLife) * time.Second,
		assets:   toSet(rule.BrowserEvidence.AssetExtensions),
		enforce:  newEnforcer(ctx.SharedMem, rule.IPDetection.MaxBroadcastPerTick),
	}
	det.run()
}

func (det *detection) run() {
	st := det.state
	b := det.buildBucket()
	if b.dropped > 0 {
		det.logf("dropped %d log entries: more than %d IPs in one interval", b.dropped, maxIPsPerBucket)
	}
	st.push(b, det.window, det.rule.WindowBuckets)
	win := st.aggregate(det.rule.IPDetection.ScanPathsThreshold + 1)
	det.updateEvidence(b, win)
	det.updateBaseline(b)
	uris, browserTotal := det.classifyURIs(win)
	hot := det.detectHotURIs(uris, browserTotal)
	det.applyURIActions(hot, uris)
	if det.rule.IPDetection.Enabled {
		det.scoreIPs(win, hot)
	}
	st.sweep(det.now)
	st.pruneBaseline(det.now, det.halfLife)
}

// buildBucket aggregates this interval's logs, skipping exempt traffic entirely.
func (det *detection) buildBucket() *bucket {
	b := &bucket{at: det.now, ips: make(map[string]*ipBucket)}
	exempt := make(map[string]bool)
	scanCap := det.rule.IPDetection.ScanPathsThreshold + 1
	for _, l := range det.ctx.Logs {
		if l.IP == "" || l.URI == "" || det.ignoredRequest(l) {
			continue
		}
		ex, ok := exempt[l.IP]
		if !ok {
			ex = det.exemptIP(l.IP)
			exempt[l.IP] = ex
		}
		if ex {
			continue
		}
		ib := b.ips[l.IP]
		if ib == nil {
			if len(b.ips) >= maxIPsPerBucket {
				b.dropped++
				continue
			}
			ib = &ipBucket{pages: make(map[string]pageHits), okPages: make(map[string]struct{}), errPaths: make(map[string]struct{})}
			b.ips[l.IP] = ib
		}
		canonical := utils.CanonicalizeURI(l.URI)
		ib.total++
		if isClientError(l.Status) {
			ib.clientErr++
			if len(ib.errPaths) < scanCap {
				ib.errPaths[canonical] = struct{}{}
			}
		}
		if isAsset(canonical, det.assets) {
			if l.Status < 400 {
				ib.evidence = true
			}
			continue
		}
		// A conditional request answered 304 comes from a browser cache; bots rarely send one.
		if l.Status == 304 {
			ib.evidence = true
		}
		ib.pageTotal++
		if cur, seen := ib.pages[canonical]; seen || len(ib.pages) < maxPagesPerIP {
			cur.all++
			if isServed(l.Status) {
				cur.served++
			}
			ib.pages[canonical] = cur
		}
		// Raw paths, because grouping would merge page-1 and page-2 of a thread into one page.
		if isServed(l.Status) && len(ib.okPages) < maxPagesPerIP {
			ib.okPages[stripQuery(l.URI)] = struct{}{}
		}
	}
	return b
}

func (det *detection) ignoredRequest(l LogEntry) bool {
	allow := det.ctx.Rule.URLAllowRule
	return allow != nil && allow.List != nil && allow.List.Match(l.URI)
}

func (det *detection) exemptIP(ip string) bool {
	if det.ctx.Marks.active(ip, det.now) {
		return true
	}
	if allow := det.ctx.Rule.IPAllowRule; allow != nil && allow.Trie != nil {
		if parsed := net.ParseIP(ip); parsed != nil && allow.Trie.Search(parsed) {
			return true
		}
	}
	return false
}

func (det *detection) browserLike(ip string) bool {
	return det.ctx.Evidence.active(ip, det.now)
}

func (det *detection) updateEvidence(b *bucket, win map[string]*ipWindow) {
	until := det.now.Add(time.Duration(det.rule.BrowserEvidence.TTL) * time.Second)
	for ip, ib := range b.ips {
		if ib.evidence {
			det.ctx.Evidence.set(ip, until)
		}
	}
	for ip, w := range win {
		// Only pages that exist count, so scanners probing many missing paths do not look like browsing.
		if len(w.okPages) >= det.rule.BrowserEvidence.DistinctPages {
			det.ctx.Evidence.set(ip, until)
		}
	}
}

// updateBaseline learns each page URI's request rate from browser-like clients only.
func (det *detection) updateBaseline(b *bucket) {
	hits := make(map[string]int64)
	for ip, ib := range b.ips {
		if !det.browserLike(ip) {
			continue
		}
		for u, h := range ib.pages {
			hits[u] += h.all
		}
	}
	for u, h := range hits {
		e := det.state.baseline[u]
		if e == nil {
			if len(det.state.baseline) >= maxBaselineURIs {
				continue
			}
			e = &ewma{updated: det.now}
			det.state.baseline[u] = e
		}
		e.observe(det.now, float64(h)/det.ctx.Interval.Seconds(), det.ctx.Interval, det.halfLife)
	}
}

func (det *detection) classifyURIs(win map[string]*ipWindow) (map[string]*uriWindow, int64) {
	uris := make(map[string]*uriWindow)
	var browserTotal int64
	for ip, w := range win {
		browser := det.browserLike(ip)
		if browser {
			browserTotal += w.pageTotal
		}
		for u, ph := range w.pages {
			h := ph.all
			uw := uris[u]
			if uw == nil {
				if len(uris) >= maxWindowURIs {
					continue
				}
				uw = &uriWindow{nonIPs: make(map[string]int64)}
				uris[u] = uw
			}
			if browser {
				uw.browser += h
			} else {
				uw.nonBrowser += h
				uw.nonIPs[ip] += h
			}
		}
	}
	return uris, browserTotal
}

// expectedBrowser is the baseline number of browser-like requests to uri over the window.
func (det *detection) expectedBrowser(uri string) float64 {
	e := det.state.baseline[uri]
	if e == nil {
		return 0
	}
	return e.at(det.now, det.halfLife) * det.window.Seconds()
}

// Hot URI detection modes.
const (
	modePaused   = "paused"
	modeFallback = "fallback"
	modeBaseline = "baseline"
)

// detectHotURIs returns URIs that met the hot condition for the configured sustain period.
func (det *detection) detectHotURIs(uris map[string]*uriWindow, browserTotal int64) map[string]bool {
	cfg := det.rule.URIDetection.Baseline
	age := det.now.Sub(det.state.created)
	mode := modePaused
	switch {
	case age >= time.Duration(cfg.Warmup)*time.Second && browserTotal >= cfg.MinReferenceRequests:
		mode = modeBaseline
	case age >= det.window:
		// Browser evidence has had one window to accumulate; judge by share until the baseline is ready.
		mode = modeFallback
	}
	if mode != det.state.mode {
		det.state.mode = mode
		switch mode {
		case modeBaseline:
			det.logf("hot URI detection using reference baseline")
		case modeFallback:
			det.logf("hot URI detection using non-browser share >= %.0f%% until the baseline is ready (browser-like requests in window: %d, need %d)",
				det.rule.URIDetection.FallbackShare*100, browserTotal, cfg.MinReferenceRequests)
		default:
			det.logf("hot URI detection paused while browser evidence accumulates")
		}
	}

	var candidates map[string]bool
	switch mode {
	case modeBaseline:
		candidates = det.baselineCandidates(uris)
	case modeFallback:
		candidates = det.fallbackCandidates(uris)
	}
	return det.sustained(candidates, uris)
}

// sustained keeps candidates whose non-browser traffic kept arriving in every interval of the
// sustain period. The window alone would keep a short burst looking hot until it ages out.
func (det *detection) sustained(candidates map[string]bool, uris map[string]*uriWindow) map[string]bool {
	hot := make(map[string]bool)
	if len(candidates) == 0 {
		return hot
	}
	need := int(math.Ceil(float64(det.rule.URIDetection.Sustain) / det.ctx.Interval.Seconds()))
	if need > len(det.state.buckets) {
		return hot
	}
	recent := det.state.buckets[len(det.state.buckets)-need:]
	if det.now.Sub(recent[0].at) >= time.Duration(need)*det.ctx.Interval {
		return hot // intervals without logs inside the sustain period
	}
	for u := range candidates {
		// Each interval must carry at least a quarter of the URI's average non-browser rate.
		perInterval := max(1, uris[u].nonBrowser/int64(det.rule.WindowBuckets)/4)
		ok := true
		for _, b := range recent {
			var n int64
			for ip, ib := range b.ips {
				if h := ib.pages[u].all; h > 0 && !det.browserLike(ip) {
					n += h
				}
			}
			if n < perInterval {
				ok = false
				break
			}
		}
		if ok {
			hot[u] = true
		}
	}
	return hot
}

// fallbackCandidates judges URIs by how much of their traffic comes from non-browser clients.
func (det *detection) fallbackCandidates(uris map[string]*uriWindow) map[string]bool {
	hc := det.rule.URIDetection
	candidates := make(map[string]bool)
	for u, uw := range uris {
		if uw.nonBrowser < hc.MinRequests || len(uw.nonIPs) < hc.MinDistinctIPs {
			continue
		}
		if float64(uw.nonBrowser) >= hc.FallbackShare*float64(uw.nonBrowser+uw.browser) {
			candidates[u] = true
		}
	}
	return candidates
}

// baselineCandidates finds URIs whose non-browser traffic far exceeds the site's normal mix.
func (det *detection) baselineCandidates(uris map[string]*uriWindow) map[string]bool {

	// The normal non-browser:browser mix, robust to attacks concentrated on a few URIs.
	var ratios, weights []float64
	for u := range det.state.baseline {
		expected := det.expectedBrowser(u)
		if expected < 1 {
			continue
		}
		var non int64
		if uw := uris[u]; uw != nil {
			non = uw.nonBrowser
		}
		ratios = append(ratios, float64(non)/expected)
		weights = append(weights, expected)
	}
	mix := weightedMedian(ratios, weights)

	hc := det.rule.URIDetection
	candidates := make(map[string]bool)
	for u, uw := range uris {
		if uw.nonBrowser < hc.MinRequests || len(uw.nonIPs) < hc.MinDistinctIPs {
			continue
		}
		expected := mix * math.Max(det.expectedBrowser(u), 1)
		if float64(uw.nonBrowser) >= hc.RatioThreshold*expected {
			candidates[u] = true
		}
	}
	return candidates
}

func (det *detection) applyURIActions(hot map[string]bool, uris map[string]*uriWindow) {
	cfg := det.rule.URIDetection
	dur := time.Duration(cfg.BlockDuration) * time.Second
	for _, u := range sortedKeys(hot) {
		// Renew only once less than half of the previous duration remains.
		if until, ok := det.state.uriRules[u]; ok && until.Sub(det.now) > dur/2 {
			continue
		}
		det.state.uriRules[u] = det.now.Add(dur)
		uw := uris[u]
		det.enforce.apply("URI", u, cfg.Action, dur, false)
		det.logf("%s hot URI %s for %v (non-browser %d from %d IPs, browser %d, baseline %.1f, mode %s)",
			actionVerb(cfg.Action), u, dur, uw.nonBrowser, len(uw.nonIPs), uw.browser, det.expectedBrowser(u), det.state.mode)
	}
}

type ipCandidate struct {
	ip      string
	score   int
	reasons []string
}

// hotHitThresholds sets, per hot URI, how many served window hits mark a non-browser client:
// more than browserHitQuantile of browser-like clients received, and at least HotURIMinHits.
func (det *detection) hotHitThresholds(win map[string]*ipWindow, hot map[string]bool) map[string]int64 {
	samples := make(map[string][]int64, len(hot))
	for ip, w := range win {
		if !det.browserLike(ip) {
			continue
		}
		for u := range hot {
			if h := w.pages[u].served; h > 0 {
				samples[u] = append(samples[u], h)
			}
		}
	}
	thresholds := make(map[string]int64, len(hot))
	for u := range hot {
		threshold := det.rule.IPDetection.HotURIMinHits
		if hits := samples[u]; len(hits) >= minQuantileSamples {
			sort.Slice(hits, func(i, j int) bool { return hits[i] < hits[j] })
			idx := int(math.Ceil(browserHitQuantile*float64(len(hits)))) - 1
			threshold = max(threshold, hits[idx]+1)
		}
		thresholds[u] = threshold
	}
	return thresholds
}

func (det *detection) scoreIPs(win map[string]*ipWindow, hot map[string]bool) {
	cfg := det.rule.IPDetection
	thresholds := det.hotHitThresholds(win, hot)
	var candidates []ipCandidate
	for ip, w := range win {
		if det.ctx.Marks.active(ip, det.now) || det.enforce.hasIPRule(ip) {
			continue
		}
		off := det.state.offenders[ip]
		if off != nil && det.now.Before(off.until) {
			continue
		}
		score, reasons := 0, []string(nil)
		add := func(points int, reason string) {
			score += points
			reasons = append(reasons, reason)
		}
		browser := det.browserLike(ip)
		// Only served hits count: a request already answered by a challenge or redirect needs no
		// further action, and real users retrying a challenge must not look like bots.
		var hotHits int64
		overURI, overHits, overThreshold := "", int64(0), int64(0)
		for u, ph := range w.pages {
			if !hot[u] {
				continue
			}
			hotHits += ph.served
			if ph.served >= thresholds[u] && ph.served > overHits {
				overURI, overHits, overThreshold = u, ph.served, thresholds[u]
			}
		}
		if !browser && overURI != "" && float64(hotHits) >= hotURIFocusRatio*float64(w.served) {
			add(scoreHotURIBot, fmt.Sprintf("hot_uri_bot(%s %d served hits, threshold %d, %d/%d served pages)",
				overURI, overHits, overThreshold, hotHits, w.served))
		}
		if !browser && w.pageTotal >= cfg.HotURIMinHits {
			add(scoreNoBrowser, "no_browser")
		}
		if w.clientErr >= cfg.MinFailures && wilsonLower(w.clientErr, w.total) >= cfg.FailRateThreshold {
			add(scoreHighFail, fmt.Sprintf("high_fail(%d/%d)", w.clientErr, w.total))
		}
		if len(w.errPaths) >= cfg.ScanPathsThreshold {
			add(scoreScanner, fmt.Sprintf("scanner(%d paths)", len(w.errPaths)))
		}
		if n := off.recent(det.now); n > 0 {
			add(min(n*scoreRepeatOffense, scoreRepeatMax), fmt.Sprintf("repeat_offender(%d)", n))
		}
		if browser {
			add(scoreBrowserLike, "browser_like")
		}
		if score >= cfg.ScoreThreshold {
			candidates = append(candidates, ipCandidate{ip, score, reasons})
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].score != candidates[j].score {
			return candidates[i].score > candidates[j].score
		}
		return candidates[i].ip < candidates[j].ip
	})

	base := time.Duration(cfg.BlockDuration) * time.Second
	maxDur := time.Duration(cfg.MaxBlockDuration) * time.Second
	for i, c := range candidates {
		off := det.state.offenders[c.ip]
		if off == nil {
			off = &offender{}
			det.state.offenders[c.ip] = off
		}
		dur := escalate(base, maxDur, off.recent(det.now))
		kept := off.times[:0]
		for _, t := range off.times {
			if det.now.Sub(t) < offenseMemory {
				kept = append(kept, t)
			}
		}
		off.times = append(kept, det.now)
		off.until = det.now.Add(dur)
		det.enforce.apply("IP", c.ip, cfg.Action, dur, true)
		if i < maxDetailedLogLines {
			det.logf("%s IP %s for %v (score %d: %s)", actionVerb(cfg.Action), c.ip, dur, c.score, strings.Join(c.reasons, ", "))
		}
	}
	if len(candidates) > maxDetailedLogLines {
		det.logf("%s %d more IPs this interval", actionVerb(cfg.Action), len(candidates)-maxDetailedLogLines)
	}
	if det.enforce.suppressed > 0 {
		det.logf("applied %d IP rules locally only: gossip broadcast limit %d per interval reached",
			det.enforce.suppressed, cfg.MaxBroadcastPerTick)
	}
}

// escalate doubles the base duration for each recent prior offense, up to maxDur.
func escalate(base, maxDur time.Duration, prior int) time.Duration {
	dur := base
	for i := 0; i < prior && dur < maxDur; i++ {
		dur *= 2
	}
	return min(dur, maxDur)
}

func (det *detection) logf(format string, args ...any) {
	log.Printf("[AdaptiveTrafficAnalyzer] [%s] %s", det.rule.Tag, fmt.Sprintf(format, args...))
}

// enforcer turns detections into action rules and gossip broadcasts.
type enforcer struct {
	engine       *action.ActionRuleEngine
	gossip       chan dataType.GossipMessage
	maxBroadcast int
	broadcasts   int
	suppressed   int
}

func newEnforcer(sharedMem *dataType.SharedMemory, maxBroadcast int) *enforcer {
	e := &enforcer{maxBroadcast: maxBroadcast}
	if sharedMem != nil {
		e.engine, _ = sharedMem.ActionRuleEngine.(*action.ActionRuleEngine)
		e.gossip = sharedMem.GossipChan
	}
	return e
}

func (e *enforcer) hasIPRule(ip string) bool {
	return e.engine != nil && e.engine.HasIPRule(ip)
}

// apply records the rule. limited broadcasts count toward maxBroadcast; the rest stay local.
func (e *enforcer) apply(ruleType, value string, act dataType.AnalyzerAction, dur time.Duration, limited bool) {
	var at action.ActionType
	switch act {
	case dataType.AnalyzerCaptchaUnverified:
		at = action.ActionCaptchaUnverified
	case dataType.AnalyzerCaptcha:
		at = action.ActionCaptcha
	case dataType.AnalyzerBlock:
		at = action.ActionBlock
	default:
		return
	}
	if e.engine == nil {
		return
	}
	if ruleType == "IP" {
		e.engine.AddIPRule(value, at, dur)
	} else {
		e.engine.AddURIRule(value, at, dur)
	}
	if limited {
		if e.broadcasts >= e.maxBroadcast {
			e.suppressed++
			return
		}
		e.broadcasts++
	}
	nodeName := ""
	if config.GlobalConfig != nil {
		nodeName = config.GlobalConfig.NodeName
	}
	utils.BroadcastActionRule(nodeName, ruleType, value, string(at), dur, e.gossip)
}

func actionVerb(act dataType.AnalyzerAction) string {
	switch act {
	case dataType.AnalyzerCaptchaUnverified:
		return "CAPTCHA (clients without browser evidence)"
	case dataType.AnalyzerCaptcha:
		return "CAPTCHA (every visitor)"
	case dataType.AnalyzerBlock:
		return "BLOCK"
	default:
		return "[observe] would act on"
	}
}

func toSet(items []string) map[string]struct{} {
	set := make(map[string]struct{}, len(items))
	for _, s := range items {
		set[s] = struct{}{}
	}
	return set
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
