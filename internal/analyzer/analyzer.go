package analyzer

import (
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/request"
	"server_torii/internal/state"
	"sync"
	"sync/atomic"
	"time"
)

// LogEntry is one served request as the connector reported it.
//
// Site, IP, URI, Status, Decision and ContentType drive the analysis, and they are all that
// is kept of a report until its interval is analyzed. The remaining fields are for detections
// that do not exist yet; nothing reads them so far.
type LogEntry struct {
	Site   string // ID of the site, resolved: never empty once the entry is in the buffer
	IP     string
	URI    string
	Status int
	// Timestamp is when the request ended according to the sender, in milliseconds. Analysis
	// windows are built from arrival time instead, which the sender cannot influence.
	Timestamp int64

	Host     string
	Method   string
	Decision string // Torii's decision; empty when the request was not checked
	Reason   string

	UserAgent    string
	Referer      string
	Proto        string
	ConnRequests int64  // requests made over the connection so far
	Fetch        string // Sec-Fetch-Dest/Mode/Site
	HasLanguage  bool   // the client sent Accept-Language
	ContentType  string // of the response
	// Incomplete says that the response was not sent to its end, which Status does not tell: a
	// client that goes away while the body is sent leaves the status of the response it got.
	Incomplete bool

	RequestTime  time.Duration
	UpstreamTime time.Duration
	// UpstreamConnectTime is how long connecting to the upstream took, and UpstreamHeaderTime
	// how long it took the upstream to send its response header, counted from the same moment.
	UpstreamConnectTime time.Duration
	UpstreamHeaderTime  time.Duration
	UpstreamStatus      int
	Cache               string
	Bytes               int64
	RequestLength       int64
}

// answeredByTorii reports whether the response came from Torii (a block, challenge, rate limit
// or redirect) instead of the site. Such a response says what Torii decided, not how the site
// reacted to the client, so it is neither a failure of the client nor a sign of a browser.
func (e *LogEntry) answeredByTorii() bool {
	return e.Decision != "" && e.Decision != action.VerdictAllow.String()
}

// What the analyzer holds of the reports that wait to be analyzed. Reports arrive as fast as
// requests are served, so without a limit a flood is held in memory for a whole interval.
const (
	// maxBufferedReports is how many reports wait for the next tick, a second away.
	maxBufferedReports = 1_000_000
	// maxReportsPerInterval is how many reports of one site are kept for one analysis. The
	// detections count requests and clients in the hundreds; a site that sends more than this
	// in an interval is judged on the first of them.
	maxReportsPerInterval = 200_000
)

// LogBuffer is a thread-safe buffer for LogEntries. It holds a limited number of them.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	limit   int
}

func NewLogBuffer() *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, 0, 1000),
		limit:   maxBufferedReports,
	}
}

// Add reports whether the entry was taken; it is not when the buffer is full.
func (lb *LogBuffer) Add(entry LogEntry) bool {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	if len(lb.entries) >= lb.limit {
		return false
	}
	lb.entries = append(lb.entries, entry)
	return true
}

func (lb *LogBuffer) Swap() []LogEntry {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	current := lb.entries
	lb.entries = make([]LogEntry, 0, 1000)
	return current
}

// Analyzer interface for specific traffic analysis logic
type Analyzer interface {
	Analyze(ctx *analysisContext)
}

// analysisContext carries one site's due window to an Analyzer.
type analysisContext struct {
	Logs     []LogEntry
	Rule     *config.RuleSet
	State    *siteState
	Runtime  *state.Runtime
	Marks    *ipExpiry // the site's exempt clients
	Evidence *ipExpiry // the site's browser-like clients
	Now      time.Time
	Interval time.Duration
}

type AdaptiveTrafficAnalyzer struct {
	buffer      *LogBuffer
	analyzers   []Analyzer
	rt          *state.Runtime
	configs     *config.Manager
	stopCh      chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
	workers     sync.WaitGroup
	lifecycleMu sync.Mutex
	processMu   sync.Mutex
	windows     map[string]*analysisWindow
	marks       *siteExpiry // exempt clients, per site
	evidence    *siteExpiry // browser-like clients, per site
	ingest      sync.Map    // *config.AdaptiveTrafficAnalyzerRule -> *ingestSettings
	// IPv6PrefixBits is the size of the IPv6 network that counts as one client; zero means the
	// default. Set it before Start.
	IPv6PrefixBits int
	lastSweep      time.Time
	// discarded counts the reports that were not analyzed because too many were waiting.
	discarded atomic.Uint64
	// reportsPerInterval is maxReportsPerInterval, lower in tests.
	reportsPerInterval int
}

// Discarded returns how many reports were not analyzed because too many were waiting.
func (ata *AdaptiveTrafficAnalyzer) Discarded() uint64 {
	if ata == nil {
		return 0
	}
	return ata.discarded.Load()
}

// ingestSettings is the part of a rule needed to record browser evidence as logs arrive.
type ingestSettings struct {
	assets map[string]struct{}
	ttl    time.Duration
}

type analysisWindow struct {
	// discarded counts the reports of this interval that did not fit in logs.
	discarded int
	interval  time.Duration
	start     time.Time
	next      time.Time
	logs      []LogEntry
	state     *siteState
}

// NewAdaptiveTrafficAnalyzer builds an analyzer that reads site rules from configs and enforces through rt.
// Either may be nil: without configs nothing is analyzed, without rt detections are only logged.
func NewAdaptiveTrafficAnalyzer(rt *state.Runtime, configs *config.Manager) *AdaptiveTrafficAnalyzer {
	return &AdaptiveTrafficAnalyzer{
		buffer:    NewLogBuffer(),
		analyzers: []Analyzer{&trafficDetector{}},
		rt:        rt,
		configs:   configs,
		stopCh:    make(chan struct{}),
		windows:   make(map[string]*analysisWindow),
		marks:     newSiteExpiry(maxMarkedClients),
		evidence:  newSiteExpiry(maxEvidenceEntries),
	}
}

func (ata *AdaptiveTrafficAnalyzer) Start() {
	ata.lifecycleMu.Lock()
	defer ata.lifecycleMu.Unlock()
	select {
	case <-ata.stopCh:
		return
	default:
	}
	ata.startOnce.Do(func() {
		ata.ProcessBatch() // Establish windows at startup, even without traffic.
		ticker := time.NewTicker(time.Second)
		ata.workers.Add(1)
		go func() {
			defer ata.workers.Done()
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					ata.ProcessBatch()
				case <-ata.stopCh:
					return
				}
			}
		}()
		ata.rt.Log().Info("traffic analyzer started")
	})
}

func (ata *AdaptiveTrafficAnalyzer) Stop() {
	ata.lifecycleMu.Lock()
	ata.stopOnce.Do(func() { close(ata.stopCh) })
	ata.lifecycleMu.Unlock()
	ata.workers.Wait()
}

// submit takes a reported request whose site is as the connector sent it. It reports false,
// keeping nothing, when the site does not exist or has traffic analysis switched off.
func (ata *AdaptiveTrafficAnalyzer) submit(entry LogEntry) bool {
	snap := ata.configs.Get()
	if snap == nil {
		return false
	}
	rules := snap.Site(entry.Site)
	if !analyzed(rules) {
		return false
	}
	entry.Site = rules.ID
	addr := request.ParseAddr(entry.IP)
	// An allow list is asked about the address of the client, as the Lists check asks it: the
	// key below is the network of the client, which an entry for one address does not hold.
	// The traffic of such a client is not analyzed.
	if rules.Lists.AllowsAddr(addr) {
		return true
	}
	// The same key the checks count the client under, so a rule made here matches its requests.
	entry.IP = request.Key(addr, entry.IP, ata.ipv6PrefixBits())
	ata.AddLog(entry)
	return true
}

func (ata *AdaptiveTrafficAnalyzer) ipv6PrefixBits() int {
	if ata.IPv6PrefixBits > 0 {
		return ata.IPv6PrefixBits
	}
	return request.DefaultIPv6PrefixBits
}

// analyzed reports whether the site exists and has traffic analysis switched on.
func analyzed(rules *config.RuleSet) bool {
	return rules != nil && rules.AdaptiveTrafficAnalyzerRule != nil && rules.AdaptiveTrafficAnalyzerRule.Enabled
}

func (ata *AdaptiveTrafficAnalyzer) AddLog(entry LogEntry) {
	ata.recordEvidence(entry, time.Now())
	// Only what the analysis reads is kept: a report can carry kilobytes of URI, user agent
	// and referer, and it waits here for up to an interval.
	kept := LogEntry{
		Site: entry.Site, IP: entry.IP, URI: entry.URI, Status: entry.Status,
		Decision: entry.Decision, ContentType: entry.ContentType,
	}
	if !ata.buffer.Add(kept) {
		ata.discarded.Add(1)
	}
}

// recordEvidence marks browser evidence as soon as a log arrives, so a page view followed
// quickly by a click onto a challenged URI is not challenged while waiting for the next analysis.
func (ata *AdaptiveTrafficAnalyzer) recordEvidence(entry LogEntry, now time.Time) {
	if entry.IP == "" || entry.Status >= 400 || entry.answeredByTorii() {
		return
	}
	rules := ata.siteRules(entry.Site)
	if rules == nil {
		return
	}
	settings := ata.ingestSettingsFor(rules.AdaptiveTrafficAnalyzerRule)
	if entry.Status == 304 || isAsset(stripQuery(entry.URI), settings.assets) || isAssetContentType(entry.ContentType) {
		ata.evidence.site(entry.Site).set(entry.IP, now.Add(settings.ttl))
	}
}

func (ata *AdaptiveTrafficAnalyzer) ingestSettingsFor(rule *config.AdaptiveTrafficAnalyzerRule) *ingestSettings {
	if cached, ok := ata.ingest.Load(rule); ok {
		return cached.(*ingestSettings)
	}
	normalized := *rule
	config.NormalizeAdaptiveTrafficAnalyzerRule(&normalized)
	settings := &ingestSettings{
		assets: toSet(normalized.BrowserEvidence.AssetExtensions),
		ttl:    normalized.BrowserEvidence.TTL,
	}
	ata.ingest.Store(rule, settings)
	return settings
}

// Evidence and marks belong to one site: what a client did, or proved, on one site says nothing
// about its traffic to another.

// HasBrowserEvidence reports whether the IP recently loaded assets, revalidated a page, or
// browsed several pages on the site.
func (ata *AdaptiveTrafficAnalyzer) HasBrowserEvidence(site, ip string) bool {
	return ata.evidence.existing(site).active(ip, time.Now())
}

// Marked reports whether the IP is exempt from the site's analysis at the given time.
func (ata *AdaptiveTrafficAnalyzer) Marked(site, ip string, at time.Time) bool {
	return ata.marks.existing(site).active(ip, at)
}

// MarkVerified exempts an IP that solved a CAPTCHA on the site.
func (ata *AdaptiveTrafficAnalyzer) MarkVerified(site, ip string, ttl time.Duration) {
	ata.mark(site, ip, ttl)
}

// MarkNeutral exempts an IP the site trusts for another reason, such as a verified crawler.
func (ata *AdaptiveTrafficAnalyzer) MarkNeutral(site, ip string, ttl time.Duration) {
	ata.mark(site, ip, ttl)
}

func (ata *AdaptiveTrafficAnalyzer) mark(site, ip string, ttl time.Duration) {
	ata.marks.site(site).set(ip, time.Now().Add(ttl))
}

func (ata *AdaptiveTrafficAnalyzer) ProcessBatch() {
	ata.processBatchAt(time.Now())
}

// processBatchAt uses collection time, rather than timestamps supplied by logs.
func (ata *AdaptiveTrafficAnalyzer) processBatchAt(now time.Time) {
	ata.processMu.Lock()
	defer ata.processMu.Unlock()
	select {
	case <-ata.stopCh:
		return
	default:
	}
	logs := ata.buffer.Swap()
	if now.Sub(ata.lastSweep) >= sweepInterval {
		ata.marks.sweep(now)
		ata.evidence.sweep(now)
		ata.ingest.Clear() // drop settings of replaced rules
		ata.lastSweep = now
	}
	snap := ata.configs.Get()
	if snap == nil {
		clear(ata.windows)
		return
	}
	logsBySite := make(map[string][]LogEntry)
	for _, l := range logs {
		logsBySite[l.Site] = append(logsBySite[l.Site], l)
	}
	for site := range ata.windows {
		if !analyzed(snap.SiteRules[site]) {
			delete(ata.windows, site)
		}
	}
	for site, rules := range snap.SiteRules {
		if !analyzed(rules) {
			continue
		}
		rule := rules.AdaptiveTrafficAnalyzerRule
		interval := rule.AnalysisInterval
		if interval <= 0 {
			interval = config.DefaultATAAnalysisInterval
		}
		window := ata.windows[site]
		if window == nil {
			window = &analysisWindow{start: now, state: newSiteState(now)}
			ata.windows[site] = window
		}
		if window.interval != interval {
			window.interval = interval
			window.next = window.start.Add(interval)
		}
		arrived := logsBySite[site]
		limit := ata.reportsPerInterval
		if limit <= 0 {
			limit = maxReportsPerInterval
		}
		if room := limit - len(window.logs); len(arrived) > room {
			window.discarded += len(arrived) - room
			ata.discarded.Add(uint64(len(arrived) - room))
			arrived = arrived[:room]
		}
		window.logs = append(window.logs, arrived...)
		if now.Before(window.next) {
			continue
		}
		if window.discarded > 0 {
			ata.rt.SiteLog(site).Warn("request reports discarded: more than the analyzer keeps for one interval; the interval is judged on the first of them",
				"source", "traffic_analyzer", "discarded", window.discarded, "kept", len(window.logs))
			window.discarded = 0
		}
		if len(window.logs) > 0 {
			ctx := &analysisContext{
				Logs:     window.logs,
				Rule:     rules,
				State:    window.state,
				Runtime:  ata.rt,
				Marks:    ata.marks.site(site),
				Evidence: ata.evidence.site(site),
				Now:      now,
				Interval: interval,
			}
			for _, analyzer := range ata.analyzers {
				analyzer.Analyze(ctx)
			}
		}
		window.logs = nil
		// Skip missed boundaries without analyzing the same batch repeatedly.
		window.start = window.next.Add((now.Sub(window.next) / interval) * interval)
		window.next = window.start.Add(interval)
	}
}

// siteRules returns the rules of the site with the given ID when its traffic is analyzed.
func (ata *AdaptiveTrafficAnalyzer) siteRules(site string) *config.RuleSet {
	snap := ata.configs.Get()
	if snap == nil {
		return nil
	}
	if rules := snap.SiteRules[site]; analyzed(rules) {
		return rules
	}
	return nil
}

// siteExpiry holds one ipExpiry per site, each bounded on its own so a flood of addresses on
// one site cannot use up the room of another.
type siteExpiry struct {
	mu    sync.RWMutex
	sites map[string]*ipExpiry
	limit int
}

func newSiteExpiry(limit int) *siteExpiry {
	return &siteExpiry{sites: make(map[string]*ipExpiry), limit: limit}
}

// existing returns the site's entries, or nil, which is an empty set, when it has none.
func (s *siteExpiry) existing(site string) *ipExpiry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sites[site]
}

// site returns the site's entries, creating them when needed.
func (s *siteExpiry) site(site string) *ipExpiry {
	if m := s.existing(site); m != nil {
		return m
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	m := s.sites[site]
	if m == nil {
		m = newIPExpiry(s.limit)
		s.sites[site] = m
	}
	return m
}

// sweep drops expired entries, and sites left without any, such as ones removed from the configuration.
func (s *siteExpiry) sweep(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for site, m := range s.sites {
		if m.sweep(now) == 0 {
			delete(s.sites, site)
		}
	}
}

// ipExpiry holds IPs until an expiry time, bounded to limit entries.
type ipExpiry struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	limit   int
}

func newIPExpiry(limit int) *ipExpiry {
	return &ipExpiry{entries: make(map[string]time.Time), limit: limit}
}

// set extends the IP's expiry to until; it never shortens an existing one.
func (m *ipExpiry) set(ip string, until time.Time) {
	if m == nil || ip == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.entries[ip]
	if !ok && len(m.entries) >= m.limit {
		return
	}
	if until.After(current) {
		m.entries[ip] = until
	}
}

func (m *ipExpiry) active(ip string, now time.Time) bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.entries[ip].After(now)
}

// sweep drops expired entries and returns how many remain.
func (m *ipExpiry) sweep(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, until := range m.entries {
		if !until.After(now) {
			delete(m.entries, ip)
		}
	}
	return len(m.entries)
}
