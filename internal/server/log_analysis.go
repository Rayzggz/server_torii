package server

import (
	"log"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync"
	"time"
)

// LogEntry represents a simplified log entry for analysis
type LogEntry struct {
	Tag       string
	IP        string
	URI       string
	Status    int
	Timestamp int64
}

// LogBuffer is a thread-safe buffer for LogEntries
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
}

func NewLogBuffer() *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, 0, 1000),
	}
}

func (lb *LogBuffer) Add(entry LogEntry) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	lb.entries = append(lb.entries, entry)
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
	Logs      []LogEntry
	Rule      *config.RuleSet
	State     *siteState
	SharedMem *dataType.SharedMemory
	Marks     *ipExpiry // exempt clients
	Evidence  *ipExpiry // browser-like clients
	Now       time.Time
	Interval  time.Duration
}

type AdaptiveTrafficAnalyzer struct {
	buffer      *LogBuffer
	analyzers   []Analyzer
	sharedMem   *dataType.SharedMemory
	stopCh      chan struct{}
	startOnce   sync.Once
	stopOnce    sync.Once
	workers     sync.WaitGroup
	lifecycleMu sync.Mutex
	processMu   sync.Mutex
	windows     map[string]*analysisWindow
	marks       *ipExpiry
	evidence    *ipExpiry
	ingest      sync.Map // *dataType.AdaptiveTrafficAnalyzerRule -> *ingestSettings
	lastSweep   time.Time
}

// ingestSettings is the part of a rule needed to record browser evidence as logs arrive.
type ingestSettings struct {
	assets map[string]struct{}
	ttl    time.Duration
}

type analysisWindow struct {
	tag      string
	interval time.Duration
	start    time.Time
	next     time.Time
	logs     []LogEntry
	state    *siteState
}

func NewAdaptiveTrafficAnalyzer(sharedMem *dataType.SharedMemory) *AdaptiveTrafficAnalyzer {
	return &AdaptiveTrafficAnalyzer{
		buffer:    NewLogBuffer(),
		analyzers: []Analyzer{&trafficDetector{}},
		sharedMem: sharedMem,
		stopCh:    make(chan struct{}),
		windows:   make(map[string]*analysisWindow),
		marks:     newIPExpiry(maxMarkedClients),
		evidence:  newIPExpiry(maxEvidenceEntries),
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
		log.Print("AdaptiveTrafficAnalyzer started with per-site intervals")
	})
}

func (ata *AdaptiveTrafficAnalyzer) Stop() {
	ata.lifecycleMu.Lock()
	ata.stopOnce.Do(func() { close(ata.stopCh) })
	ata.lifecycleMu.Unlock()
	ata.workers.Wait()
}

func (ata *AdaptiveTrafficAnalyzer) AddLog(entry LogEntry) {
	ata.recordEvidence(entry, time.Now())
	ata.buffer.Add(entry)
}

// recordEvidence marks browser evidence as soon as a log arrives, so a page view followed
// quickly by a click onto a challenged URI is not challenged while waiting for the next analysis.
func (ata *AdaptiveTrafficAnalyzer) recordEvidence(entry LogEntry, now time.Time) {
	if entry.IP == "" || entry.Status >= 400 {
		return
	}
	rules := ata.findRuleByTag(entry.Tag)
	if rules == nil {
		return
	}
	settings := ata.ingestSettingsFor(rules.AdaptiveTrafficAnalyzerRule)
	if entry.Status == 304 || isAsset(stripQuery(entry.URI), settings.assets) {
		ata.evidence.set(entry.IP, now.Add(settings.ttl))
	}
}

func (ata *AdaptiveTrafficAnalyzer) ingestSettingsFor(rule *dataType.AdaptiveTrafficAnalyzerRule) *ingestSettings {
	if cached, ok := ata.ingest.Load(rule); ok {
		return cached.(*ingestSettings)
	}
	normalized := *rule
	config.NormalizeAdaptiveTrafficAnalyzerRule(&normalized)
	settings := &ingestSettings{
		assets: toSet(normalized.BrowserEvidence.AssetExtensions),
		ttl:    time.Duration(normalized.BrowserEvidence.TTL) * time.Second,
	}
	ata.ingest.Store(rule, settings)
	return settings
}

// HasBrowserEvidence reports whether the IP recently loaded assets, revalidated a page, or browsed several pages.
func (ata *AdaptiveTrafficAnalyzer) HasBrowserEvidence(ip string) bool {
	return ata.evidence.active(ip, time.Now())
}

// MarkVerified exempts an IP that solved a CAPTCHA.
func (ata *AdaptiveTrafficAnalyzer) MarkVerified(ip string, ttl time.Duration) {
	ata.marks.set(ip, time.Now().Add(ttl))
}

// MarkNeutral exempts an IP that is trusted for another reason, such as a verified crawler.
func (ata *AdaptiveTrafficAnalyzer) MarkNeutral(ip string, ttl time.Duration) {
	ata.marks.set(ip, time.Now().Add(ttl))
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
	var snap *config.SiteConfigSnapshot
	if config.Manager != nil {
		snap = config.Manager.Get()
	}
	if snap == nil {
		clear(ata.windows)
		return
	}
	logsByTag := make(map[string][]LogEntry)
	for _, l := range logs {
		logsByTag[l.Tag] = append(logsByTag[l.Tag], l)
	}
	for site := range ata.windows {
		rules := snap.SiteRules[site]
		if rules == nil || rules.AdaptiveTrafficAnalyzerRule == nil ||
			!rules.AdaptiveTrafficAnalyzerRule.Enabled || rules.AdaptiveTrafficAnalyzerRule.Tag == "" {
			delete(ata.windows, site)
		}
	}
	for site, rules := range snap.SiteRules {
		if rules == nil || rules.AdaptiveTrafficAnalyzerRule == nil {
			continue
		}
		rule := rules.AdaptiveTrafficAnalyzerRule
		if !rule.Enabled || rule.Tag == "" {
			continue
		}
		interval := time.Duration(rule.AnalysisInterval) * time.Second
		if interval <= 0 {
			interval = config.DefaultATAAnalysisInterval * time.Second
		}
		window := ata.windows[site]
		if window == nil || window.tag != rule.Tag {
			window = &analysisWindow{tag: rule.Tag, start: now, state: newSiteState(now)}
			ata.windows[site] = window
		}
		if window.interval != interval {
			window.interval = interval
			window.next = window.start.Add(interval)
		}
		window.logs = append(window.logs, logsByTag[rule.Tag]...)
		if now.Before(window.next) {
			continue
		}
		if len(window.logs) > 0 {
			ctx := &analysisContext{
				Logs:      window.logs,
				Rule:      rules,
				State:     window.state,
				SharedMem: ata.sharedMem,
				Marks:     ata.marks,
				Evidence:  ata.evidence,
				Now:       now,
				Interval:  interval,
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

// findRuleByTag looks up the RuleSet that matches the given tag from the current snapshot
func (ata *AdaptiveTrafficAnalyzer) findRuleByTag(tag string) *config.RuleSet {
	if config.Manager == nil {
		return nil
	}
	snap := config.Manager.Get()
	if snap == nil {
		return nil
	}
	for _, rules := range snap.SiteRules {
		if rules != nil && rules.AdaptiveTrafficAnalyzerRule != nil && rules.AdaptiveTrafficAnalyzerRule.Enabled && rules.AdaptiveTrafficAnalyzerRule.Tag == tag {
			return rules
		}
	}
	return nil
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

func (m *ipExpiry) sweep(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for ip, until := range m.entries {
		if !until.After(now) {
			delete(m.entries, ip)
		}
	}
}
