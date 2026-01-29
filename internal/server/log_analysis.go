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
	Analyze(logs []LogEntry, rule *config.RuleSet, sharedMem *dataType.SharedMemory)
}

// AdaptiveTrafficAnalyzer manages the analysis process
type AdaptiveTrafficAnalyzer struct {
	buffer    *LogBuffer
	analyzers []Analyzer
	siteRules map[string]*config.RuleSet
	tagRules  map[string]*config.RuleSet
	sharedMem *dataType.SharedMemory
	stopCh    chan struct{}
}

func NewAdaptiveTrafficAnalyzer(siteRules map[string]*config.RuleSet, sharedMem *dataType.SharedMemory) *AdaptiveTrafficAnalyzer {
	tagRules := make(map[string]*config.RuleSet)
	for _, rules := range siteRules {
		if rules.AdaptiveTrafficAnalyzerRule != nil {
			tagRules[rules.AdaptiveTrafficAnalyzerRule.Tag] = rules
		}
	}

	return &AdaptiveTrafficAnalyzer{
		buffer:    NewLogBuffer(),
		analyzers: []Analyzer{&Non200Analyzer{}}, // Register default analyzers
		siteRules: siteRules,
		tagRules:  tagRules,
		sharedMem: sharedMem,
		stopCh:    make(chan struct{}),
	}
}

func (ata *AdaptiveTrafficAnalyzer) Start() {
	// Find the minimum analysis interval across all sites
	minInterval := int64(60) // Default 1 minute
	for _, rules := range ata.siteRules {
		if rules.AdaptiveTrafficAnalyzerRule != nil && rules.AdaptiveTrafficAnalyzerRule.Enabled {
			if rules.AdaptiveTrafficAnalyzerRule.AnalysisInterval < minInterval {
				minInterval = rules.AdaptiveTrafficAnalyzerRule.AnalysisInterval
			}
		}
	}

	ticker := time.NewTicker(time.Duration(minInterval) * time.Second)
	go func() {
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
	log.Printf("AdaptiveTrafficAnalyzer started with interval %ds", minInterval)
}

func (ata *AdaptiveTrafficAnalyzer) Stop() {
	close(ata.stopCh)
}

func (ata *AdaptiveTrafficAnalyzer) AddLog(entry LogEntry) {
	ata.buffer.Add(entry)
}

func (ata *AdaptiveTrafficAnalyzer) ProcessBatch() {
	logs := ata.buffer.Swap()
	if len(logs) == 0 {
		return
	}

	// Optimization: Group logs by Tag first
	logsByTag := make(map[string][]LogEntry)
	for _, l := range logs {
		logsByTag[l.Tag] = append(logsByTag[l.Tag], l)
	}

	for tag, tagLogs := range logsByTag {
		// Find rule for this tag
		var ruleSet *config.RuleSet

		// We need a map Tag -> RuleSet. We should build this on init.
		ruleSet = ata.findRuleByTag(tag)

		if ruleSet == nil {
			continue // If log belongs to no known tag, discard
		}

		if ruleSet.AdaptiveTrafficAnalyzerRule == nil || !ruleSet.AdaptiveTrafficAnalyzerRule.Enabled {
			continue
		}

		for _, analyzer := range ata.analyzers {
			analyzer.Analyze(tagLogs, ruleSet, ata.sharedMem)
		}
	}
}

// findRuleByTag looks up the RuleSet that matches the given tag
func (ata *AdaptiveTrafficAnalyzer) findRuleByTag(tag string) *config.RuleSet {
	if rule, ok := ata.tagRules[tag]; ok {
		return rule
	}
	return nil
}

// Non200Analyzer implements Analyzer for non-200 status codes
type Non200Analyzer struct{}

type ipStats struct {
	TotalRequests int64
	FailRequests  int64
	UriStats      map[string]*uriStat
}

type uriStat struct {
	Total int64
	Fail  int64
}

func (n *Non200Analyzer) Analyze(logs []LogEntry, rule *config.RuleSet, sharedMem *dataType.SharedMemory) {
	non200Rule := rule.AdaptiveTrafficAnalyzerRule.Non200Analysis
	if !non200Rule.Enabled {
		return
	}

	stats := make(map[string]*ipStats)

	// 1. Aggregate Stats
	for _, l := range logs {
		if l.IP == "" {
			continue
		}
		s, exists := stats[l.IP]
		if !exists {
			s = &ipStats{UriStats: make(map[string]*uriStat)}
			stats[l.IP] = s
		}

		s.TotalRequests++
		if l.Status != 200 {
			s.FailRequests++
		}

		// URI Stats
		if l.URI != "" {
			uStats, uExists := s.UriStats[l.URI]
			if !uExists {
				uStats = &uriStat{}
				s.UriStats[l.URI] = uStats
			}
			uStats.Total++
			if l.Status != 200 {
				uStats.Fail++
			}
		}
	}

	// 2. Evaluate Rules
	for ip, stat := range stats {
		if sharedMem.BlockList.IsBlocked(ip) {
			continue
		}

		blocked := false
		reason := ""

		// Condition 1: Simple Fail Count
		if non200Rule.FailCountThreshold > 0 && stat.FailRequests >= non200Rule.FailCountThreshold {
			blocked = true
			reason = "Fail Count Exceeded"
		}

		// Condition 2: Fail Count + Fail Rate
		if !blocked && non200Rule.FailRateThreshold > 0 {
			// Check if min count met (optional, default to 0 if not set)
			if stat.FailRequests >= non200Rule.FailRateCountThreshold {
				rate := float64(stat.FailRequests) / float64(stat.TotalRequests)
				if rate >= non200Rule.FailRateThreshold {
					blocked = true
					reason = "Fail Rate Exceeded"
				}
			}
		}

		// Condition 3: Top N URI Rate
		if !blocked && non200Rule.UriRateThreshold > 0 && non200Rule.UriRateTopN > 0 {
			// Extract URIs
			type uriItem struct {
				URI   string
				Count int64
				Fail  int64
			}
			items := make([]uriItem, 0, len(stat.UriStats))
			for u, us := range stat.UriStats {
				items = append(items, uriItem{URI: u, Count: us.Total, Fail: us.Fail})
			}

			// Sort descending by Count
			for i := 0; i < len(items); i++ {
				for j := i + 1; j < len(items); j++ {
					if items[j].Count > items[i].Count {
						items[i], items[j] = items[j], items[i]
					}
				}
			}

			// Check Top N
			checkCount := non200Rule.UriRateTopN
			if checkCount > len(items) {
				checkCount = len(items)
			}

			for i := 0; i < checkCount; i++ {
				uItem := items[i]
				if uItem.Count == 0 {
					continue
				}
				rate := float64(uItem.Fail) / float64(uItem.Count)
				if rate >= non200Rule.UriRateThreshold {
					blocked = true
					reason = "URI Rate Exceeded: " + uItem.URI
					break
				}
			}
		}

		if blocked {
			sharedMem.BlockList.Block(ip, non200Rule.BlockDuration)
			log.Printf("[AdaptiveTrafficAnalyzer] Blocked IP %s for %ds (Tag: %s, Reason: %s)",
				ip, non200Rule.BlockDuration, rule.AdaptiveTrafficAnalyzerRule.Tag, reason)
		}
	}
}
