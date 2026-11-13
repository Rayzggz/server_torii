package config

import (
	"fmt"
	"log"
	"server_torii/internal/utils"
	"sync/atomic"
)

// SiteConfigSnapshot represents a complete, immutable snapshot of the active site configurations and their derived states.
type SiteConfigSnapshot struct {
	SiteRules map[string]*RuleSet
	Pages     *ErrorPages
}

// CounterWindows is the longest window, in seconds, each shared rate counter must cover.
type CounterWindows struct {
	HTTPFloodSpeed   int64
	HTTPFloodSameURI int64
	HTTPFloodFailure int64
	CaptchaFailure   int64
}

// CounterWindows returns the longest rate-limit windows configured across all sites.
func (s *SiteConfigSnapshot) CounterWindows() CounterWindows {
	var w CounterWindows
	for _, rules := range s.SiteRules {
		w.HTTPFloodSpeed = max(w.HTTPFloodSpeed, utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSpeedLimit))
		w.HTTPFloodSameURI = max(w.HTTPFloodSameURI, utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodSameURILimit))
		w.HTTPFloodFailure = max(w.HTTPFloodFailure, utils.FindMaxRateTime(rules.HTTPFloodRule.HTTPFloodFailureLimit))
		w.CaptchaFailure = max(w.CaptchaFailure, utils.FindMaxRateTime(rules.CAPTCHARule.CaptchaFailureLimit))
	}
	return w
}

// ConfigManager handles the thread-safe swapping of site configuration snapshots.
type ConfigManager struct {
	snapshot atomic.Pointer[SiteConfigSnapshot]
}

// NewManager returns a manager with no snapshot; call Reload to load one.
func NewManager() *ConfigManager {
	return &ConfigManager{}
}

// Get returns the current, immutable site configuration snapshot, or nil when none is loaded.
// Calling this at the start of a request guarantees that the request sees a consistent state.
func (m *ConfigManager) Get() *SiteConfigSnapshot {
	if m == nil {
		return nil
	}
	return m.snapshot.Load()
}

// Set forcefully replaces the current configuration snapshot with a new one.
func (m *ConfigManager) Set(snap *SiteConfigSnapshot) {
	m.snapshot.Store(snap)
}

// LoadSnapshot reads all site rules and error pages into a new snapshot.
func LoadSnapshot(cfg *MainConfig) (*SiteConfigSnapshot, error) {
	siteRules, err := LoadSiteRules(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to reload site rules: %w", err)
	}

	pages, err := LoadErrorPages(cfg.ErrorPage)
	if err != nil {
		return nil, fmt.Errorf("failed to reload error pages: %w", err)
	}

	return &SiteConfigSnapshot{SiteRules: siteRules, Pages: pages}, nil
}

// Reload re-reads all site rules and swaps the snapshot without interrupting current requests.
// A failed load leaves the current snapshot in place. Each beforeSwap hook runs once the new
// snapshot is loaded and before requests can see it, so state derived from it is ready in time.
func (m *ConfigManager) Reload(cfg *MainConfig, beforeSwap ...func(*SiteConfigSnapshot)) error {
	log.Println("[INFO] Reloading site configurations...")

	snap, err := LoadSnapshot(cfg)
	if err != nil {
		return err
	}
	for _, hook := range beforeSwap {
		hook(snap)
	}

	m.snapshot.Store(snap)
	log.Println("[INFO] Successfully applied new site configuration snapshot.")
	return nil
}
