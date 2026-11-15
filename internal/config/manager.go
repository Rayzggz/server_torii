package config

import (
	"fmt"
	"log"
	"sync/atomic"
)

// SiteConfigSnapshot represents a complete, immutable snapshot of the active site configurations and their derived states.
type SiteConfigSnapshot struct {
	// SiteRules holds every site by its ID.
	SiteRules map[string]*RuleSet
	// DefaultSite is the ID of the site for requests that name none; it may be empty.
	DefaultSite string
	// Pages are the error pages of the sites that have none of their own.
	Pages *ErrorPages
	// SitePages holds the pages of the sites that configure an error_page directory.
	SitePages map[string]*ErrorPages
}

// PagesFor returns the error pages of a site: its own, or the common ones.
func (s *SiteConfigSnapshot) PagesFor(siteID string) *ErrorPages {
	if pages, ok := s.SitePages[siteID]; ok {
		return pages
	}
	return s.Pages
}

// Site returns the site with the given ID. An empty ID selects the default site. It returns nil
// for an unknown ID, and for an empty one when no default site is configured.
func (s *SiteConfigSnapshot) Site(id string) *RuleSet {
	if id == "" {
		id = s.DefaultSite
	}
	if id == "" {
		return nil
	}
	return s.SiteRules[id]
}

// CounterWindows is the longest window, in seconds, each rate counter of a site must cover.
type CounterWindows struct {
	HTTPFloodSpeed   int64
	HTTPFloodSameURI int64
	HTTPFloodFailure int64
	ChallengeFailure int64
}

// CounterWindows returns the longest rate-limit windows the site configures.
func (rs *RuleSet) CounterWindows() CounterWindows {
	return CounterWindows{
		HTTPFloodSpeed:   rs.HTTPFloodRule.SpeedLimit.MaxWindow(),
		HTTPFloodSameURI: rs.HTTPFloodRule.SameURILimit.MaxWindow(),
		HTTPFloodFailure: rs.HTTPFloodRule.FailureLimit.MaxWindow(),
		ChallengeFailure: rs.Challenge.FailureLimit.MaxWindow(),
	}
}

// CounterWindows returns the rate-limit windows of every site by site ID.
func (s *SiteConfigSnapshot) CounterWindows() map[string]CounterWindows {
	windows := make(map[string]CounterWindows, len(s.SiteRules))
	for id, rules := range s.SiteRules {
		windows[id] = rules.CounterWindows()
	}
	return windows
}

// Manager handles the thread-safe swapping of site configuration snapshots.
type Manager struct {
	snapshot atomic.Pointer[SiteConfigSnapshot]
}

// NewManager returns a manager with no snapshot; call Reload to load one.
func NewManager() *Manager {
	return &Manager{}
}

// Get returns the current, immutable site configuration snapshot, or nil when none is loaded.
// Calling this at the start of a request guarantees that the request sees a consistent state.
func (m *Manager) Get() *SiteConfigSnapshot {
	if m == nil {
		return nil
	}
	return m.snapshot.Load()
}

// Set forcefully replaces the current configuration snapshot with a new one.
func (m *Manager) Set(snap *SiteConfigSnapshot) {
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

	sitePages := make(map[string]*ErrorPages)
	for _, site := range cfg.Sites {
		if site.ErrorPage == "" {
			continue
		}
		if sitePages[site.ID], err = LoadSiteErrorPages(site.ErrorPage, pages); err != nil {
			return nil, fmt.Errorf("failed to reload error pages of site %s: %w", site.ID, err)
		}
	}
	return &SiteConfigSnapshot{SiteRules: siteRules, DefaultSite: cfg.DefaultSite, Pages: pages, SitePages: sitePages}, nil
}

// Reload re-reads all site rules and swaps the snapshot without interrupting current requests.
// A failed load leaves the current snapshot in place. Each beforeSwap hook runs once the new
// snapshot is loaded and before requests can see it, so state derived from it is ready in time.
func (m *Manager) Reload(cfg *MainConfig, beforeSwap ...func(*SiteConfigSnapshot)) error {
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
