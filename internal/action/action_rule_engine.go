package action

import (
	"server_torii/internal/request"
	"strings"
	"sync"
	"time"
)

// ActionType defines the type of action to take.
type ActionType string

const (
	ActionNone    ActionType = "NONE"
	ActionBlock   ActionType = "BLOCK"
	ActionCaptcha ActionType = "CAPTCHA"
	// ActionCaptchaUnverified challenges only clients the traffic analyzer has not seen behave like a browser.
	ActionCaptchaUnverified ActionType = "CAPTCHA_UNVERIFIED"
)

// actionRule represents a temporary rule with an expiration time.
type actionRule struct {
	Action    ActionType
	ExpiresAt time.Time
}

// ruleKey scopes a rule value to a site, so a rule installed for one site never matches a
// request of another. Site IDs cannot contain the separator.
func ruleKey(site, value string) string {
	return site + "\x00" + value
}

func splitRuleKey(key string) (site, value string) {
	site, value, _ = strings.Cut(key, "\x00")
	return site, value
}

// ActionRuleEngine manages the temporary action rules of every site, based on IP, UA, and URI.
type ActionRuleEngine struct {
	mu           sync.RWMutex
	ipRules      map[string]actionRule
	uaRules      map[string]actionRule
	uriRules     map[string]actionRule
	stopCleanup  chan struct{}
	cleanupTimer *time.Ticker
}

// NewActionRuleEngine creates a new ActionRuleEngine and starts the cleanup routine.
func NewActionRuleEngine(cleanupInterval time.Duration) *ActionRuleEngine {
	e := &ActionRuleEngine{
		ipRules:      make(map[string]actionRule),
		uaRules:      make(map[string]actionRule),
		uriRules:     make(map[string]actionRule),
		stopCleanup:  make(chan struct{}),
		cleanupTimer: time.NewTicker(cleanupInterval),
	}
	go e.runCleanup()
	return e
}

// Stop stops the background cleanup routine.
func (e *ActionRuleEngine) Stop() {
	e.cleanupTimer.Stop()
	close(e.stopCleanup)
}

// AddIPRule adds a rule for a specific IP on one site.
func (e *ActionRuleEngine) AddIPRule(site, ip string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ip = ruleKey(site, ip)

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.ipRules[ip]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.ipRules[ip] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// HasIPRule reports whether an unexpired rule exists for the IP on the site.
func (e *ActionRuleEngine) HasIPRule(site, ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	rule, ok := e.ipRules[ruleKey(site, ip)]
	return ok && rule.ExpiresAt.After(time.Now())
}

// AddUARule adds a rule for a specific User-Agent on one site.
func (e *ActionRuleEngine) AddUARule(site, ua string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	ua = ruleKey(site, ua)

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.uaRules[ua]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.uaRules[ua] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// AddURIRule adds a rule for a specific URI on one site.
func (e *ActionRuleEngine) AddURIRule(site, uri string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()
	uri = ruleKey(site, uri)

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.uriRules[uri]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.uriRules[uri] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// Check evaluates the request attributes against the rules of the site.
// Priority: IP > UA > URI.
func (e *ActionRuleEngine) Check(site, ip, ua, uri string) ActionType {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()

	// Check IP Rules
	if rule, ok := e.ipRules[ruleKey(site, ip)]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check UA Rules
	if rule, ok := e.uaRules[ruleKey(site, ua)]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check URI Rules
	if rule, ok := e.uriRules[ruleKey(site, uri)]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check Canonical URI Rules
	canonicalURI := CanonicalizeURI(uri)
	if canonicalURI != uri {
		if rule, ok := e.uriRules[ruleKey(site, canonicalURI)]; ok {
			if rule.ExpiresAt.After(now) {
				return rule.Action
			}
		}
	}

	return ActionNone
}

// CheckRequest evaluates the request against the rules using UserRequest data.
func (e *ActionRuleEngine) CheckRequest(req request.UserRequest) ActionType {
	return e.Check(req.Site, req.RemoteIP, req.UserAgent, req.Uri)
}

// runCleanup periodically removes expired rules.
func (e *ActionRuleEngine) runCleanup() {
	for {
		select {
		case <-e.stopCleanup:
			return
		case <-e.cleanupTimer.C:
			e.cleanup()
		}
	}
}

func (e *ActionRuleEngine) cleanup() {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()

	for k, v := range e.ipRules {
		if !v.ExpiresAt.After(now) {
			delete(e.ipRules, k)
		}
	}
	for k, v := range e.uaRules {
		if !v.ExpiresAt.After(now) {
			delete(e.uaRules, k)
		}
	}
	for k, v := range e.uriRules {
		if !v.ExpiresAt.After(now) {
			delete(e.uriRules, k)
		}
	}
}

// RuleSnapshot is one active rule as reported by GetSnapshot.
type RuleSnapshot struct {
	Site      string
	RuleType  string // "IP", "UA" or "URI"
	Value     string
	Action    ActionType
	ExpiresAt time.Time
}

// GetSnapshot returns a copy of the active action rules.
func (e *ActionRuleEngine) GetSnapshot() []RuleSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var snapshot []RuleSnapshot
	now := time.Now()

	for _, kind := range []struct {
		name  string
		rules map[string]actionRule
	}{{"IP", e.ipRules}, {"UA", e.uaRules}, {"URI", e.uriRules}} {
		for key, rule := range kind.rules {
			if rule.ExpiresAt.After(now) {
				site, value := splitRuleKey(key)
				snapshot = append(snapshot, RuleSnapshot{
					Site:      site,
					RuleType:  kind.name,
					Value:     value,
					Action:    rule.Action,
					ExpiresAt: rule.ExpiresAt,
				})
			}
		}
	}

	return snapshot
}
