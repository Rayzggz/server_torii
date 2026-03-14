package action

import (
	"server_torii/internal/dataType"
	"server_torii/internal/utils"
	"sync"
	"time"
)

// ActionType defines the type of action to take.
type ActionType string

const (
	ActionNone    ActionType = "NONE"
	ActionBlock   ActionType = "BLOCK"
	ActionCaptcha ActionType = "CAPTCHA"
)

// actionRule represents a temporary rule with an expiration time.
type actionRule struct {
	Action    ActionType
	ExpiresAt time.Time
}

// ActionRuleEngine manages action rules based on IP, UA, and URI.
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

// AddIPRule adds a rule for a specific IP.
func (e *ActionRuleEngine) AddIPRule(ip string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.ipRules[ip]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.ipRules[ip] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// AddUARule adds a rule for a specific User-Agent.
func (e *ActionRuleEngine) AddUARule(ua string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.uaRules[ua]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.uaRules[ua] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// AddURIRule adds a rule for a specific URI.
func (e *ActionRuleEngine) AddURIRule(uri string, action ActionType, ttl time.Duration) {
	e.mu.Lock()
	defer e.mu.Unlock()

	newExpiresAt := time.Now().Add(ttl)
	if existing, ok := e.uriRules[uri]; ok && existing.ExpiresAt.After(newExpiresAt) {
		newExpiresAt = existing.ExpiresAt
	}

	e.uriRules[uri] = actionRule{
		Action:    action,
		ExpiresAt: newExpiresAt,
	}
}

// Check evaluates the request attributes against the rules.
// Priority: IP > UA > URI.
func (e *ActionRuleEngine) Check(ip, ua, uri string) ActionType {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()

	// Check IP Rules
	if rule, ok := e.ipRules[ip]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check UA Rules
	if rule, ok := e.uaRules[ua]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check URI Rules
	if rule, ok := e.uriRules[uri]; ok {
		if rule.ExpiresAt.After(now) {
			return rule.Action
		}
	}

	// Check Canonical URI Rules
	canonicalURI := utils.CanonicalizeURI(uri)
	if canonicalURI != uri {
		if rule, ok := e.uriRules[canonicalURI]; ok {
			if rule.ExpiresAt.After(now) {
				return rule.Action
			}
		}
	}

	return ActionNone
}

// CheckRequest evaluates the request against the rules using UserRequest data.
func (e *ActionRuleEngine) CheckRequest(req dataType.UserRequest) ActionType {
	return e.Check(req.RemoteIP, req.UserAgent, req.Uri)
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

// GetSnapshot returns a copy of the active action rules.
func (e *ActionRuleEngine) GetSnapshot() []dataType.ActionRulePayload {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var snapshot []dataType.ActionRulePayload
	now := time.Now()

	for ip, rule := range e.ipRules {
		if rule.ExpiresAt.After(now) {
			snapshot = append(snapshot, dataType.ActionRulePayload{
				RuleType:  "IP",
				Value:     ip,
				Action:    string(rule.Action),
				ExpiresAt: rule.ExpiresAt.Unix(),
			})
		}
	}
	for ua, rule := range e.uaRules {
		if rule.ExpiresAt.After(now) {
			snapshot = append(snapshot, dataType.ActionRulePayload{
				RuleType:  "UA",
				Value:     ua,
				Action:    string(rule.Action),
				ExpiresAt: rule.ExpiresAt.Unix(),
			})
		}
	}
	for uri, rule := range e.uriRules {
		if rule.ExpiresAt.After(now) {
			snapshot = append(snapshot, dataType.ActionRulePayload{
				RuleType:  "URI",
				Value:     uri,
				Action:    string(rule.Action),
				ExpiresAt: rule.ExpiresAt.Unix(),
			})
		}
	}

	return snapshot
}
