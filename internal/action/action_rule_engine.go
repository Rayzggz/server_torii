package action

import (
	"fmt"
	"server_torii/internal/request"
	"strings"
	"sync"
	"time"
)

// Action is what a rule asks to be done with a request. It is the one vocabulary shared by the
// site configuration, the temporary rules and the messages nodes send each other; every place
// that reads an action accepts the subset that makes sense there, see Parse.
type Action string

const (
	// ActionNone is the absence of an action: no rule matched.
	ActionNone Action = ""
	// ActionContinue leaves the request to the checks that follow.
	ActionContinue Action = "continue"
	// ActionAllow lets the request through at once.
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
	// ActionChallenge makes the client prove itself before it is let through.
	ActionChallenge Action = "challenge"
	// ActionChallengeUnverified challenges only clients the traffic analyzer has not seen behave like a browser.
	ActionChallengeUnverified Action = "challenge_unverified"
	// ActionSkip skips some of the checks that follow.
	ActionSkip Action = "skip"
	// ActionLog only records that the rule matched.
	ActionLog Action = "log"
	// ActionObserve is what the traffic analyzer does with a detection it must not act on.
	ActionObserve Action = "observe"
)

// Parse returns the action called name when it is one of allowed.
func Parse(name string, allowed ...Action) (Action, error) {
	for _, a := range allowed {
		if name == string(a) {
			return a, nil
		}
	}
	names := make([]string, len(allowed))
	for i, a := range allowed {
		names[i] = string(a)
	}
	return ActionNone, fmt.Errorf("invalid action %q: expected one of %s", name, strings.Join(names, ", "))
}

// RuleKind is what a temporary rule matches a request on.
type RuleKind string

const (
	RuleIP  RuleKind = "IP"
	RuleURI RuleKind = "URI"
)

// ParseRuleKind returns the rule kind called name.
func ParseRuleKind(name string) (RuleKind, error) {
	switch kind := RuleKind(name); kind {
	case RuleIP, RuleURI:
		return kind, nil
	}
	return "", fmt.Errorf("invalid rule type %q: expected IP or URI", name)
}

// ruleKey scopes a rule to a site, so a rule installed for one site never matches a request of
// another.
type ruleKey struct {
	site  string
	kind  RuleKind
	value string
}

// actionRule represents a temporary rule with an expiration time.
type actionRule struct {
	Action    Action
	ExpiresAt time.Time
}

// ActionRuleEngine manages the temporary action rules of every site, based on IP and URI.
type ActionRuleEngine struct {
	mu           sync.RWMutex
	rules        map[ruleKey]actionRule
	stopCleanup  chan struct{}
	cleanupTimer *time.Ticker
}

// NewActionRuleEngine creates a new ActionRuleEngine and starts the cleanup routine.
func NewActionRuleEngine(cleanupInterval time.Duration) *ActionRuleEngine {
	e := &ActionRuleEngine{
		rules:        make(map[ruleKey]actionRule),
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

// AddRule installs a rule on one site. A rule that already exists for the same value takes the
// new action and keeps whichever expiry is later.
func (e *ActionRuleEngine) AddRule(site string, kind RuleKind, value string, action Action, ttl time.Duration) {
	key := ruleKey{site, kind, value}
	expiresAt := time.Now().Add(ttl)

	e.mu.Lock()
	defer e.mu.Unlock()
	if existing, ok := e.rules[key]; ok && existing.ExpiresAt.After(expiresAt) {
		expiresAt = existing.ExpiresAt
	}
	e.rules[key] = actionRule{Action: action, ExpiresAt: expiresAt}
}

// AddIPRule adds a rule for a specific IP on one site.
func (e *ActionRuleEngine) AddIPRule(site, ip string, action Action, ttl time.Duration) {
	e.AddRule(site, RuleIP, ip, action, ttl)
}

// AddURIRule adds a rule for a specific URI on one site.
func (e *ActionRuleEngine) AddURIRule(site, uri string, action Action, ttl time.Duration) {
	e.AddRule(site, RuleURI, uri, action, ttl)
}

// HasIPRule reports whether an unexpired rule exists for the IP on the site.
func (e *ActionRuleEngine) HasIPRule(site, ip string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.activeLocked(ruleKey{site, RuleIP, ip}, time.Now()) != ActionNone
}

// activeLocked returns the action of the rule under key, or ActionNone when there is none or it
// has expired. Callers hold e.mu.
func (e *ActionRuleEngine) activeLocked(key ruleKey, now time.Time) Action {
	if rule, ok := e.rules[key]; ok && rule.ExpiresAt.After(now) {
		return rule.Action
	}
	return ActionNone
}

// Check evaluates the request attributes against the rules of the site.
// Priority: IP > URI as sent > canonical URI.
func (e *ActionRuleEngine) Check(site, ip, uri string) Action {
	e.mu.RLock()
	defer e.mu.RUnlock()

	now := time.Now()
	if act := e.activeLocked(ruleKey{site, RuleIP, ip}, now); act != ActionNone {
		return act
	}
	if act := e.activeLocked(ruleKey{site, RuleURI, uri}, now); act != ActionNone {
		return act
	}
	if canonicalURI := CanonicalizeURI(uri); canonicalURI != uri {
		return e.activeLocked(ruleKey{site, RuleURI, canonicalURI}, now)
	}
	return ActionNone
}

// CheckRequest evaluates the request against the rules using UserRequest data.
func (e *ActionRuleEngine) CheckRequest(req request.UserRequest) Action {
	return e.Check(req.Site, req.ClientKey(), req.Uri)
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
	for k, v := range e.rules {
		if !v.ExpiresAt.After(now) {
			delete(e.rules, k)
		}
	}
}

// RuleSnapshot is one active rule as reported by GetSnapshot.
type RuleSnapshot struct {
	Site      string
	RuleType  RuleKind
	Value     string
	Action    Action
	ExpiresAt time.Time
}

// GetSnapshot returns a copy of the active action rules.
func (e *ActionRuleEngine) GetSnapshot() []RuleSnapshot {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var snapshot []RuleSnapshot
	now := time.Now()
	for key, rule := range e.rules {
		if rule.ExpiresAt.After(now) {
			snapshot = append(snapshot, RuleSnapshot{
				Site:      key.site,
				RuleType:  key.kind,
				Value:     key.value,
				Action:    rule.Action,
				ExpiresAt: rule.ExpiresAt,
			})
		}
	}
	return snapshot
}
