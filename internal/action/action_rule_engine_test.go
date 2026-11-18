package action

import (
	"server_torii/internal/request"
	"sync"
	"testing"
	"time"
)

func TestActionRuleEngine_AddAndCheck(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	// Test IP Rule
	engine.AddIPRule("", "192.168.1.1", ActionBlock, time.Minute)
	if action := engine.Check("", "192.168.1.1", "/index.html"); action != ActionBlock {
		t.Errorf("Expected IP rule to return ActionBlock, got %v", action)
	}

	// Test URI Rule
	engine.AddURIRule("", "/admin", ActionBlock, time.Minute)
	if action := engine.Check("", "10.0.0.1", "/admin"); action != ActionBlock {
		t.Errorf("Expected URI rule to return ActionBlock, got %v", action)
	}

	// Test No Match
	if action := engine.Check("", "10.0.0.1", "/home"); action != ActionNone {
		t.Errorf("Expected no match to return ActionNone, got %v", action)
	}
}

func TestActionRuleEngine_Priority(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("", "1.1.1.1", ActionBlock, time.Minute)
	engine.AddURIRule("", "/login", ActionChallenge, time.Minute)

	// IP should override the URI
	if action := engine.Check("", "1.1.1.1", "/login"); action != ActionBlock {
		t.Errorf("Expected IP priority (ActionBlock), got %v", action)
	}
	if action := engine.Check("", "2.2.2.2", "/login"); action != ActionChallenge {
		t.Errorf("Expected the URI rule (ActionChallenge), got %v", action)
	}
}

// A rule belongs to one site and one kind: the same value elsewhere does not match.
func TestActionRuleEngine_Scope(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("shop", "/login", ActionBlock, time.Minute)
	if action := engine.Check("shop", "1.1.1.1", "/login"); action != ActionNone {
		t.Errorf("an IP rule matched a URI: %v", action)
	}
	engine.AddURIRule("shop", "/login", ActionBlock, time.Minute)
	if action := engine.Check("blog", "1.1.1.1", "/login"); action != ActionNone {
		t.Errorf("a rule of one site matched another: %v", action)
	}
	if !engine.HasIPRule("shop", "/login") || engine.HasIPRule("blog", "/login") {
		t.Error("HasIPRule ignores the site")
	}
}

// Adding a rule again changes its action but never shortens it.
func TestActionRuleEngine_AddAgainKeepsLaterExpiry(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("", "1.1.1.1", ActionChallenge, time.Hour)
	engine.AddIPRule("", "1.1.1.1", ActionBlock, time.Minute)
	snapshot := engine.GetSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("snapshot has %d rules, want 1", len(snapshot))
	}
	rule := snapshot[0]
	if rule.RuleType != RuleIP || rule.Value != "1.1.1.1" || rule.Action != ActionBlock {
		t.Errorf("rule = %+v", rule)
	}
	if time.Until(rule.ExpiresAt) < 30*time.Minute {
		t.Errorf("expiry was shortened to %v", time.Until(rule.ExpiresAt))
	}
}

func TestParse(t *testing.T) {
	if act, err := Parse("block", ActionBlock, ActionChallenge); err != nil || act != ActionBlock {
		t.Errorf("Parse(block) = %v, %v", act, err)
	}
	for _, name := range []string{"allow", "BLOCK", "", "captcha"} {
		if _, err := Parse(name, ActionBlock, ActionChallenge); err == nil {
			t.Errorf("Parse(%q) accepted", name)
		}
	}
	if _, err := ParseRuleKind("UA"); err == nil {
		t.Error("UA accepted as a rule kind")
	}
}

func TestActionRuleEngine_TTL(t *testing.T) {
	interval := 10 * time.Millisecond
	engine := NewActionRuleEngine(interval)
	defer engine.Stop()

	// Add a short-lived rule
	ttl := 50 * time.Millisecond
	engine.AddIPRule("", "1.2.3.4", ActionBlock, ttl)

	// Should exist immediately
	if action := engine.Check("", "1.2.3.4", ""); action != ActionBlock {
		t.Errorf("Expected rule to match immediately")
	}

	// Wait for expiration + cleanup
	time.Sleep(ttl + interval*2)

	// Should be gone
	if action := engine.Check("", "1.2.3.4", ""); action != ActionNone {
		t.Errorf("Expected rule to expire, but got %v", action)
	}
}

func TestActionRuleEngine_Concurrency(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop() // Ensure cleanup routine handles stop signal properly

	var wg sync.WaitGroup
	count := 100

	// Concurrent Writers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			engine.AddIPRule("", "1.1.1.1", ActionBlock, time.Minute)
			engine.AddURIRule("", "/index", ActionChallenge, time.Minute)
		}
	}()

	// Concurrent Readers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			engine.Check("", "1.1.1.1", "/index")
		}
	}()

	wg.Wait()
}

func TestActionRuleEngine_CheckRequest(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("", "10.0.0.5", ActionBlock, time.Minute)

	req := &request.UserRequest{
		RemoteIP:  "10.0.0.5",
		UserAgent: "Mozilla/5.0",
		Uri:       "/index.html",
	}

	if action := engine.CheckRequest(*req); action != ActionBlock {
		t.Errorf("Expected ActionBlock for CheckRequest, got %v", action)
	}

	reqNormal := &request.UserRequest{
		RemoteIP:  "10.0.0.6",
		UserAgent: "Mozilla/5.0",
		Uri:       "/index.html",
	}

	if action := engine.CheckRequest(*reqNormal); action != ActionNone {
		t.Errorf("Expected ActionNone for CheckRequest, got %v", action)
	}
}

func TestActionRuleEngine_CanonicalURI(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	// Rule added for canonical URI (no query params)
	engine.AddURIRule("", "/admin", ActionBlock, time.Minute)

	// Check with raw URI containing query params
	if action := engine.Check("", "10.0.0.1", "/admin?debug=true"); action != ActionBlock {
		t.Errorf("Expected ActionBlock for raw URI matching canonical rule, got %v", action)
	}

	// Check with raw URI containing extra slashes
	if action := engine.Check("", "10.0.0.1", "//admin/"); action != ActionBlock {
		t.Errorf("Expected ActionBlock for non-clean URI matching canonical rule, got %v", action)
	}
}
