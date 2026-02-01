package action

import (
	"server_torii/internal/dataType"
	"sync"
	"testing"
	"time"
)

func TestActionRuleEngine_AddAndCheck(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	// Test IP Rule
	engine.AddIPRule("192.168.1.1", ActionBlock, time.Minute)
	if action := engine.Check("192.168.1.1", "Mozilla", "/index.html"); action != ActionBlock {
		t.Errorf("Expected IP rule to return ActionBlock, got %v", action)
	}

	// Test UA Rule
	engine.AddUARule("BadBot", ActionCaptcha, time.Minute)
	if action := engine.Check("10.0.0.1", "BadBot", "/index.html"); action != ActionCaptcha {
		t.Errorf("Expected UA rule to return ActionCaptcha, got %v", action)
	}

	// Test URI Rule
	engine.AddURIRule("/admin", ActionBlock, time.Minute)
	if action := engine.Check("10.0.0.1", "Mozilla", "/admin"); action != ActionBlock {
		t.Errorf("Expected URI rule to return ActionBlock, got %v", action)
	}

	// Test No Match
	if action := engine.Check("10.0.0.1", "Mozilla", "/home"); action != ActionNone {
		t.Errorf("Expected no match to return ActionNone, got %v", action)
	}
}

func TestActionRuleEngine_Priority(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("1.1.1.1", ActionBlock, time.Minute)
	engine.AddUARule("SpecialUser", ActionCaptcha, time.Minute)
	engine.AddURIRule("/login", ActionBlock, time.Minute)

	// IP should override everything
	if action := engine.Check("1.1.1.1", "SpecialUser", "/login"); action != ActionBlock {
		t.Errorf("Expected IP priority (ActionBlock), got %v", action)
	}

	// UA should override URI
	if action := engine.Check("2.2.2.2", "SpecialUser", "/login"); action != ActionCaptcha {
		t.Errorf("Expected UA priority (ActionCaptcha), got %v", action)
	}
}

func TestActionRuleEngine_TTL(t *testing.T) {
	interval := 10 * time.Millisecond
	engine := NewActionRuleEngine(interval)
	defer engine.Stop()

	// Add a short-lived rule
	ttl := 50 * time.Millisecond
	engine.AddIPRule("1.2.3.4", ActionBlock, ttl)

	// Should exist immediately
	if action := engine.Check("1.2.3.4", "", ""); action != ActionBlock {
		t.Errorf("Expected rule to match immediately")
	}

	// Wait for expiration + cleanup
	time.Sleep(ttl + interval*2)

	// Should be gone
	if action := engine.Check("1.2.3.4", "", ""); action != ActionNone {
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
			engine.AddIPRule("1.1.1.1", ActionBlock, time.Minute)
			engine.AddUARule("Bot", ActionCaptcha, time.Minute)
		}
	}()

	// Concurrent Readers
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < count; i++ {
			engine.Check("1.1.1.1", "Bot", "/index")
		}
	}()

	wg.Wait()
}

func TestActionRuleEngine_CheckRequest(t *testing.T) {
	engine := NewActionRuleEngine(time.Second)
	defer engine.Stop()

	engine.AddIPRule("10.0.0.5", ActionBlock, time.Minute)

	req := &dataType.UserRequest{
		RemoteIP:  "10.0.0.5",
		UserAgent: "Mozilla/5.0",
		Uri:       "/index.html",
	}

	if action := engine.CheckRequest(*req); action != ActionBlock {
		t.Errorf("Expected ActionBlock for CheckRequest, got %v", action)
	}

	reqNormal := &dataType.UserRequest{
		RemoteIP:  "10.0.0.6",
		UserAgent: "Mozilla/5.0",
		Uri:       "/index.html",
	}

	if action := engine.CheckRequest(*reqNormal); action != ActionNone {
		t.Errorf("Expected ActionNone for CheckRequest, got %v", action)
	}
}
