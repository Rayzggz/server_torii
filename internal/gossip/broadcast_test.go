package gossip

import (
	"encoding/json"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"strings"
	"testing"
	"time"
)

func TestShareRuleQueuesTheRule(t *testing.T) {
	gm := NewManager(&config.MainConfig{NodeName: "node-a"}, nil, nil)
	before := time.Now().Add(time.Minute).Unix()
	gm.ShareRule("site_a", action.RuleURI, `/quoted/"path`, action.ActionBlock, time.Minute)
	after := time.Now().Add(time.Minute).Unix()
	select {
	case message := <-gm.outbox:
		if message.Type != TypeActionRule || message.OriginNode != "node-a" || message.Rule == nil {
			t.Fatalf("unexpected envelope: %+v", message)
		}
		rule := *message.Rule
		if rule.Site != "site_a" || rule.RuleType != "URI" || rule.Value != `/quoted/"path` || rule.Action != "block" {
			t.Fatalf("unexpected rule: %+v", rule)
		}
		if rule.ExpiresAt < before || rule.ExpiresAt > after {
			t.Errorf("expiry %d outside [%d, %d]", rule.ExpiresAt, before, after)
		}
	default:
		t.Fatal("the rule was not queued")
	}
}

// A request never waits for the peers: with the queue full the rule stays local.
func TestShareRuleDoesNotBlock(t *testing.T) {
	gm := NewManager(&config.MainConfig{NodeName: "node-a"}, nil, nil)
	done := make(chan struct{})
	go func() {
		for i := 0; i < outboxSize+10; i++ {
			gm.ShareRule("site_a", action.RuleIP, "192.0.2.1", action.ActionBlock, time.Minute)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ShareRule blocked on a full queue")
	}
	if len(gm.outbox) != outboxSize || gm.unshared != 10-1 {
		// The first rule that found the queue full was logged and reset the count.
		t.Fatalf("queued %d, counted %d unshared", len(gm.outbox), gm.unshared)
	}
}

// A rule travels as an object of the message, not as a string of JSON inside it.
func TestMessageCarriesRulesAsObjects(t *testing.T) {
	rule := ActionRulePayload{Site: "site_a", RuleType: "IP", Value: "1.2.3.4", Action: "block", ExpiresAt: 1700000000}
	for name, msg := range map[string]Message{
		"rule": {Version: ProtocolVersion, Type: TypeActionRule, ID: "id", OriginNode: "node-a", Rule: &rule},
		"sync": {Version: ProtocolVersion, Type: TypeSync, ID: "id", OriginNode: "node-a", Rules: []ActionRulePayload{rule}},
	} {
		data, err := json.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `{"site":"site_a","rule_type":"IP","value":"1.2.3.4","action":"block","expires_at":1700000000}`) ||
			strings.Contains(string(data), `\"`) || strings.Contains(string(data), `"content"`) {
			t.Errorf("%s: %s", name, data)
		}
	}
}
