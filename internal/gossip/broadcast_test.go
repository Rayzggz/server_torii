package gossip

import (
	"encoding/json"
	"testing"
	"time"
)

func TestBroadcastActionRulePayload(t *testing.T) {
	ch := make(chan Message, 1)
	before := time.Now().Add(time.Minute).Unix()
	BroadcastActionRule("node-a", "URI", `/quoted/"path`, "BLOCK", time.Minute, ch)
	after := time.Now().Add(time.Minute).Unix()
	select {
	case message := <-ch:
		if message.Type != TypeActionRule || message.OriginNode != "node-a" {
			t.Fatalf("unexpected envelope: %+v", message)
		}
		var payload ActionRulePayload
		if err := json.Unmarshal([]byte(message.Content), &payload); err != nil {
			t.Fatal(err)
		}
		if payload.RuleType != "URI" || payload.Value != `/quoted/"path` || payload.Action != "BLOCK" {
			t.Fatalf("unexpected payload: %+v", payload)
		}
		if payload.ExpiresAt < before || payload.ExpiresAt > after {
			t.Errorf("expiry %d outside [%d, %d]", payload.ExpiresAt, before, after)
		}
	default:
		t.Fatal("broadcast did not enqueue message")
	}
}

func TestBroadcastActionRuleDoesNotBlock(t *testing.T) {
	full := make(chan Message, 1)
	full <- Message{ID: "existing"}
	for name, ch := range map[string]chan Message{"nil": nil, "full": full, "unbuffered": make(chan Message)} {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() { BroadcastActionRule("node", "IP", "192.0.2.1", "BLOCK", time.Minute, ch); close(done) }()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("broadcast blocked")
			}
		})
	}
	if got := <-full; got.ID != "existing" {
		t.Fatal("full channel message replaced")
	}
}
