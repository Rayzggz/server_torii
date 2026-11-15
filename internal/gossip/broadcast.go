package gossip

import (
	"server_torii/internal/action"
	"time"
)

// outboxSize is how many rules of this node may wait to be sent to the peers.
const outboxSize = 1000

// outboxFullLogInterval keeps a flood from writing a line for every rule that is not shared.
const outboxFullLogInterval = 10 * time.Second

// ShareRule queues a rule this node installed for the peers. It never blocks: when the queue is
// full the rule stays local, and the next sync brings it to the peers anyway.
func (gm *Manager) ShareRule(site string, kind action.RuleKind, value string, act action.Action, ttl time.Duration) {
	msg := Message{
		Type:       TypeActionRule,
		OriginNode: gm.cfg.NodeName,
		Rule: &ActionRulePayload{
			Site:      site,
			RuleType:  string(kind),
			Value:     value,
			Action:    string(act),
			ExpiresAt: time.Now().Add(ttl).Unix(),
		},
	}
	select {
	case gm.outbox <- msg:
	default:
		gm.noteOutboxFull()
	}
}

func (gm *Manager) noteOutboxFull() {
	gm.mu.Lock()
	gm.unshared++
	count, now := gm.unshared, time.Now()
	report := now.Sub(gm.unsharedLog) >= outboxFullLogInterval
	if report {
		gm.unshared, gm.unsharedLog = 0, now
	}
	gm.mu.Unlock()
	if report {
		gm.logger().Warn("gossip: rules not shared at once: too many are waiting to be sent; the next sync carries them", "rules", count)
	}
}
