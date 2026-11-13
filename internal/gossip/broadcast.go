package gossip

import (
	"encoding/json"
	"time"
)

// BroadcastActionRule sends an action rule event to the gossip channel
func BroadcastActionRule(nodeName string, ruleType string, value string, action string, duration time.Duration, gossipChan chan GossipMessage) {
	if gossipChan == nil {
		return
	}

	payload := ActionRulePayload{
		RuleType:  ruleType,
		Value:     value,
		Action:    action,
		ExpiresAt: time.Now().Add(duration).Unix(),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return
	}

	select {
	case gossipChan <- GossipMessage{
		Type:       GossipTypeActionRule,
		OriginNode: nodeName,
		Content:    string(payloadBytes),
	}:
	default:
	}
}
