package utils

import (
	"encoding/json"
	"server_torii/internal/dataType"
	"time"
)

// BroadcastActionRule sends an action rule event to the gossip channel
func BroadcastActionRule(nodeName string, ruleType string, value string, action string, duration time.Duration, gossipChan chan dataType.GossipMessage) {
	if gossipChan == nil {
		return
	}

	payload := dataType.ActionRulePayload{
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
	case gossipChan <- dataType.GossipMessage{
		Type:       dataType.GossipTypeActionRule,
		OriginNode: nodeName,
		Content:    string(payloadBytes),
	}:
	default:
	}
}
