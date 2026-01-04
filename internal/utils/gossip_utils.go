package utils

import (
	"server_torii/internal/dataType"
)

// BroadcastBlock sends a block event to the gossip channel in a non-blocking way
func BroadcastBlock(ip string, duration int64, gossipChan chan dataType.GossipMessage) {
	if gossipChan == nil {
		return
	}

	select {
	case gossipChan <- dataType.GossipMessage{
		Type:     dataType.GossipTypeBlockIP,
		Content:  ip,
		Duration: duration,
		Source:   "local", //TODO： Use actual source identifier
	}:
	default:
		// Channel full, drop message to prevent blocking the checker
	}
}
