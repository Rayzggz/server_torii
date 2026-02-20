package utils

import (
	"server_torii/internal/dataType"
	"time"
)

// BroadcastBlock sends a block event to the gossip channel
func BroadcastBlock(nodeName string, ip string, duration int64, gossipChan chan dataType.GossipMessage) {
	if gossipChan == nil {
		return
	}

	expiration := time.Now().Unix() + duration

	select {
	case gossipChan <- dataType.GossipMessage{
		Type:       dataType.GossipTypeBlockIP,
		OriginNode: nodeName,
		Content:    ip,
		Expiration: expiration,
	}:
	default:
	}
}
