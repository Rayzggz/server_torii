package dataType

type GossipMessage struct {
	Type       string `json:"type"`        // e.g., "BLOCK_IP", "SYNC"
	ID         string `json:"id"`          // UUID for deduplication
	Seq        int64  `json:"seq"`         // Sequence number/Version
	Timestamp  int64  `json:"timestamp"`   // Creation time
	OriginNode string `json:"origin_node"` // Node that originated the message
	Content    string `json:"content"`     // IP address or JSON payload
	Expiration int64  `json:"expiration"`  // Absolute expiration timestamp
}

const (
	GossipTypeBlockIP = "BLOCK_IP"
	GossipTypeSync    = "SYNC"
)
