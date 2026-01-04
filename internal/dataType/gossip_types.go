package dataType

type GossipMessage struct {
	Type     string `json:"type"` // e.g., "BLOCK_IP"
	Content  string `json:"content"`
	Duration int64  `json:"duration"`
	Source   string `json:"source"`
}

const (
	GossipTypeBlockIP = "BLOCK_IP"
)
