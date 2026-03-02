package dataType

type GossipMessage struct {
	Type       string `json:"type"`        // e.g., "ACTION_RULE", "SYNC"
	ID         string `json:"id"`          // UUID for deduplication
	Seq        int64  `json:"seq"`         // Sequence number/Version
	Timestamp  int64  `json:"timestamp"`   // Creation time
	OriginNode string `json:"origin_node"` // Node that originated the message
	Content    string `json:"content"`     // JSON payload
}

type ActionRulePayload struct {
	RuleType  string `json:"rule_type"`  // "IP", "UA", "URI"
	Value     string `json:"value"`      // The actual IP, UA, or URI
	Action    string `json:"action"`     // "BLOCK", "CAPTCHA", etc.
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

type ActionRuleSyncPayload struct {
	Rules []ActionRulePayload `json:"rules"`
}

const (
	GossipTypeActionRule = "ACTION_RULE"
	GossipTypeSync       = "SYNC"
)
