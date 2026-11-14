package gossip

// ProtocolVersion is the version of the messages this node sends and accepts. Version 2 names
// actions in lower case ("block", "challenge", "challenge_unverified") and has no UA rules; a
// node that speaks another version is ignored, so the nodes of a cluster are upgraded together.
const ProtocolVersion = 2

type Message struct {
	Version    int    `json:"v"`           // ProtocolVersion of the sender
	Type       string `json:"type"`        // e.g., "ACTION_RULE", "SYNC"
	ID         string `json:"id"`          // UUID for deduplication
	Seq        int64  `json:"seq"`         // Sequence number/Version
	Timestamp  int64  `json:"timestamp"`   // Creation time
	OriginNode string `json:"origin_node"` // Node that originated the message
	Content    string `json:"content"`     // JSON payload
}

type ActionRulePayload struct {
	Site      string `json:"site"`       // ID of the site the rule belongs to
	RuleType  string `json:"rule_type"`  // action.RuleKind: "IP" or "URI"
	Value     string `json:"value"`      // The actual IP, UA, or URI
	Action    string `json:"action"`     // action.Action: "block", "challenge" or "challenge_unverified"
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

type ActionRuleSyncPayload struct {
	Rules []ActionRulePayload `json:"rules"`
}

const (
	TypeActionRule = "ACTION_RULE"
	TypeSync       = "SYNC"
)
