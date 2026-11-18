package gossip

// ProtocolVersion is the version of the messages this node sends and accepts. Version 2 names
// actions in lower case ("block", "challenge", "challenge_unverified"), has no UA rules and
// carries its rules as JSON objects, not as a string of JSON; a node that speaks another
// version is ignored, so the nodes of a cluster are upgraded together.
const ProtocolVersion = 2

type Message struct {
	Version    int    `json:"v"`           // ProtocolVersion of the sender
	Type       string `json:"type"`        // e.g., "ACTION_RULE", "SYNC"
	ID         string `json:"id"`          // UUID for deduplication
	Seq        int64  `json:"seq"`         // Sequence number/Version
	Timestamp  int64  `json:"timestamp"`   // Creation time
	OriginNode string `json:"origin_node"` // Node that originated the message
	// Rule is the rule of an ACTION_RULE message, Rules the rules of a SYNC message.
	Rule  *ActionRulePayload  `json:"rule,omitempty"`
	Rules []ActionRulePayload `json:"rules,omitempty"`
}

type ActionRulePayload struct {
	Site      string `json:"site"`       // ID of the site the rule belongs to
	RuleType  string `json:"rule_type"`  // action.RuleKind: "IP" or "URI"
	Value     string `json:"value"`      // The actual IP, UA, or URI
	Action    string `json:"action"`     // action.Action: "block", "challenge" or "challenge_unverified"
	ExpiresAt int64  `json:"expires_at"` // Unix timestamp
}

const (
	TypeActionRule = "ACTION_RULE"
	TypeSync       = "SYNC"
)
