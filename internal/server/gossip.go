package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	GossipMaxSkew       = 2 * time.Minute
	GossipMaxAge        = 10 * time.Minute
	maxGossipBodySize   = 10 * 1024 * 1024 // 10MB
	maxSyncEntriesBatch = 5000             // conservative count to stay under 10MB
	maxSeenMessages     = 50000            // default limit for seen messages
)

type GossipManager struct {
	cfg                 *config.MainConfig
	actionEngine        *action.ActionRuleEngine
	seenMessages        map[string]time.Time
	mu                  sync.RWMutex
	localSeq            int64
	AntiEntropyInterval time.Duration
	maxSeenEntries      int
	rng                 *rand.Rand
	rngMu               sync.Mutex
}

func NewGossipManager(cfg *config.MainConfig, actionEngine *action.ActionRuleEngine) *GossipManager {
	return &GossipManager{
		cfg:                 cfg,
		actionEngine:        actionEngine,
		seenMessages:        make(map[string]time.Time),
		AntiEntropyInterval: 30 * time.Second,
		maxSeenEntries:      maxSeenMessages,
		rng:                 rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (gm *GossipManager) Start(gossipChan <-chan dataType.GossipMessage) {
	log.Printf("GossipManager started, listening for events...")

	// Start anti-entropy ticker
	go gm.startAntiEntropy()

	// Start cleanup ticker for seen messages
	go gm.cleanupSeenMessages()

	for msg := range gossipChan {
		if msg.OriginNode == gm.cfg.NodeName {
			// Originated from this node, enrich and broadcast
			if msg.ID == "" {
				msg.ID = uuid.New().String()
			}
			msg.Timestamp = time.Now().Unix()
			msg.Seq = atomic.AddInt64(&gm.localSeq, 1)

			gm.markSeen(msg.ID)
			gm.epidemicBroadcast(msg)
		} else {
			// Should not happen if channel is only for local,
			// but if we ever pipe remote msgs here:
			gm.processRemoteMessage(msg)
		}
	}
}

func (gm *GossipManager) markSeen(id string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Enforce capacity limit
	if len(gm.seenMessages) >= gm.maxSeenEntries {
		gm.pruneSeenMessagesLocked()
	}

	gm.seenMessages[id] = time.Now()
}

func (gm *GossipManager) isSeen(id string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	_, ok := gm.seenMessages[id]
	return ok
}

// checkAndMarkSeen atomically checks if a message has been seen.
// If not seen, it marks it as seen and returns false.
// If already seen, it returns true.
func (gm *GossipManager) checkAndMarkSeen(id string) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if _, ok := gm.seenMessages[id]; ok {
		return true
	}

	// Enforce capacity limit
	if len(gm.seenMessages) >= gm.maxSeenEntries {
		gm.pruneSeenMessagesLocked()
	}

	gm.seenMessages[id] = time.Now()
	return false
}

func (gm *GossipManager) isKnownPeer(name string) bool {
	for _, p := range gm.cfg.Peers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// pruneSeenMessagesLocked removes expired messages and enforces the size limit.
// It must be called with mu.Lock() held.
func (gm *GossipManager) pruneSeenMessagesLocked() {
	now := time.Now()
	// 1. Remove expired messages
	for id, t := range gm.seenMessages {
		if now.Sub(t) > GossipMaxAge {
			delete(gm.seenMessages, id)
		}
	}

	// 2. If still over limit, remove random entries until under limit.
	// We do not sort by time to avoid O(N log N) or O(N) sort cost on every insert/prune.
	// Random eviction is acceptable for DoS protection.
	if len(gm.seenMessages) >= gm.maxSeenEntries {
		// Calculate how many to remove
		toRemove := len(gm.seenMessages) - gm.maxSeenEntries + 1 // +1 to make room for new one
		// To avoid infinite loop (though unlikely), cap at current size
		if toRemove > len(gm.seenMessages) {
			toRemove = len(gm.seenMessages)
		}

		removedCount := 0
		for id := range gm.seenMessages {
			if removedCount >= toRemove {
				break
			}
			delete(gm.seenMessages, id)
			removedCount++
		}
		log.Printf("[GOSSIP-W] Pruned %d messages from seen cache (size was %d)", removedCount, len(gm.seenMessages)+removedCount)
	}
}

func (gm *GossipManager) cleanupSeenMessages() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		gm.mu.Lock()
		gm.pruneSeenMessagesLocked()
		gm.mu.Unlock()
	}
}

func (gm *GossipManager) epidemicBroadcast(msg dataType.GossipMessage) {
	// Fanout: Select k random peers
	k := 3 // Fanout factor
	peers := gm.cfg.Peers
	if len(peers) == 0 {
		return
	}

	// Shuffle peers
	gm.rngMu.Lock()
	perm := gm.rng.Perm(len(peers))
	gm.rngMu.Unlock()
	count := 0
	for _, i := range perm {
		if count >= k {
			break
		}
		go gm.sendGossip(peers[i], msg)
		count++
	}
}

func (gm *GossipManager) startAntiEntropy() {
	ticker := time.NewTicker(gm.AntiEntropyInterval) // Run every interval
	defer ticker.Stop()

	for range ticker.C {
		peers := gm.cfg.Peers
		if len(peers) == 0 {
			continue
		}

		// Select 1 random peer
		gm.rngMu.Lock()
		idx := gm.rng.Intn(len(peers))
		gm.rngMu.Unlock()
		peer := peers[idx]

		// Create snapshot
		snapshot := gm.actionEngine.GetSnapshot()

		// Chunking logic for large snapshots
		var batch []dataType.ActionRulePayload
		count := 0

		for _, rule := range snapshot {
			batch = append(batch, rule)
			count++

			if count >= maxSyncEntriesBatch {
				gm.sendSyncBatch(peer, dataType.ActionRuleSyncPayload{Rules: batch})
				// Reset batch
				batch = make([]dataType.ActionRulePayload, 0, maxSyncEntriesBatch)
				count = 0
			}
		}

		// Send remaining
		if len(batch) > 0 {
			gm.sendSyncBatch(peer, dataType.ActionRuleSyncPayload{Rules: batch})
		}
	}
}

func (gm *GossipManager) sendSyncBatch(peer config.Peer, batch dataType.ActionRuleSyncPayload) {
	content, err := json.Marshal(batch)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal snapshot batch for anti-entropy: %v", err)
		return
	}

	msg := dataType.GossipMessage{
		Type:       dataType.GossipTypeSync,
		ID:         uuid.New().String(),
		OriginNode: gm.cfg.NodeName,
		Timestamp:  time.Now().Unix(),
		Content:    string(content),
	}

	go gm.sendGossip(peer, msg)
}

func (gm *GossipManager) sendGossip(p config.Peer, msg dataType.GossipMessage) {
	url := p.Address + gm.cfg.WebPath + "/gossip"

	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal gossip message: %v", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		log.Printf("[ERROR] Failed to create request for peer %s: %v", p.Address, err)
		return
	}

	req.Header.Set("Content-Type", "application/json")

	// Calculate HMAC-SHA512 Signature
	mac := hmac.New(sha512.New, []byte(gm.cfg.GlobalSecret))
	mac.Write(data)
	signature := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Torii-Signature", signature)

	if p.Host != "" {
		req.Host = p.Host
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[WARNING] Failed to send gossip to peer %s: %v", p.Address, err)
		return
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			log.Printf("[WARNING] Failed to close response body from %s: %v", p.Address, err)
		}
	}()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[WARNING] Peer %s returned status %d", p.Address, resp.StatusCode)
	}
}

func (gm *GossipManager) HandleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, ok := gm.readAndVerifyBody(w, r)
	if !ok {
		return
	}

	var msg dataType.GossipMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check msg.ID constraints (UUID v4)
	if msg.ID == "" {
		log.Printf("[SECURITY] Dropped gossip with empty ID from %s", r.RemoteAddr)
		http.Error(w, "Forbidden: Empty Message ID", http.StatusForbidden)
		return
	}
	u, err := uuid.Parse(msg.ID)
	if err != nil {
		log.Printf("[SECURITY] Dropped gossip with invalid UUID from %s: %s", r.RemoteAddr, msg.ID)
		http.Error(w, "Forbidden: Invalid Message ID", http.StatusForbidden)
		return
	}
	if u.Version() != 4 {
		log.Printf("[SECURITY] Dropped gossip with non-v4 UUID from %s: %s (v%d)", r.RemoteAddr, msg.ID, u.Version())
		http.Error(w, "Forbidden: UUID v4 required", http.StatusForbidden)
		return
	}

	// Verify OriginNode is in Peers list
	if !gm.isKnownPeer(msg.OriginNode) {
		log.Printf("[SECURITY] Received gossip from unknown node: %s", msg.OriginNode)
		http.Error(w, "Forbidden: Unknown OriginNode", http.StatusForbidden)
		return
	}

	// Replay Protection: Timestamp Validation
	now := time.Now()
	msgTime := time.Unix(msg.Timestamp, 0)

	if now.Sub(msgTime) > GossipMaxAge {
		log.Printf("[SECURITY] Dropped old gossip from %s: ts=%d", msg.OriginNode, msg.Timestamp)
	} else if msgTime.Sub(now) > GossipMaxSkew {
		log.Printf("[SECURITY] Dropped future gossip from %s: ts=%d", msg.OriginNode, msg.Timestamp)
	} else {
		// Processing
		gm.processRemoteMessage(msg)
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ACK")); err != nil {
		log.Printf("[ERROR] Failed to write ACK response: %v", err)
	}
}

func (gm *GossipManager) readAndVerifyBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	// Check Content-Length if provided
	if r.ContentLength > maxGossipBodySize {
		log.Printf("[SECURITY] Rejected oversized gossip request from %s (Content-Length: %d)", r.RemoteAddr, r.ContentLength)
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return nil, false
	}

	// Verify HMAC-SHA512 Signature Header EARLY (before reading body)
	signatureHeader := r.Header.Get("X-Torii-Signature")
	if signatureHeader == "" {
		log.Printf("[SECURITY] Missing signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	// SHA-512 is 64 bytes -> 128 hex characters
	if len(signatureHeader) != 128 {
		log.Printf("[SECURITY] Invalid signature length from %s (%d chars)", r.RemoteAddr, len(signatureHeader))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	sigBytes, err := hex.DecodeString(signatureHeader)
	if err != nil {
		log.Printf("[SECURITY] Invalid signature format from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	// Limit Body Size
	r.Body = http.MaxBytesReader(w, r.Body, maxGossipBodySize)

	// Read Body (Protected by MaxBytesReader)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		if err.Error() == "http: request body too large" {
			log.Printf("[SECURITY] Dropped oversized gossip request from %s", r.RemoteAddr)
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		} else {
			log.Printf("[ERROR] Failed to read gossip body: %v", err)
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
		}
		return nil, false
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("[WARNING] readAndVerifyBody: Failed to close request body: %v", err)
		}
	}()

	mac := hmac.New(sha512.New, []byte(gm.cfg.GlobalSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedMAC) {
		log.Printf("[SECURITY] Invalid signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	return body, true
}

func (gm *GossipManager) processRemoteMessage(msg dataType.GossipMessage) {
	// Deduplication
	if gm.checkAndMarkSeen(msg.ID) {
		return
	}
	now := time.Now()

	switch msg.Type {
	case dataType.GossipTypeActionRule:
		gm.processActionRule(msg, now)
	case dataType.GossipTypeSync:
		gm.processSync(msg, now)
	}
}

func (gm *GossipManager) processActionRule(msg dataType.GossipMessage, now time.Time) {
	var payload dataType.ActionRulePayload
	if err := json.Unmarshal([]byte(msg.Content), &payload); err != nil {
		log.Printf("[ERROR] Failed to unmarshal action rule gossip: %v", err)
		return
	}

	if err := validateActionRule(payload, now); err != nil {
		log.Printf("[SECURITY] Dropped gossip ActionRule from %s: err=%v", msg.OriginNode, err)
		return
	}

	// Apply action rule
	ttl := time.Unix(payload.ExpiresAt, 0).Sub(now)
	if ttl > 0 {
		switch payload.RuleType {
		case "IP":
			gm.actionEngine.AddIPRule(payload.Value, action.ActionType(payload.Action), ttl)
		case "UA":
			gm.actionEngine.AddUARule(payload.Value, action.ActionType(payload.Action), ttl)
		case "URI":
			gm.actionEngine.AddURIRule(payload.Value, action.ActionType(payload.Action), ttl)
		}
	}
	log.Printf("[GOSSIP] Received ActionRule for %s:%s from %s (Exp: %d)", payload.RuleType, payload.Value, msg.OriginNode, payload.ExpiresAt)

	// Epidemic: Re-broadcast to infect others
	gm.epidemicBroadcast(msg)
}

func (gm *GossipManager) processSync(msg dataType.GossipMessage, now time.Time) {
	log.Printf("[GOSSIP] Received SYNC from %s", msg.OriginNode)
	var syncPayload dataType.ActionRuleSyncPayload
	if err := json.Unmarshal([]byte(msg.Content), &syncPayload); err != nil {
		log.Printf("[ERROR] Failed to unmarshal sync snapshot: %v", err)
		return
	}

	if len(syncPayload.Rules) > maxSyncEntriesBatch {
		log.Printf("[SECURITY] Dropped oversized SYNC from %s: %d entries (limit %d)", msg.OriginNode, len(syncPayload.Rules), maxSyncEntriesBatch)
		return
	}

	invalidCount := 0
	for _, payload := range syncPayload.Rules {
		if err := validateActionRule(payload, now); err != nil {
			invalidCount++
			if invalidCount <= 5 {
				log.Printf("[SECURITY] Dropped gossip SYNC entry from %s: value=%q exp=%d err=%v", msg.OriginNode, payload.Value, payload.ExpiresAt, err)
			}
			continue
		}

		ttl := time.Unix(payload.ExpiresAt, 0).Sub(now)
		if ttl > 0 {
			switch payload.RuleType {
			case "IP":
				gm.actionEngine.AddIPRule(payload.Value, action.ActionType(payload.Action), ttl)
			case "UA":
				gm.actionEngine.AddUARule(payload.Value, action.ActionType(payload.Action), ttl)
			case "URI":
				gm.actionEngine.AddURIRule(payload.Value, action.ActionType(payload.Action), ttl)
			}
		}
	}

	if invalidCount > 0 {
		if invalidCount > 5 {
			log.Printf("[SECURITY] Dropped %d invalid SYNC entries from %s (only first 5 shown)", invalidCount, msg.OriginNode)
		} else {
			log.Printf("[SECURITY] Dropped %d invalid SYNC entries from %s", invalidCount, msg.OriginNode)
		}
	}
}

const maxGossipBlockDuration = 7 * 24 * time.Hour

func validateActionRule(payload dataType.ActionRulePayload, now time.Time) error {
	trimmed := strings.TrimSpace(payload.Value)
	if trimmed == "" {
		return fmt.Errorf("empty rule value")
	}

	if payload.RuleType == "IP" {
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return fmt.Errorf("invalid ip format")
		}

		if ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !ip.IsGlobalUnicast() {
			return fmt.Errorf("non-global ip")
		}
	} else if payload.RuleType != "UA" && payload.RuleType != "URI" {
		return fmt.Errorf("invalid rule type: %s", payload.RuleType)
	}

	if payload.Action != string(action.ActionBlock) && payload.Action != string(action.ActionCaptcha) {
		return fmt.Errorf("invalid action: %s", payload.Action)
	}

	nowUnix := now.Unix()
	if payload.ExpiresAt <= nowUnix {
		return fmt.Errorf("expiration already passed")
	}

	maxExpiration := nowUnix + int64(maxGossipBlockDuration/time.Second)
	if payload.ExpiresAt > maxExpiration {
		return fmt.Errorf("expiration exceeds max allowed duration")
	}

	return nil
}
