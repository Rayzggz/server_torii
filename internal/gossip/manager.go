package gossip

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"server_torii/internal/action"
	"server_torii/internal/config"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	MaxSkew             = 2 * time.Minute
	MaxAge              = 10 * time.Minute
	maxGossipBodySize   = 10 * 1024 * 1024 // 10MB
	maxSyncEntriesBatch = 5000             // conservative count to stay under 10MB
	maxSeenMessages     = 50000            // default limit for seen messages
)

type Manager struct {
	cfg                 *config.MainConfig
	actionEngine        *action.ActionRuleEngine
	seenMessages        map[string]time.Time
	mu                  sync.RWMutex
	localSeq            int64
	AntiEntropyInterval time.Duration
	maxSeenEntries      int
	rng                 *rand.Rand
	rngMu               sync.Mutex
	log                 *slog.Logger // nil logs nothing
	// outbox holds the rules of this node that wait to be sent to the peers.
	outbox chan Message
	// unshared counts the rules that found the outbox full since unsharedLog, when it was last logged.
	unshared    int
	unsharedLog time.Time

	// senders holds one sender per peer, made when the first message for the peer is sent.
	sendersMu sync.Mutex
	senders   map[string]*peerSender
	// stopCh is closed by Stop; workers counts Start and the senders.
	lifeOnce sync.Once
	stopOnce sync.Once
	stopCh   chan struct{}
	workers  sync.WaitGroup
}

// NewManager creates the gossip of a node. It logs to logger; nil logs nothing.
func NewManager(cfg *config.MainConfig, actionEngine *action.ActionRuleEngine, logger *slog.Logger) *Manager {
	return &Manager{
		log:                 logger,
		outbox:              make(chan Message, outboxSize),
		cfg:                 cfg,
		actionEngine:        actionEngine,
		seenMessages:        make(map[string]time.Time),
		AntiEntropyInterval: 30 * time.Second,
		maxSeenEntries:      maxSeenMessages,
		rng:                 rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (gm *Manager) logger() *slog.Logger {
	if gm.log == nil {
		return slog.New(slog.DiscardHandler)
	}
	return gm.log
}

// dropped logs a message, or a part of one, that was received and not applied.
func (gm *Manager) dropped(why string, attrs ...any) {
	gm.logger().Warn("gossip dropped: "+why, attrs...)
}

// Start sends the rules of this node to the peers until ctx is done or Stop is called. It
// returns then; Stop also waits for the senders.
func (gm *Manager) Start(ctx context.Context) {
	done := gm.life()
	if gm.stopped() {
		return
	}
	gm.logger().Info("gossip started", "peers", len(gm.cfg.Peers))

	gm.workers.Add(3)
	defer gm.workers.Done()
	go gm.startAntiEntropy()
	go gm.cleanupSeenMessages()

	for {
		select {
		case msg := <-gm.outbox:
			msg.ID = uuid.New().String()
			msg.Version = ProtocolVersion
			msg.Timestamp = time.Now().Unix()
			msg.Seq = atomic.AddInt64(&gm.localSeq, 1)

			gm.markSeen(msg.ID)
			gm.epidemicBroadcast(msg)
		case <-ctx.Done():
			// Stop waits for this goroutine too, so it is not called from here.
			gm.stopOnce.Do(func() { close(gm.stopCh) })
			return
		case <-done:
			return
		}
	}
}

func (gm *Manager) markSeen(id string) {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	// Enforce capacity limit
	if len(gm.seenMessages) >= gm.maxSeenEntries {
		gm.pruneSeenMessagesLocked()
	}

	gm.seenMessages[id] = time.Now()
}

func (gm *Manager) isSeen(id string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	_, ok := gm.seenMessages[id]
	return ok
}

// checkAndMarkSeen atomically checks if a message has been seen.
// If not seen, it marks it as seen and returns false.
// If already seen, it returns true.
func (gm *Manager) checkAndMarkSeen(id string) bool {
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

func (gm *Manager) isKnownPeer(name string) bool {
	for _, p := range gm.cfg.Peers {
		if p.Name == name {
			return true
		}
	}
	return false
}

// pruneSeenMessagesLocked removes expired messages and enforces the size limit.
// It must be called with mu.Lock() held.
func (gm *Manager) pruneSeenMessagesLocked() {
	now := time.Now()
	// 1. Remove expired messages
	for id, t := range gm.seenMessages {
		if now.Sub(t) > MaxAge {
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
		gm.logger().Warn("gossip: seen-message cache full, oldest entries dropped", "dropped", removedCount, "size_before", len(gm.seenMessages)+removedCount)
	}
}

func (gm *Manager) cleanupSeenMessages() {
	defer gm.workers.Done()
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	done := gm.life()
	for {
		select {
		case <-ticker.C:
			gm.mu.Lock()
			gm.pruneSeenMessagesLocked()
			gm.mu.Unlock()
		case <-done:
			return
		}
	}
}

func (gm *Manager) epidemicBroadcast(msg Message) {
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
		if peers[i].Name == gm.cfg.NodeName {
			continue
		}
		gm.enqueue(peers[i], msg)
		count++
	}
}

// startAntiEntropy sends every rule of this node to one peer, chosen anew every interval. It
// sends the batches itself, one after another: a snapshot is never queued whole, and a peer
// that is slow delays the next sync, not the rules that are shared as they are made.
func (gm *Manager) startAntiEntropy() {
	defer gm.workers.Done()
	ticker := time.NewTicker(gm.AntiEntropyInterval) // Run every interval
	defer ticker.Stop()
	done := gm.life()

	for {
		select {
		case <-ticker.C:
		case <-done:
			return
		}
		peers := gm.cfg.Peers
		if len(peers) == 0 {
			continue
		}

		// Select 1 random peer
		gm.rngMu.Lock()
		idx := gm.rng.Intn(len(peers))
		gm.rngMu.Unlock()
		peer := peers[idx]

		if peer.Name == gm.cfg.NodeName {
			continue
		}

		// Create snapshot
		snapshot := gm.actionEngine.GetSnapshot()

		// Chunking logic for large snapshots
		var batch []ActionRulePayload
		count := 0

		for _, rule := range snapshot {
			batch = append(batch, ActionRulePayload{
				Site:      rule.Site,
				RuleType:  string(rule.RuleType),
				Value:     rule.Value,
				Action:    string(rule.Action),
				ExpiresAt: rule.ExpiresAt.Unix(),
			})
			count++

			if count >= maxSyncEntriesBatch {
				gm.sendSyncBatch(peer, batch)
				// Reset batch
				batch = make([]ActionRulePayload, 0, maxSyncEntriesBatch)
				count = 0
			}
		}

		// Send remaining
		if len(batch) > 0 {
			gm.sendSyncBatch(peer, batch)
		}
	}
}

func (gm *Manager) sendSyncBatch(peer config.Peer, rules []ActionRulePayload) {
	msg := Message{
		Version:    ProtocolVersion,
		Type:       TypeSync,
		ID:         uuid.New().String(),
		OriginNode: gm.cfg.NodeName,
		Timestamp:  time.Now().Unix(),
		Rules:      rules,
	}

	if gm.stopped() {
		return
	}
	gm.sendGossip(gm.sender(peer), msg)
}

// sendGossip sends one message to the peer of s and waits for the answer.
func (gm *Manager) sendGossip(s *peerSender, msg Message) {
	p := s.peer
	url := p.Address + gm.cfg.WebPath + "/gossip"

	data, err := json.Marshal(msg)
	if err != nil {
		gm.logger().Error("gossip: message not encoded", "error", err.Error())
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		gm.logger().Error("gossip: request not created", "peer", p.Address, "error", err.Error())
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

	resp, err := s.client.Do(req)
	if err != nil {
		gm.logger().Warn("gossip: message not sent", "peer", p.Address, "error", err.Error())
		return
	}
	// The body is read to its end so the connection can be used again.
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusOK {
		gm.logger().Warn("gossip: peer refused the message", "peer", p.Address, "status", resp.StatusCode)
		return
	}
	gm.logger().Debug("gossip: message sent", "id", msg.ID, "type", string(msg.Type), "peer", p.Address)
}

func (gm *Manager) HandleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, ok := gm.readAndVerifyBody(w, r)
	if !ok {
		return
	}

	var msg Message
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Check msg.ID constraints (UUID v4)
	if msg.ID == "" {
		gm.dropped("empty message ID", "from", r.RemoteAddr)
		http.Error(w, "Forbidden: Empty Message ID", http.StatusForbidden)
		return
	}
	u, err := uuid.Parse(msg.ID)
	if err != nil {
		gm.dropped("message ID is not a UUID", "from", r.RemoteAddr, "id", msg.ID)
		http.Error(w, "Forbidden: Invalid Message ID", http.StatusForbidden)
		return
	}
	if u.Version() != 4 {
		gm.dropped("message ID is not a version 4 UUID", "from", r.RemoteAddr, "id", msg.ID)
		http.Error(w, "Forbidden: UUID v4 required", http.StatusForbidden)
		return
	}

	// Verify OriginNode is in Peers list
	if !gm.isKnownPeer(msg.OriginNode) {
		gm.dropped("origin is not a peer", "from", r.RemoteAddr, "origin", msg.OriginNode)
		http.Error(w, "Forbidden: Unknown OriginNode", http.StatusForbidden)
		return
	}

	// Replay Protection: Timestamp Validation
	now := time.Now()
	msgTime := time.Unix(msg.Timestamp, 0)

	if now.Sub(msgTime) > MaxAge {
		gm.dropped("message too old", "origin", msg.OriginNode, "timestamp", msg.Timestamp)
	} else if msgTime.Sub(now) > MaxSkew {
		gm.dropped("message from the future", "origin", msg.OriginNode, "timestamp", msg.Timestamp)
	} else {
		// Processing
		gm.processRemoteMessage(msg)
	}

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ACK")); err != nil {
		gm.logger().Warn("gossip: acknowledgement not written", "error", err.Error())
	}
}

func (gm *Manager) readAndVerifyBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	// Check Content-Length if provided
	if r.ContentLength > maxGossipBodySize {
		gm.dropped("request too large", "from", r.RemoteAddr, "content_length", r.ContentLength)
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return nil, false
	}

	// Verify HMAC-SHA512 Signature Header EARLY (before reading body)
	signatureHeader := r.Header.Get("X-Torii-Signature")
	if signatureHeader == "" {
		gm.dropped("no signature", "from", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	// SHA-512 is 64 bytes -> 128 hex characters
	if len(signatureHeader) != 128 {
		gm.dropped("signature has the wrong length", "from", r.RemoteAddr, "length", len(signatureHeader))
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	sigBytes, err := hex.DecodeString(signatureHeader)
	if err != nil {
		gm.dropped("signature is not hex", "from", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	// Limit Body Size
	r.Body = http.MaxBytesReader(w, r.Body, maxGossipBodySize)

	// Read Body (Protected by MaxBytesReader)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			gm.dropped("request too large", "from", r.RemoteAddr)
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		} else {
			gm.logger().Warn("gossip: request not read", "from", r.RemoteAddr, "error", err.Error())
			http.Error(w, "Failed to read body", http.StatusInternalServerError)
		}
		return nil, false
	}
	defer func() { _ = r.Body.Close() }()

	mac := hmac.New(sha512.New, []byte(gm.cfg.GlobalSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedMAC) {
		gm.dropped("wrong signature", "from", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return nil, false
	}

	return body, true
}

func (gm *Manager) processRemoteMessage(msg Message) {
	// Deduplication
	if gm.checkAndMarkSeen(msg.ID) {
		gm.logger().Debug("gossip: message seen before", "id", msg.ID, "origin", msg.OriginNode)
		return
	}
	gm.logger().Debug("gossip: message received", "id", msg.ID, "type", string(msg.Type), "origin", msg.OriginNode)
	if msg.Version != ProtocolVersion {
		gm.dropped("protocol version differs: upgrade every node of the cluster to the same release",
			"origin", msg.OriginNode, "version", msg.Version, "own_version", ProtocolVersion)
		return
	}
	now := time.Now()

	switch msg.Type {
	case TypeActionRule:
		gm.processActionRule(msg, now)
	case TypeSync:
		gm.processSync(msg, now)
	}
}

func (gm *Manager) processActionRule(msg Message, now time.Time) {
	if msg.Rule == nil {
		gm.dropped("message has no rule", "origin", msg.OriginNode)
		return
	}
	payload := *msg.Rule

	if err := validateActionRule(payload, now); err != nil {
		gm.dropped("invalid rule", "origin", msg.OriginNode, "error", err.Error())
		return
	}

	// Apply action rule
	ttl := time.Unix(payload.ExpiresAt, 0).Sub(now)
	if ttl > 0 {
		gm.actionEngine.AddRule(payload.Site, action.RuleKind(payload.RuleType), payload.Value, action.Action(payload.Action), ttl)
	}
	gm.logger().Info("gossip: rule received", "site", payload.Site, "kind", payload.RuleType, "value", payload.Value,
		"action", payload.Action, "expires", payload.ExpiresAt, "origin", msg.OriginNode)

	// Epidemic: Re-broadcast to infect others
	gm.epidemicBroadcast(msg)
}

func (gm *Manager) processSync(msg Message, now time.Time) {

	if len(msg.Rules) > maxSyncEntriesBatch {
		gm.dropped("sync has too many rules", "origin", msg.OriginNode, "rules", len(msg.Rules), "rule_limit", maxSyncEntriesBatch)
		return
	}

	invalidCount := 0
	for _, payload := range msg.Rules {
		if err := validateActionRule(payload, now); err != nil {
			invalidCount++
			if invalidCount <= 5 {
				gm.dropped("invalid rule in a sync", "origin", msg.OriginNode, "value", payload.Value, "expires", payload.ExpiresAt, "error", err.Error())
			}
			continue
		}

		ttl := time.Unix(payload.ExpiresAt, 0).Sub(now)
		if ttl > 0 {
			gm.actionEngine.AddRule(payload.Site, action.RuleKind(payload.RuleType), payload.Value, action.Action(payload.Action), ttl)
		}
	}

	if invalidCount > 0 {
		// Only the first 5 got a line of their own.
		gm.dropped("invalid rules in a sync", "origin", msg.OriginNode, "rules", invalidCount)
	}
}

const maxGossipBlockDuration = 7 * 24 * time.Hour

func validateActionRule(payload ActionRulePayload, now time.Time) error {
	// A rule without a site matches no request; an invalid one cannot belong to any site.
	if !config.ValidSiteID(payload.Site) {
		return fmt.Errorf("invalid site: %q", payload.Site)
	}

	trimmed := strings.TrimSpace(payload.Value)
	if trimmed == "" {
		return fmt.Errorf("empty rule value")
	}

	kind, err := action.ParseRuleKind(payload.RuleType)
	if err != nil {
		return err
	}
	if kind == action.RuleIP {
		ip := net.ParseIP(trimmed)
		if ip == nil {
			return fmt.Errorf("invalid ip format")
		}

		if ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() ||
			ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !ip.IsGlobalUnicast() {
			return fmt.Errorf("non-global ip")
		}
	}

	// Only the actions a temporary rule can carry; anything else would install a rule no check understands.
	if _, err := action.Parse(payload.Action, action.ActionBlock, action.ActionChallenge, action.ActionChallengeUnverified); err != nil {
		return err
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
