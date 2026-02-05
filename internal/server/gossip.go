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
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

const (
	GossipMaxSkew = 2 * time.Minute
	GossipMaxAge  = 10 * time.Minute
)

type GossipManager struct {
	cfg                 *config.MainConfig
	blockList           *dataType.BlockList
	seenMessages        map[string]time.Time
	mu                  sync.RWMutex
	localSeq            int64
	AntiEntropyInterval time.Duration
}

func NewGossipManager(cfg *config.MainConfig, blockList *dataType.BlockList) *GossipManager {
	return &GossipManager{
		cfg:                 cfg,
		blockList:           blockList,
		seenMessages:        make(map[string]time.Time),
		AntiEntropyInterval: 30 * time.Second,
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
	gm.seenMessages[id] = time.Now()
}

func (gm *GossipManager) isSeen(id string) bool {
	gm.mu.RLock()
	defer gm.mu.RUnlock()
	_, ok := gm.seenMessages[id]
	return ok
}

func (gm *GossipManager) cleanupSeenMessages() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		gm.mu.Lock()
		now := time.Now()
		for id, t := range gm.seenMessages {
			if now.Sub(t) > GossipMaxAge { // Keep seen IDs for 10 min
				delete(gm.seenMessages, id)
			}
		}
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
	perm := rand.Perm(len(peers))
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
		peer := peers[rand.Intn(len(peers))]

		// Create snapshot
		snapshot := gm.blockList.GetSnapshot()
		content, err := json.Marshal(snapshot)
		if err != nil {
			log.Printf("[ERROR] Failed to marshal snapshot for anti-entropy: %v", err)
			continue
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

	// Read Body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusInternalServerError)
		return
	}
	defer func() {
		if err := r.Body.Close(); err != nil {
			log.Printf("[WARNING] HandleGossip: Failed to close request body: %v", err)
		}
	}()

	// Verify HMAC-SHA512 Signature
	signatureHeader := r.Header.Get("X-Torii-Signature")
	if signatureHeader == "" {
		log.Printf("[SECURITY] Missing signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	sigBytes, err := hex.DecodeString(signatureHeader)
	if err != nil {
		log.Printf("[SECURITY] Invalid signature format from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	mac := hmac.New(sha512.New, []byte(gm.cfg.GlobalSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)

	if !hmac.Equal(sigBytes, expectedMAC) {
		log.Printf("[SECURITY] Invalid signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var msg dataType.GossipMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Verify OriginNode is in Peers list
	knownPeer := false
	for _, p := range gm.cfg.Peers {
		if p.Name == msg.OriginNode {
			knownPeer = true
			break
		}
	}

	if !knownPeer {
		log.Printf("[SECURITY] Received gossip from unknown node: %s", msg.OriginNode)
		http.Error(w, "Forbidden: Unknown OriginNode", http.StatusForbidden)
		return
	}

	// Replay Protection: Timestamp Validation
	now := time.Now()
	msgTime := time.Unix(msg.Timestamp, 0)

	if now.Sub(msgTime) > GossipMaxAge {
		log.Printf("[SECURITY] Dropped old gossip from %s: ts=%d", msg.OriginNode, msg.Timestamp)
		// We don't error 403 here because it might be just lag, but we act as if we processed it (OK) or just ignore.
		// Returning OK to stop retry storm if any.
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ACK")); err != nil {
			log.Printf("[ERROR] Failed to write ACK response: %v", err)
		}
		return
	}

	if msgTime.Sub(now) > GossipMaxSkew {
		log.Printf("[SECURITY] Dropped future gossip from %s: ts=%d", msg.OriginNode, msg.Timestamp)
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ACK")); err != nil {
			log.Printf("[ERROR] Failed to write ACK response: %v", err)
		}
		return
	}

	// Processing
	gm.processRemoteMessage(msg)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write([]byte("ACK")); err != nil {
		log.Printf("[ERROR] Failed to write ACK response: %v", err)
	}
}

func (gm *GossipManager) processRemoteMessage(msg dataType.GossipMessage) {
	// Deduplication
	if gm.isSeen(msg.ID) {
		return
	}
	gm.markSeen(msg.ID)
	now := time.Now()

	switch msg.Type {
	case dataType.GossipTypeBlockIP:
		if err := validateGossipBlock(msg.Content, msg.Expiration, now); err != nil {
			log.Printf("[SECURITY] Dropped gossip BlockIP from %s: ip=%q exp=%d err=%v", msg.OriginNode, msg.Content, msg.Expiration, err)
			return
		}
		// Apply block
		gm.blockList.BlockUntil(msg.Content, msg.Expiration)
		log.Printf("[GOSSIP] Received BlockIP for %s from %s (Exp: %d)", msg.Content, msg.OriginNode, msg.Expiration)

		// Epidemic: Re-broadcast to infect others
		gm.epidemicBroadcast(msg)

	case dataType.GossipTypeSync:
		log.Printf("[GOSSIP] Received SYNC from %s", msg.OriginNode)
		var snapshot map[string]int64
		if err := json.Unmarshal([]byte(msg.Content), &snapshot); err != nil {
			log.Printf("[ERROR] Failed to unmarshal sync snapshot: %v", err)
			return
		}

		invalidCount := 0
		for ip, expiration := range snapshot {
			if err := validateGossipBlock(ip, expiration, now); err != nil {
				invalidCount++
				if invalidCount <= 5 {
					log.Printf("[SECURITY] Dropped gossip SYNC entry from %s: ip=%q exp=%d err=%v", msg.OriginNode, ip, expiration, err)
				}
				continue
			}
			gm.blockList.BlockUntil(ip, expiration)
		}

		if invalidCount > 0 {
			if invalidCount > 5 {
				log.Printf("[SECURITY] Dropped %d invalid SYNC entries from %s (only first 5 shown)", invalidCount, msg.OriginNode)
			} else {
				log.Printf("[SECURITY] Dropped %d invalid SYNC entries from %s", invalidCount, msg.OriginNode)
			}
		}
	}
}

const maxGossipBlockDuration = 7 * 24 * time.Hour

func validateGossipBlock(ipStr string, expiration int64, now time.Time) error {
	trimmed := strings.TrimSpace(ipStr)
	if trimmed == "" {
		return fmt.Errorf("empty ip")
	}

	ip := net.ParseIP(trimmed)
	if ip == nil {
		return fmt.Errorf("invalid ip format")
	}

	if ip.IsPrivate() || ip.IsLoopback() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || !ip.IsGlobalUnicast() {
		return fmt.Errorf("non-global ip")
	}

	nowUnix := now.Unix()
	if expiration <= nowUnix {
		return fmt.Errorf("expiration already passed")
	}

	maxExpiration := nowUnix + int64(maxGossipBlockDuration/time.Second)
	if expiration > maxExpiration {
		return fmt.Errorf("expiration exceeds max allowed duration")
	}

	return nil
}
