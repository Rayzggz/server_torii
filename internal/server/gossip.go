package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync"
	"time"

	"github.com/google/uuid"
)

type GossipManager struct {
	cfg                 *config.MainConfig
	blockList           *dataType.BlockList
	seenMessages        map[string]time.Time
	mu                  sync.RWMutex
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
			if now.Sub(t) > 1*time.Hour { // Keep seen IDs for 1 hour to prevent cycles
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
	defer resp.Body.Close()

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
	defer r.Body.Close()

	// Verify HMAC-SHA512 Signature
	signatureHeader := r.Header.Get("X-Torii-Signature")
	if signatureHeader == "" {
		log.Printf("[SECURITY] Missing signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	mac := hmac.New(sha512.New, []byte(gm.cfg.GlobalSecret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	if subtle.ConstantTimeCompare([]byte(signatureHeader), []byte(expectedSignature)) != 1 {
		log.Printf("[SECURITY] Invalid signature from %s", r.RemoteAddr)
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var msg dataType.GossipMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Processing
	gm.processRemoteMessage(msg)

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ACK"))
}

func (gm *GossipManager) processRemoteMessage(msg dataType.GossipMessage) {
	// Deduplication
	if gm.isSeen(msg.ID) {
		return
	}
	gm.markSeen(msg.ID)

	switch msg.Type {
	case dataType.GossipTypeBlockIP:
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

		for ip, expiration := range snapshot {
			gm.blockList.BlockUntil(ip, expiration)
		}
	}
}
