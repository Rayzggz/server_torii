package server

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

type GossipManager struct {
	cfg       *config.MainConfig
	blockList *dataType.BlockList
}

func NewGossipManager(cfg *config.MainConfig, blockList *dataType.BlockList) *GossipManager {
	return &GossipManager{
		cfg:       cfg,
		blockList: blockList,
	}
}

func (gm *GossipManager) Start(gossipChan <-chan dataType.GossipMessage) {
	log.Printf("GossipManager started, listening for events...")
	for msg := range gossipChan {
		if msg.Source == "local" {
			gm.broadcast(msg)
		}
	}
}

func (gm *GossipManager) broadcast(msg dataType.GossipMessage) {
	// Set source to this node's name or address to prevent loops if we had full mesh without "local" check
	// But "local" check in Start handles it.
	// We should probably set msg.Source to cfg.NodeName when sending,
	// but the receiver handles it by just blocking.

	client := &http.Client{}

	for _, peer := range gm.cfg.Peers {
		go func(p config.Peer) {
			// Construct URL: peer.Address + WebPath + /gossip
			url := p.Address + gm.cfg.WebPath + "/gossip"

			// Marshal message
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
			if p.Host != "" {
				req.Host = p.Host
			}

			// Fire and forget, or log error
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("[WARNING] Failed to send gossip to peer %s: %v", p.Address, err)
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("[WARNING] Peer %s returned status %d", p.Address, resp.StatusCode)
			}
		}(peer)
	}
}

func (gm *GossipManager) HandleGossip(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg dataType.GossipMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	if msg.Type == dataType.GossipTypeBlockIP {
		log.Printf("[GOSSIP] Received BlockIP for %s from %s", msg.Content, msg.Source)
		// Use Block directly as it doesn't broadcast anymore (broadcast is separate)
		gm.blockList.Block(msg.Content, msg.Duration)
		//TODD: Not duplicating the broadcast to avoid loops
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ACK"))
}
