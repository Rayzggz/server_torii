package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGossipSecurityFixes(t *testing.T) {
	// Helper to create a fresh setup for each test
	setup := func() (*GossipManager, *dataType.BlockList, *config.MainConfig) {
		cfg := &config.MainConfig{
			NodeName:     "test-node",
			WebPath:      "/torii",
			GlobalSecret: "test-secret-key-1234",
			Peers: []config.Peer{
				{Name: "valid-peer", Address: "http://localhost:8081"},
			},
		}
		bl := dataType.NewBlockList()
		gm := NewGossipManager(cfg, bl)
		return gm, bl, cfg
	}

	// Helper to create a signed request
	createSignedRequest := func(msg dataType.GossipMessage, cfg *config.MainConfig) *http.Request {
		body, _ := json.Marshal(msg)
		req := httptest.NewRequest("POST", "/torii/gossip", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")

		mac := hmac.New(sha512.New, []byte(cfg.GlobalSecret))
		mac.Write(body)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Torii-Signature", signature)
		return req
	}

	t.Run("RejectEmptyMessageID", func(t *testing.T) {
		gm, _, cfg := setup()
		msg := dataType.GossipMessage{
			Type:       dataType.GossipTypeBlockIP,
			ID:         "", // Empty ID
			OriginNode: "valid-peer",
			Timestamp:  time.Now().Unix(),
			Content:    "1.2.3.4",
			Expiration: time.Now().Add(1 * time.Hour).Unix(),
		}

		req := createSignedRequest(msg, cfg)
		w := httptest.NewRecorder()
		gm.HandleGossip(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status Forbidden (403), got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Empty Message ID") {
			t.Errorf("Expected response body to contain 'Empty Message ID', got %q", w.Body.String())
		}
	})

	t.Run("RejectInvalidUUID", func(t *testing.T) {
		gm, _, cfg := setup()
		msg := dataType.GossipMessage{
			Type:       dataType.GossipTypeBlockIP,
			ID:         "not-a-uuid", // Invalid UUID
			OriginNode: "valid-peer",
			Timestamp:  time.Now().Unix(),
			Content:    "1.2.3.4",
			Expiration: time.Now().Add(1 * time.Hour).Unix(),
		}

		req := createSignedRequest(msg, cfg)
		w := httptest.NewRecorder()
		gm.HandleGossip(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Expected status Forbidden (403), got %d", w.Code)
		}
		if !strings.Contains(w.Body.String(), "Invalid Message ID") {
			t.Errorf("Expected response body to contain 'Invalid Message ID', got %q", w.Body.String())
		}
	})

	t.Run("AcceptValidUUID", func(t *testing.T) {
		gm, _, cfg := setup()
		msg := dataType.GossipMessage{
			Type:       dataType.GossipTypeBlockIP,
			ID:         uuid.New().String(), // Valid UUID
			OriginNode: "valid-peer",
			Timestamp:  time.Now().Unix(),
			Content:    "1.2.3.4",
			Expiration: time.Now().Add(1 * time.Hour).Unix(),
		}

		req := createSignedRequest(msg, cfg)
		w := httptest.NewRecorder()
		gm.HandleGossip(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status OK (200), got %d", w.Code)
		}
	})

	// Testing internal processing logic directly for SYNC limit as it logs and drops, doesn't return HTTP error
	t.Run("DropOversizedSyncSnapshot", func(t *testing.T) {
		gm, bl, _ := setup()

		// Create a large snapshot
		snapshot := make(map[string]int64)
		for i := 0; i < maxSyncEntriesBatch+10; i++ {
			snapshot[uuid.New().String()] = time.Now().Add(1 * time.Hour).Unix()
		}

		content, _ := json.Marshal(snapshot)

		msg := dataType.GossipMessage{
			Type:       dataType.GossipTypeSync,
			ID:         uuid.New().String(),
			OriginNode: "valid-peer",
			Timestamp:  time.Now().Unix(),
			Content:    string(content),
		}

		// Initial state: blocklist empty
		if len(bl.GetSnapshot()) != 0 {
			t.Errorf("Expected blocklist to be empty initially, got %d entries", len(bl.GetSnapshot()))
		}

		// Process
		gm.processRemoteMessage(msg)

		// Assert: Blocklist should STILL be empty because the sync message was dropped
		if len(bl.GetSnapshot()) != 0 {
			t.Errorf("Blocklist should be empty as oversized sync was dropped, got %d entries", len(bl.GetSnapshot()))
		}
	})
}
