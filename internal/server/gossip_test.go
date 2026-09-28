package server

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Keep the peer alive until every asynchronous broadcast has arrived.
func newGossipTestPeer(t *testing.T, expectedRequests int) string {
	t.Helper()
	received := make(chan struct{}, expectedRequests)
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusOK)
		received <- struct{}{}
	}))
	t.Cleanup(func() {
		defer peer.Close()
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for i := 0; i < expectedRequests; i++ {
			select {
			case <-received:
			case <-timer.C:
				t.Errorf("received %d gossip broadcasts, want %d", i, expectedRequests)
				return
			}
		}
	})
	return peer.URL
}

func TestGossipManager_HandleGossip_OriginNodeValidation(t *testing.T) {
	// Setup
	cfg := &config.MainConfig{
		GlobalSecret: "secret123",
		NodeName:     "TestNode",
		Peers: []config.Peer{
			{Name: "KnownPeer", Address: "http://known.com"},
		},
	}

	// Mock BlockList (nil might be okay if we don't reach processing, but let's be safe)
	// Actually we need a valid blockList if processing happens.
	// We can avoid processing issues by using a message type that doesn't panic or requires less setup,
	// or just check if we get past the 403 check.
	// If we pass validation, HandleGossip calls processRemoteMessage.
	// processRemoteMessage uses gm.seenMessages (map) and gm.blockList.
	// So we need to init them.

	// Since we are only testing the validation logic, we can verify that
	// 1. Unknown peer returns 403.
	// 2. Known peer returns 200 (assuming processRemoteMessage works or doesn't crash immediately).
	// To be safe, let's init the map.

	gm := &GossipManager{
		cfg:          cfg,
		seenMessages: make(map[string]time.Time),
		// blockList is nil, so if we reach processRemoteMessage it might panic if it uses blockList.
		// However, for this test, we care about the 403 vs NON-403 (or panic, which means it passed validation).
		// Let's create a minimal blockList if possible, or just accept that 200/panic means validation passed.
		// A safer way is to check the response code.
	}
	// To avoid panic in processRemoteMessage, we can mock blockList or ensure we don't hit nil pointer.
	// NewGossipManager creates it. But that needs more deps.
	// Let's try to construct it minimally.
	// For "GossipTypeSync", it unmarshals content.
	// For "GossipTypeBlockIP", it calls blockList.BlockUntil.
	// If we send a message ID that is already seen, it returns early!
	// So we can pre-populate seenMessages to avoid BlockList interaction!

	msgID := uuid.New().String()
	gm.markSeen(msgID) // Mark as seen so processRemoteMessage returns early

	// Helper to create request
	createReq := func(originNode string) *http.Request {
		payload, _ := json.Marshal(dataType.ActionRulePayload{RuleType: "IP", Value: "1.2.3.4", Action: "BLOCK", ExpiresAt: time.Now().Add(1 * time.Hour).Unix()})
		msg := dataType.GossipMessage{
			ID:         msgID,
			OriginNode: originNode,
			Type:       dataType.GossipTypeActionRule,
			Content:    string(payload),
			Timestamp:  time.Now().Unix(),
		}
		data, _ := json.Marshal(msg)
		req := httptest.NewRequest("POST", "/gossip", bytes.NewBuffer(data))

		// Sign it
		mac := hmac.New(sha512.New, []byte(cfg.GlobalSecret))
		mac.Write(data)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Torii-Signature", signature)

		return req
	}

	// Test Case 1: Unknown OriginNode
	req1 := createReq("UnknownAttacker")
	w1 := httptest.NewRecorder()
	gm.HandleGossip(w1, req1)

	if w1.Code != http.StatusForbidden {
		t.Errorf("Expected 403 for unknown peer, got %d", w1.Code)
	}

	// Test Case 2: Known OriginNode
	req2 := createReq("KnownPeer")
	w2 := httptest.NewRecorder()

	// We mocked seenMessages, so processRemoteMessage should return immediately.
	// So we should get 200 OK and "ACK"
	gm.HandleGossip(w2, req2)

	if w2.Code != http.StatusOK {
		t.Errorf("Expected 200 for known peer, got %d. Body: %s", w2.Code, w2.Body.String())
	}
}
