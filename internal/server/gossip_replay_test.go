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
	"testing"
	"time"
)

func TestGossipManager_HandleGossip_ReplayProtection(t *testing.T) {
	cfg := &config.MainConfig{
		GlobalSecret: "secret123",
		NodeName:     "TestNode",
		Peers: []config.Peer{
			{Name: "KnownPeer", Address: "http://known.com"},
		},
	}

	createReq := func(ts int64, id string) *http.Request {
		msg := dataType.GossipMessage{
			ID:         id,
			OriginNode: "KnownPeer",
			Type:       dataType.GossipTypeBlockIP,
			Content:    "1.2.3.4",
			Timestamp:  ts,
		}
		data, _ := json.Marshal(msg)
		req := httptest.NewRequest("POST", "/gossip", bytes.NewBuffer(data))

		mac := hmac.New(sha512.New, []byte(cfg.GlobalSecret))
		mac.Write(data)
		signature := hex.EncodeToString(mac.Sum(nil))
		req.Header.Set("X-Torii-Signature", signature)
		return req
	}

	tests := []struct {
		name      string
		tsDelta   time.Duration // timestamp = now + delta
		shouldSee bool
	}{
		{
			name:      "Valid Timestamp (Now)",
			tsDelta:   0,
			shouldSee: true,
		},
		{
			name:      "Valid Timestamp (5 mins ago)",
			tsDelta:   -5 * time.Minute,
			shouldSee: true,
		},
		{
			name:      "Too Old (11 mins ago)",
			tsDelta:   -11 * time.Minute,
			shouldSee: false,
		},
		{
			name:      "Valid Future (1 min future)",
			tsDelta:   1 * time.Minute,
			shouldSee: true,
		},
		{
			name:      "Too Future (3 mins future)",
			tsDelta:   3 * time.Minute,
			shouldSee: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gm := NewGossipManager(cfg, dataType.NewBlockList())
			// Override start time/random dependencies if needed, but here simple logic suffices.

			id := "msg-" + tt.name
			req := createReq(time.Now().Add(tt.tsDelta).Unix(), id)
			w := httptest.NewRecorder()

			gm.HandleGossip(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected 200 OK, got %d", w.Code)
			}

			seen := gm.isSeen(id)
			if seen != tt.shouldSee {
				t.Errorf("Time delta %v: Expected seen=%v, but got seen=%v", tt.tsDelta, tt.shouldSee, seen)
			}
		})
	}
}
