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
)

func TestGossipManager_HandleGossip_DoS(t *testing.T) {
	cfg := &config.MainConfig{
		GlobalSecret: "secret123",
		NodeName:     "TestNode",
		Peers: []config.Peer{
			{Name: "KnownPeer", Address: "http://known.com"},
		},
	}
	gm := &GossipManager{
		cfg:          cfg,
		seenMessages: make(map[string]time.Time),
	}

	// 1. Test Small Request (Should pass size check, might fail signature/validation if we don't sign perfectly, but size is key)
	// We'll sign it correctly so we expect 200 or 403 (if validation fails later) but NOT 413.
	smallBody := strings.Repeat("a", 100) // 100 bytes
	reqSmall := createSignedGossipRequest(t, cfg, smallBody)
	wSmall := httptest.NewRecorder()
	gm.HandleGossip(wSmall, reqSmall)

	if wSmall.Code == http.StatusRequestEntityTooLarge {
		t.Errorf("Small request should not be rejected as too large")
	}

	// 2. Test Large Request (> 10MB)
	// We construct a fake body > 10MB
	largeBodySize := 10*1024*1024 + 500 // 10MB + 500 bytes
	// We can't use strings.Repeat for 10MB easily in memory without allocation, but it's fine for a test.
	// Actually 10MB is small enough for test memory (~20MB for string + bytes).
	// To be safer/faster, we can make a Reader that fails or just a large buffer.
	// But HandleGossip reads it all, so we must provide it.

	// Create a large body. We don't need real JSON because the size check happens during ReadAll.
	largeBody := make([]byte, largeBodySize)
	// Just fill with 'a'
	for i := 0; i < len(largeBody); i++ {
		largeBody[i] = 'a'
	}

	reqLarge := httptest.NewRequest("POST", "/gossip", bytes.NewReader(largeBody))
	// We still need to sign it roughly or at least contain the headers so it doesn't fail early on Method check.
	// Actually, HandleGossip checks Method, then reads body. So we don't even need a valid signature to trigger Body Read if we pass Method.
	// Wait, code order:
	// 1. Method Check
	// 2. Read Body (this is where it should fail)
	// 3. Verify Signature

	// So signature is not needed to trigger 413.

	wLarge := httptest.NewRecorder()
	gm.HandleGossip(wLarge, reqLarge)

	if wLarge.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("Expected 413 Request Entity Too Large, got %d", wLarge.Code)
	}
}

func createSignedGossipRequest(t *testing.T, cfg *config.MainConfig, bodyStr string) *http.Request {
	msg := dataType.GossipMessage{
		ID:         "test-id",
		OriginNode: "KnownPeer",
		Type:       dataType.GossipTypeBlockIP,
		Content:    "1.2.3.4",
		Timestamp:  time.Now().Unix(),
	}
	// We ignore bodyStr for JSON structure if we want valid JSON,
	// but here we just want to test size limits essentially.
	// However, for the "Small Request" pass, we want valid JSON to avoid 400.

	data, _ := json.Marshal(msg)
	// If bodyStr is just random string, unmarshal fails.
	// Let's use the marshaled data as the body for the small request.

	req := httptest.NewRequest("POST", "/gossip", bytes.NewBuffer(data))

	mac := hmac.New(sha512.New, []byte(cfg.GlobalSecret))
	mac.Write(data)
	signature := hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Torii-Signature", signature)

	return req
}
