package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
