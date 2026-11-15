package gossip

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"server_torii/internal/config"
	"sync/atomic"
	"testing"
	"time"
)

// A peer that does not answer must not cost a goroutine per message: its queue fills, the
// rest is dropped, and nothing piles up behind it.
func TestAPeerThatDoesNotAnswerHoldsOneSender(t *testing.T) {
	release := make(chan struct{})
	var requests atomic.Int64
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		<-release
	}))
	defer slow.Close()

	cfg := &config.MainConfig{NodeName: "node-a", WebPath: "/torii", GlobalSecret: "test-secret", Peers: []config.Peer{
		{Name: "slow-1", Address: slow.URL}, {Name: "slow-2", Address: slow.URL}, {Name: "slow-3", Address: slow.URL},
	}}
	gm := NewManager(cfg, nil, nil)

	before := runtime.NumGoroutine()
	const messages = 5000
	for i := 0; i < messages; i++ {
		gm.epidemicBroadcast(Message{Version: ProtocolVersion, Type: TypeActionRule, ID: "m"})
	}
	// Every sender is now stuck in its first request.
	deadline := time.Now().Add(5 * time.Second)
	for requests.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if got := requests.Load(); got != 3 {
		t.Fatalf("requests in flight = %d, want one per peer", got)
	}
	// One sender per peer, with the goroutines of its one connection; not one per message.
	if grown := runtime.NumGoroutine() - before; grown > 30 {
		t.Fatalf("%d goroutines for %d messages to peers that do not answer", grown, messages)
	}
	queued, dropped := 0, 0
	for _, s := range gm.senders {
		queued += len(s.queue)
		s.mu.Lock()
		dropped += s.dropped
		s.mu.Unlock()
	}
	if queued != 3*peerQueueSize {
		t.Fatalf("queued = %d, want every queue full at %d", queued, peerQueueSize)
	}
	// The first message that did not fit was logged and reset the count of its sender.
	if want := 3*messages - 3 - 3*peerQueueSize - 3; dropped != want {
		t.Fatalf("dropped = %d, want %d", dropped, want)
	}

	// Stop ends the senders once the requests in flight return, and leaves what was queued.
	close(release)
	stopped := make(chan struct{})
	go func() { gm.Stop(); close(stopped) }()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return")
	}
	gm.epidemicBroadcast(Message{ID: "after stop"})
	gm.Stop()
}

// Start returns when its context is done, and takes its tickers and senders with it.
func TestStartEndsWithItsContext(t *testing.T) {
	var received atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { received.Add(1) }))
	defer peer.Close()

	cfg := &config.MainConfig{NodeName: "node-a", WebPath: "/torii", GlobalSecret: "test-secret", Peers: []config.Peer{{Name: "node-b", Address: peer.URL}}}
	gm := NewManager(cfg, nil, nil)
	gm.AntiEntropyInterval = time.Hour

	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	returned := make(chan struct{})
	go func() { gm.Start(ctx); close(returned) }()

	gm.ShareRule("shop", "IP", "203.0.113.9", "block", time.Minute)
	deadline := time.Now().Add(5 * time.Second)
	for received.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if received.Load() != 1 {
		t.Fatalf("the peer received %d messages, want 1", received.Load())
	}

	cancel()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("Start did not return when its context was done")
	}
	gm.Stop()
	peer.CloseClientConnections()
	deadline = time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > before+2 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if left := runtime.NumGoroutine() - before; left > 2 {
		t.Fatalf("%d goroutines left after Stop", left)
	}
}
