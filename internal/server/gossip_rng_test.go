package server

import (
	"testing"
	"time"

	"server_torii/internal/config"
	"server_torii/internal/dataType"
)

func TestGossipManager_RNG_Seeding(t *testing.T) {
	cfg := &config.MainConfig{
		NodeName: "test-node",
		Peers:    []config.Peer{{Name: "p1", Address: "http://localhost:8080"}},
	}
	bl := dataType.NewBlockList()

	// Create two managers with a delay to ensure different seeds
	gm1 := NewGossipManager(cfg, bl)
	time.Sleep(2 * time.Nanosecond) // Ensure time.Now().UnixNano() changes
	gm2 := NewGossipManager(cfg, bl)

	if gm1.rng == nil {
		t.Fatal("gm1.rng is nil")
	}
	if gm2.rng == nil {
		t.Fatal("gm2.rng is nil")
	}

	// Verify they are different instances
	if gm1.rng == gm2.rng {
		t.Fatal("gm1.rng and gm2.rng point to the same instance")
	}

	// Verify they produce different streams (statistically likely)
	// We'll draw a few numbers. If they are identical for a long sequence, they have same seed.
	// (Note: default Source(1) would be identical)

	// We need to lock because the test might run in parallel or we just want to be safe,
	// though here we are single threaded per GM.
	v1 := gm1.rng.Int63()
	v2 := gm2.rng.Int63()

	if v1 == v2 {
		// Extremely unlikely to be equal if seeded differently.
		// Try one more just in case of collision
		v1 = gm1.rng.Int63()
		v2 = gm2.rng.Int63()
		if v1 == v2 {
			t.Errorf("RNGs appear to be using the same seed (values: %d, %d)", v1, v2)
		}
	}
}

func TestGossipManager_RNG_Locking(t *testing.T) {
	// Basic test to ensure no data race when using the RNG.
	// The -race detector will catch this if we run with it,
	// but here we just ensure it runs.
	cfg := &config.MainConfig{
		NodeName: "test-node",
		Peers:    make([]config.Peer, 10),
	}
	for i := 0; i < 10; i++ {
		cfg.Peers[i] = config.Peer{Name: "p", Address: "http://localhost:8080"}
	}
	bl := dataType.NewBlockList()
	gm := NewGossipManager(cfg, bl)

	// Simulate concurrent access
	done := make(chan bool)
	go func() {
		gm.epidemicBroadcast(dataType.GossipMessage{ID: "test"})
		done <- true
	}()
	go func() {
		gm.epidemicBroadcast(dataType.GossipMessage{ID: "test2"})
		done <- true
	}()

	<-done
	<-done
}
