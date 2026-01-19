package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
)

// setupTestNode creates a GossipManager and a httptest.Server that mocks the peer.
// It returns the manager, the server, the BlockList, and a pointer to a request counter.
func setupTestNode(name string, port string, secret string) (*GossipManager, *httptest.Server, *dataType.BlockList, *int64) {
	bl := dataType.NewBlockList()
	cfg := &config.MainConfig{
		NodeName:     name,
		Port:         port,
		WebPath:      "/torii",
		GlobalSecret: secret,
		// Peers will be populated later
	}

	gm := NewGossipManager(cfg, bl)

	var reqCount int64

	// Create a test server that routes /torii/gossip to gm.HandleGossip
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/torii/gossip" {
			atomic.AddInt64(&reqCount, 1)
			gm.HandleGossip(w, r)
			return
		}
		http.NotFound(w, r)
	}))

	return gm, ts, bl, &reqCount
}

func TestGossipSimulation(t *testing.T) {
	nodeCount := 10
	globalSecret := "this-is-a-very-secure-secret-key-32-chars-long" // Must be >32 chars

	var managers []*GossipManager
	var servers []*httptest.Server
	var blockLists []*dataType.BlockList
	var gossipChans []chan dataType.GossipMessage
	var reqCounts []*int64

	// 1. Setup Nodes
	for i := 0; i < nodeCount; i++ {
		name := fmt.Sprintf("Node-%d", i)
		gm, ts, bl, rc := setupTestNode(name, "8080", globalSecret)
		managers = append(managers, gm)
		servers = append(servers, ts)
		blockLists = append(blockLists, bl)
		gossipChans = append(gossipChans, make(chan dataType.GossipMessage, 10))
		reqCounts = append(reqCounts, rc)
	}

	// 2. Configure Peers (Full Mesh)
	for i := 0; i < nodeCount; i++ {
		var peers []config.Peer
		for j := 0; j < nodeCount; j++ {
			if i == j {
				continue
			}
			peers = append(peers, config.Peer{
				Address: servers[j].URL,
			})
		}
		managers[i].cfg.Peers = peers
	}

	// 3. Start GossipManagers
	for i := 0; i < nodeCount; i++ {
		go managers[i].Start(gossipChans[i])
	}

	defer func() {
		for _, ts := range servers {
			ts.Close()
		}
	}()

	// 4. Inject a Message into Node 0
	targetIP := "192.168.1.100"
	msgID := uuid.New().String()
	expiration := time.Now().Add(1 * time.Hour).Unix()
	msg := dataType.GossipMessage{
		ID:         msgID,
		Type:       dataType.GossipTypeBlockIP,
		OriginNode: managers[0].cfg.NodeName,
		Content:    targetIP,
		Expiration: expiration,
	}

	// Simulator: Manually block on Origin Node because GossipManager.Start loop only broadcasts own msgs
	blockLists[0].BlockUntil(targetIP, expiration)

	fmt.Printf("Injecting gossip message into Node 0: BlockIP %s\n", targetIP)
	gossipChans[0] <- msg

	// 5. Wait for convergence
	// Note: Epidemic broadcast is probabilistic. With N=10, K=3, it usually reaches everyone,
	// but can occasionally leave 1-2 nodes isolated until Anti-Entropy picks them up.
	// We wait enough time for Anti-Entropy (30s) to kick in if needed.
	timeout := time.After(45 * time.Second)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	converged := false
	aeLogged := false

	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for gossip convergence")
		case <-ticker.C:
			countHasIt := 0
			for i := 0; i < nodeCount; i++ {
				if blockLists[i].IsBlocked(targetIP) {
					countHasIt++
				}
			}

			// Calculate total requests
			var totalReqs int64
			for _, rc := range reqCounts {
				totalReqs += atomic.LoadInt64(rc)
			}

			if !converged { // Only log convergence progress if not done
				fmt.Printf("Convergence status: %d/%d nodes. Total Requests: %d\n", countHasIt, nodeCount, totalReqs)
			}

			if countHasIt == nodeCount {
				converged = true
				break
			}

			// If 5 seconds passed and not converged, log about AE
			if !aeLogged && totalReqs > 0 && countHasIt < nodeCount {
				// Rough heuristic: if we have activity but stuck
				// We can check time, but for simplicity:
				aeLogged = true
				fmt.Println("Epidemic phase finished or stalled. Waiting for Anti-Entropy to heal partitions (approx 30s)...")
			}
		}
		if converged {
			break
		}
	}

	if !converged {
		t.Errorf("Failed to converge on all %d nodes", nodeCount)
	} else {
		fmt.Println("SUCCESS: All nodes blocked the IP via gossip!")
	}

	// 6. Broadcast Storm / Efficiency Check
	var totalReqs int64
	for i, rc := range reqCounts {
		c := atomic.LoadInt64(rc)
		fmt.Printf("Node %d recieved %d requests\n", i, c)
		totalReqs += c
	}
	fmt.Printf("Total network requests: %d\n", totalReqs)

	// Expectation:
	// Epidemic: ~ N * Fanout (10 * 3 = 30)
	// AE: 1 request every 30s per node.
	// Total should be well under 1000.
	if totalReqs > 500 {
		t.Errorf("FAIL: Broadcast storm detected! Total requests: %d", totalReqs)
	} else {
		t.Logf("PASS: No broadcast storm. efficiency is acceptable (%d requests).", totalReqs)
	}
}

func TestAntiEntropyRecovery(t *testing.T) {
	nodeCount := 10
	globalSecret := "this-is-a-very-secure-secret-key-32-chars-long"

	var managers []*GossipManager
	var servers []*httptest.Server
	var blockLists []*dataType.BlockList
	var gossipChans []chan dataType.GossipMessage

	// 1. Setup Nodes
	for i := 0; i < nodeCount; i++ {
		name := fmt.Sprintf("Node-%d", i)
		// Note: setupTestNode returns 4 values now, assume we ignore reqCount for this test or update helper usage
		gm, ts, bl, _ := setupTestNode(name, "8080", globalSecret)

		// FAST Anti-Entropy for testing
		gm.AntiEntropyInterval = 100 * time.Millisecond

		managers = append(managers, gm)
		servers = append(servers, ts)
		blockLists = append(blockLists, bl)
		gossipChans = append(gossipChans, make(chan dataType.GossipMessage, 10))
	}

	// 2. Configure Peers (Full Mesh)
	for i := 0; i < nodeCount; i++ {
		var peers []config.Peer
		for j := 0; j < nodeCount; j++ {
			if i == j {
				continue
			}
			peers = append(peers, config.Peer{
				Address: servers[j].URL,
			})
		}
		managers[i].cfg.Peers = peers
	}

	// 3. Start GossipManagers
	for i := 0; i < nodeCount; i++ {
		go managers[i].Start(gossipChans[i])
	}

	defer func() {
		for _, ts := range servers {
			ts.Close()
		}
	}()

	// 4. Inject MULTIPLE "Silent" Updates into Node 0
	// We do NOT send to gossipChan, so it won't trigger Epidemic broadcast.
	// We only add it to BlockList directly.
	ips := []string{"10.0.0.91", "10.0.0.92", "10.0.0.93", "10.0.0.94", "10.0.0.95"}
	expiration := time.Now().Add(1 * time.Hour).Unix()

	for _, ip := range ips {
		fmt.Printf("Silently blocking IP %s on Node 0 (Expect propagation via Anti-Entropy)\n", ip)
		blockLists[0].BlockUntil(ip, expiration)
	}

	// Verify that initially, others don't have them
	time.Sleep(50 * time.Millisecond)
	for _, bl := range blockLists[1:] {
		for _, ip := range ips {
			if bl.IsBlocked(ip) {
				t.Fatalf("Node has IP %s too early! Epidemic might have leaked or test timing is wrong.", ip)
			}
		}
	}

	// 5. Wait for Anti-Entropy to converge
	// With 100ms interval, it should happen relatively quickly (~seconds)
	timeout := time.After(10 * time.Second)
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	converged := false
	for {
		select {
		case <-timeout:
			t.Fatal("Timeout waiting for Anti-Entropy convergence")
		case <-ticker.C:
			allNodesHaveAllIPs := true
			nodesWithAllIPs := 0

			for i := 0; i < nodeCount; i++ {
				nodeHasAll := true
				for _, ip := range ips {
					if !blockLists[i].IsBlocked(ip) {
						nodeHasAll = false
						break
					}
				}
				if nodeHasAll {
					nodesWithAllIPs++
				} else {
					allNodesHaveAllIPs = false
				}
			}

			fmt.Printf("AE Convergence: %d/%d nodes have all %d IPs\n", nodesWithAllIPs, nodeCount, len(ips))

			if allNodesHaveAllIPs {
				converged = true
				break
			}
		}
		if converged {
			break
		}
	}

	if !converged {
		t.Errorf("Anti-Entropy failed to propagate all blocks to all nodes")
	} else {
		fmt.Println("SUCCESS: Anti-Entropy successfully synchronized all nodes with multiple messages!")
	}
}
