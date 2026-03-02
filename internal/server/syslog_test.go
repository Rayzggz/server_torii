package server

import (
	"fmt"
	"net"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync"
	"testing"
	"time"
)

// TestSyslogConcurrency verifies that the syslog listener handles high concurrency
// without crashing or spawning excessive goroutines (though we can't easily measure goroutines count per se in a simple test without runtime.NumGoroutine checks which might be flaky).
// We rely on the fact that we implemented a constrained worker pool.
func TestSyslogConcurrency(t *testing.T) {
	// Setup dependencies
	mockSharedMem := &dataType.SharedMemory{
		BlockList: dataType.NewBlockList(),
	}
	siteRules := make(map[string]*config.RuleSet)
	// Add a dummy rule to ensure logs are not discarded early
	siteRules["test_site"] = &config.RuleSet{
		AdaptiveTrafficAnalyzerRule: &dataType.AdaptiveTrafficAnalyzerRule{
			Tag:     "nginx",
			Enabled: true,
		},
	}

	analyzer := NewAdaptiveTrafficAnalyzer(siteRules, mockSharedMem)

	// Find a free port
	conn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatalf("failed to find free port: %v", err)
	}
	port := fmt.Sprintf("%d", conn.LocalAddr().(*net.UDPAddr).Port)
	conn.Close()

	// Start listener in a goroutine
	listener := NewSyslogListener(port, analyzer)
	if err := listener.Start(); err != nil {
		t.Fatalf("Failed to start listener: %v", err)
	}
	defer listener.Stop()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Connect to the server
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
	if err != nil {
		t.Fatalf("failed to resolve addr: %v", err)
	}
	client, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer client.Close()

	// Send more messages than buffer size to trigger dropping or filling buffer
	// Buffer is 10000. Send 15000.
	msgCount := 15000
	message := "<190>Jan 28 19:50:24 hostname nginx: 127.0.0.1 - - [28/Jan/2026:19:50:24 -0500] \"GET / HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0...\""

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			_, err := client.Write([]byte(message))
			if err != nil {
				t.Errorf("failed to write: %v", err)
				return
			}
			// Send as fast as possible
		}
	}()

	wg.Wait()

	// Allow some time for processing
	time.Sleep(1 * time.Second)

	// Verify server passes without panic.
	// We can inspect analyzer.buffer if we are in package server
	analyzer.buffer.mu.Lock()
	count := len(analyzer.buffer.entries)
	analyzer.buffer.mu.Unlock()

	t.Logf("Processed entries count: %d", count)

	if count == 0 {
		t.Error("Expected some entries to be processed, got 0")
	}

	// Since we drop messages when full, we expect count <= 15000 (likely much less if processing is slow, or full if fast enough)
	// But mostly we care that it didn't panic and accepted some logs.
}
