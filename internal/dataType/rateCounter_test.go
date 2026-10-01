package dataType

import (
	"sync"
	"testing"
	"time"

	"github.com/cespare/xxhash/v2"
)

func TestCounterElementWindowAndRollover(t *testing.T) {
	c := newCounterElement(5)
	c.counterElementAdd(100, 2)
	c.counterElementAdd(100, 3)
	c.counterElementAdd(102, 7)
	for _, tc := range []struct{ window, now, want int64 }{
		{0, 102, 0}, {1, 102, 7}, {2, 102, 7}, {3, 102, 12},
		{10, 102, 12}, {2, 104, 0}, {5, 107, 0},
	} {
		if got := c.counterElementQuery(tc.window, tc.now); got != tc.want {
			t.Errorf("Query(%d, %d) = %d, want %d", tc.window, tc.now, got, tc.want)
		}
	}
	c.counterElementAdd(105, 11)
	if got := c.counterElementQuery(5, 105); got != 18 {
		t.Errorf("rollover = %d, want 18", got)
	}
	if c.lastUpdated != 105 {
		t.Errorf("lastUpdated = %d", c.lastUpdated)
	}
}

func TestCounterConcurrentAddAndReset(t *testing.T) {
	c := NewCounter(4, 3600)
	if c.GetSegSize() != 3600 {
		t.Fatal("incorrect segment size")
	}
	if got := c.Query("missing", 10); got != 0 {
		t.Fatalf("missing key = %d", got)
	}
	if got := c.QueryBatch("missing", []int64{1, 5}); len(got) != 2 || got[0] != 0 || got[1] != 0 {
		t.Fatalf("missing batch = %v", got)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				c.Add("shared", 1)
				c.Query("shared", 3600)
			}
		}()
	}
	wg.Wait()
	c.Add("other", 9)
	if got := c.Query("shared", 3600); got != 800 {
		t.Errorf("concurrent total = %d, want 800", got)
	}
	c.Reset("shared")
	c.Reset("missing")
	if got := c.Query("shared", 3600); got != 0 {
		t.Errorf("reset total = %d", got)
	}
	if got := c.Query("other", 3600); got != 9 {
		t.Errorf("reset affected another key: %d", got)
	}
}

func TestCounterGarbageCollection(t *testing.T) {
	c := NewCounter(2, 60)
	now := time.Now().Unix()
	for key, timestamp := range map[string]int64{"expired": now - 120, "active": now} {
		element := newCounterElement(60)
		element.counterElementAdd(timestamp, 7)
		c.getBucket(key).counters[xxhash.Sum64String(key)] = element
	}
	c.GC()
	if _, ok := c.getBucket("expired").counters[xxhash.Sum64String("expired")]; ok {
		t.Fatal("expired counter retained")
	}
	if got := c.Query("active", 60); got != 7 {
		t.Errorf("active counter lost: %d", got)
	}
}

func TestCounterBatchSingleWindow(t *testing.T) {
	c := NewCounter(2, 60)
	c.Add("client", 4)
	c.Add("client", 6)
	if got := c.QueryBatch("client", []int64{60}); len(got) != 1 || got[0] != 10 {
		t.Fatalf("batch total = %v, want [10]", got)
	}
}
