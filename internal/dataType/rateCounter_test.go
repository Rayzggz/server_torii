package dataType

import (
	"slices"
	"sync"
	"testing"
	"time"
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
		bucket, h := c.getBucket(key)
		bucket.counters[h] = element
	}
	c.GC()
	bucket, h := c.getBucket("expired")
	if _, ok := bucket.counters[h]; ok {
		t.Fatal("expired counter retained")
	}
	if got := c.Query("active", 60); got != 7 {
		t.Errorf("active counter lost: %d", got)
	}
}

func TestCounterElementQueryBatchMatchesQuery(t *testing.T) {
	c := newCounterElement(10)
	c.counterElementAdd(100, 1)
	c.counterElementAdd(103, 5)
	c.counterElementAdd(105, 2)
	c.counterElementAdd(108, 4)
	// now=110 has no data, and neither do the last seconds of most windows.
	windows := []int64{30, 3, 0, 1, 7, 5, 10, -2, 2}
	for _, now := range []int64{108, 110, 112, 125} {
		got := c.counterElementQueryBatch(windows, now)
		if len(got) != len(windows) {
			t.Fatalf("now=%d: len = %d, want %d", now, len(got), len(windows))
		}
		for i, w := range windows {
			want := int64(0)
			if w > 0 {
				want = c.counterElementQuery(w, now)
			}
			if got[i] != want {
				t.Errorf("now=%d window=%d: batch = %d, Query = %d", now, w, got[i], want)
			}
		}
	}
	// Spot-check against hand-computed values at now=110.
	got := c.counterElementQueryBatch([]int64{2, 3, 6, 10}, 110)
	if want := []int64{0, 4, 6, 11}; !slices.Equal(got, want) {
		t.Errorf("now=110 batch = %v, want %v", got, want)
	}
}

func TestCounterElementQueryBatchEmpty(t *testing.T) {
	c := newCounterElement(5)
	c.counterElementAdd(100, 3)
	if got := c.counterElementQueryBatch(nil, 100); len(got) != 0 {
		t.Errorf("nil windows = %v", got)
	}
	if got := c.counterElementQueryBatch([]int64{}, 100); len(got) != 0 {
		t.Errorf("empty windows = %v", got)
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
