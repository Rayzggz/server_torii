package ratelimit

import (
	"fmt"
	"math/rand"
	"runtime"
	"testing"
)

// denseWindow is the counter as it was: one slot for every second of the window. The sparse
// counter must give the same answer for every sequence of events.
type denseWindow struct {
	segments []timeSegment
	size     int64
}

func (d *denseWindow) add(ts, value int64) {
	idx := ts % d.size
	if d.segments[idx].timestamp != ts {
		d.segments[idx] = timeSegment{timestamp: ts, count: value}
	} else {
		d.segments[idx].count += value
	}
}

func (d *denseWindow) query(lastN, now int64) int64 {
	lastN = min(lastN, d.size)
	var sum int64
	for sec := now - lastN + 1; sec <= now; sec++ {
		if seg := d.segments[sec%d.size]; seg.timestamp == sec {
			sum += seg.count
		}
	}
	return sum
}

func TestSparseCounterCountsLikeTheDenseOne(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, size := range []int64{1, 2, 10, 60, 300} {
		sparse := newCounterElement(int(size))
		dense := &denseWindow{segments: make([]timeSegment, size), size: size}
		now := int64(1_000_000)
		for step := 0; step < 5000; step++ {
			// Bursts within a second, quiet stretches, gaps longer than the window.
			switch rng.Intn(10) {
			case 0:
				now += size + int64(rng.Intn(5))
			case 1, 2, 3:
				now += int64(rng.Intn(3))
			}
			value := int64(1 + rng.Intn(4))
			sparse.counterElementAdd(now, value)
			dense.add(now, value)

			window := 1 + rng.Int63n(size+2)
			if got, want := sparse.counterElementQuery(window, now), dense.query(window, now); got != want {
				t.Fatalf("size %d step %d: last %d seconds = %d, want %d", size, step, window, got, want)
			}
			windows := []int64{size, 1, window, 0}
			batch := sparse.counterElementQueryBatch(windows, now)
			for i, w := range windows {
				want := int64(0)
				if w > 0 {
					want = dense.query(w, now)
				}
				if batch[i] != want {
					t.Fatalf("size %d step %d: batch window %d = %d, want %d", size, step, w, batch[i], want)
				}
			}
			if int64(len(sparse.segments)) > size {
				t.Fatalf("size %d: %d segments kept", size, len(sparse.segments))
			}
		}
	}
}

// A clock that steps back must not lose or double an event.
func TestSparseCounterWithAClockThatStepsBack(t *testing.T) {
	c := newCounterElement(10)
	c.counterElementAdd(105, 1)
	c.counterElementAdd(103, 2)
	c.counterElementAdd(105, 4)
	c.counterElementAdd(103, 8)
	if got := c.counterElementQuery(10, 105); got != 15 {
		t.Fatalf("total = %d, want 15", got)
	}
	if got := c.counterElementQuery(2, 105); got != 5 {
		t.Fatalf("last two seconds = %d, want 5", got)
	}
	if len(c.segments) != 2 || c.segments[0].timestamp != 103 {
		t.Fatalf("segments = %v", c.segments)
	}
}

// A full counter stops taking new keys and goes on counting the ones it has.
func TestCounterStopsAtItsKeyLimit(t *testing.T) {
	c := NewCounter(4, 60)
	c.SetMaxKeys(400)
	for i := 0; i < 5000; i++ {
		c.Add(fmt.Sprintf("client-%d", i), 1)
	}
	if got := c.Len(); got != 400 {
		t.Fatalf("keys = %d, want the limit of 400", got)
	}
	if got := c.Untracked(); got != 5000-400 {
		t.Fatalf("untracked = %d, want %d", got, 5000-400)
	}

	var known, unknown string
	for i := 0; i < 5000 && (known == "" || unknown == ""); i++ {
		key := fmt.Sprintf("client-%d", i)
		if c.Query(key, 60) == 1 {
			known = key
		} else {
			unknown = key
		}
	}
	c.Add(known, 1)
	if got := c.Query(known, 60); got != 2 {
		t.Fatalf("a key the counter holds = %d, want 2", got)
	}
	// A key that did not fit reads as zero: the client is let through, not limited.
	c.Add(unknown, 1)
	if got := c.Query(unknown, 60); got != 0 {
		t.Fatalf("a key that did not fit = %d, want 0", got)
	}

	// Room made by Reset is used again.
	c.Reset(known)
	before := c.Untracked()
	for i := 5000; i < 5100 && c.Len() < 400; i++ {
		c.Add(fmt.Sprintf("client-%d", i), 1)
	}
	if c.Len() != 400 || c.Untracked()-before > 99 {
		t.Fatalf("keys = %d after a reset made room", c.Len())
	}
}

// TestCounterMemoryPerKey measures what a key that is seen once costs: the case of a client
// that changes the query string with every request. It reports the figure and fails when a
// key costs a meaningful part of what a whole window costs.
func TestCounterMemoryPerKey(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates a million keys")
	}
	const keys, window = 1_000_000, 300
	heap := func() uint64 {
		runtime.GC()
		var m runtime.MemStats
		runtime.ReadMemStats(&m)
		return m.HeapAlloc
	}
	before := heap()
	c := NewCounter(64, window)
	for i := 0; i < keys; i++ {
		c.Add(fmt.Sprintf("2001:db8:%x::/64|/search?q=%d", i%65536, i), 1)
	}
	perKey := float64(heap()-before) / keys
	runtime.KeepAlive(c)
	dense := float64(window * 16)
	t.Logf("%d keys seen once, window %ds: %.0f bytes per key (one slot per second took %.0f for the slots alone)", keys, window, perKey, dense)
	if perKey > dense/10 {
		t.Fatalf("a key seen once costs %.0f bytes", perKey)
	}

	// At the limit the memory stops growing. The limit is set to what the counter holds; it
	// applies per bucket, so the buckets that hold less than their share still take a few keys.
	c.SetMaxKeys(keys)
	full := heap()
	for i := keys; i < 2*keys; i++ {
		c.Add(fmt.Sprintf("2001:db8:%x::/64|/search?q=%d", i%65536, i), 1)
	}
	grown := int64(heap()) - int64(full)
	runtime.KeepAlive(c)
	t.Logf("another %d keys at the limit: heap changed by %d bytes, %d events not counted", keys, grown, c.Untracked())
	if c.Len() > keys+keys/100 || grown > int64(keys)*8 {
		t.Fatalf("the counter grew past its limit: %d keys, %d bytes more", c.Len(), grown)
	}
}
