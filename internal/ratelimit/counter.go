package ratelimit

import (
	"cmp"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cespare/xxhash/v2"
)

type timeSegment struct {
	timestamp int64
	count     int64
}

// counterElement counts the events of one key in a sliding window of segSize seconds, to the
// second. It keeps only the seconds that had an event, oldest first, so a key seen once costs
// one segment and not a whole window: an attacker who makes a new key with every request buys
// a few dozen bytes with it, not kilobytes.
type counterElement struct {
	segments    []timeSegment
	segSize     int64
	lastUpdated int64
}

func newCounterElement(segments int) *counterElement {
	return &counterElement{
		segSize:     int64(segments),
		lastUpdated: time.Now().Unix(),
	}
}

func (c *counterElement) counterElementAdd(ts int64, value int64) {
	c.lastUpdated = ts
	// Seconds that left the window make room first, so the slice never outgrows the window.
	expired := 0
	for expired < len(c.segments) && c.segments[expired].timestamp <= ts-c.segSize {
		expired++
	}
	if expired > 0 {
		c.segments = append(c.segments[:0], c.segments[expired:]...)
	}
	// The second is nearly always the last one or a new one after it; a clock that stepped
	// back puts it earlier.
	at := len(c.segments)
	for at > 0 && c.segments[at-1].timestamp > ts {
		at--
	}
	if at > 0 && c.segments[at-1].timestamp == ts {
		c.segments[at-1].count += value
		return
	}
	c.segments = slices.Insert(c.segments, at, timeSegment{timestamp: ts, count: value})
}

// counterElementQuery returns the events of the lastN seconds up to and including now.
func (c *counterElement) counterElementQuery(lastN int64, now int64) int64 {
	lastN = min(lastN, c.segSize)
	var sum int64
	for i := len(c.segments) - 1; i >= 0; i-- {
		seg := c.segments[i]
		if seg.timestamp <= now-lastN {
			break
		}
		if seg.timestamp <= now {
			sum += seg.count
		}
	}
	return sum
}

// counterElementQueryBatch returns, for each window in lastN, the same value
// counterElementQuery would return for it. lastN may be in any order; windows
// larger than segSize are clamped and windows <= 0 yield 0.
func (c *counterElement) counterElementQueryBatch(lastN []int64, now int64) []int64 {
	res := make([]int64, len(lastN))
	if len(lastN) == 0 {
		return res
	}

	// Visit windows from smallest to largest while walking back from now,
	// so each window's total is the running sum of the most recent seconds.
	order := make([]int, len(lastN))
	for i := range order {
		order[i] = i
	}
	slices.SortFunc(order, func(a, b int) int { return cmp.Compare(lastN[a], lastN[b]) })

	var sum int64
	next := len(c.segments) - 1
	for _, qi := range order {
		window := min(lastN[qi], c.segSize)
		for next >= 0 && c.segments[next].timestamp > now-window {
			if c.segments[next].timestamp <= now {
				sum += c.segments[next].count
			}
			next--
		}
		if window > 0 {
			res[qi] = sum
		}
	}
	return res
}

type CounterBucket struct {
	mu       sync.RWMutex
	counters map[uint64]*counterElement
}

func NewCounterBucket() *CounterBucket {
	return &CounterBucket{
		counters: make(map[uint64]*counterElement),
	}
}

// DefaultMaxKeys is how many keys a Counter counts at a time.
const DefaultMaxKeys = 2_000_000

// Counter counts events per key in a sliding window. It holds a limited number of keys: when
// it is full a new key is not counted and reads as zero, so the limit it would have enforced
// lets the client through. That happens under an attack from more sources than any limit per
// client can hold back; refusing every new client then would take the site down for the
// attacker. Untracked says how often it happened.
type Counter struct {
	buckets      []*CounterBucket
	bucketCount  uint64
	segSize      int64
	maxPerBucket int
	untracked    atomic.Uint64
}

func NewCounter(bucketCount int, size int64) *Counter {
	tc := &Counter{
		buckets:     make([]*CounterBucket, bucketCount),
		bucketCount: uint64(bucketCount),
		segSize:     size,
	}
	tc.SetMaxKeys(DefaultMaxKeys)
	for i := 0; i < bucketCount; i++ {
		tc.buckets[i] = NewCounterBucket()
	}
	return tc
}

// SetMaxKeys changes how many keys the counter holds. The keys are spread over the buckets by
// their hash, so the limit is applied per bucket. It is not safe to call while the counter is used.
func (tc *Counter) SetMaxKeys(n int) {
	tc.maxPerBucket = max(n/len(tc.buckets), 1)
}

// Untracked returns how many events were not counted because the counter was full.
func (tc *Counter) Untracked() uint64 {
	return tc.untracked.Load()
}

// Len returns how many keys the counter holds.
func (tc *Counter) Len() int {
	n := 0
	for _, bucket := range tc.buckets {
		bucket.mu.RLock()
		n += len(bucket.counters)
		bucket.mu.RUnlock()
	}
	return n
}

func (tc *Counter) GetSegSize() int64 {
	return tc.segSize
}

// getBucket hashes key once and returns its bucket along with the hash,
// which is also the key used inside the bucket's map.
func (tc *Counter) getBucket(key string) (*CounterBucket, uint64) {
	h := xxhash.Sum64String(key)
	return tc.buckets[h%tc.bucketCount], h
}

func (tc *Counter) Add(key string, value int64) {
	now := time.Now().Unix()
	bucket, hashKey := tc.getBucket(key)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	counter, exists := bucket.counters[hashKey]
	if !exists {
		if len(bucket.counters) >= tc.maxPerBucket {
			tc.untracked.Add(1)
			return
		}
		counter = newCounterElement(int(tc.segSize))
		bucket.counters[hashKey] = counter
	}
	counter.counterElementAdd(now, value)
}

func (tc *Counter) Query(key string, lastN int64) int64 {
	now := time.Now().Unix()
	bucket, hashKey := tc.getBucket(key)
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	if counter, exists := bucket.counters[hashKey]; exists {
		return counter.counterElementQuery(lastN, now)
	}
	return 0
}

func (tc *Counter) Reset(key string) {
	bucket, hashKey := tc.getBucket(key)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	delete(bucket.counters, hashKey)
}

func (tc *Counter) QueryBatch(key string, lastN []int64) []int64 {
	now := time.Now().Unix()
	bucket, hashKey := tc.getBucket(key)
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	if counter, exists := bucket.counters[hashKey]; exists {
		return counter.counterElementQueryBatch(lastN, now)
	}
	return make([]int64, len(lastN))
}

func (tc *Counter) GC() {
	now := time.Now().Unix()
	expireThreshold := now - tc.segSize
	for _, bucket := range tc.buckets {
		bucket.mu.Lock()
		for key, counter := range bucket.counters {
			if counter.lastUpdated < expireThreshold {
				delete(bucket.counters, key)
			}
		}
		bucket.mu.Unlock()
	}
}
