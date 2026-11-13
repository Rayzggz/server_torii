package dataType

import (
	"cmp"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
)

type timeSegment struct {
	timestamp int64
	count     int64
}

type counterElement struct {
	segments    []timeSegment
	segSize     int64
	lastUpdated int64
}

func newCounterElement(segments int) *counterElement {
	return &counterElement{
		segments:    make([]timeSegment, segments),
		segSize:     int64(segments),
		lastUpdated: time.Now().Unix(),
	}
}

func (c *counterElement) counterElementAdd(ts int64, value int64) {
	idx := ts % c.segSize
	if c.segments[idx].timestamp != ts {
		c.segments[idx].timestamp = ts
		c.segments[idx].count = value
	} else {
		c.segments[idx].count += value
	}
	c.lastUpdated = ts
}

func (c *counterElement) counterElementQuery(lastN int64, now int64) int64 {
	var sum int64
	if lastN > c.segSize {
		lastN = c.segSize
		log.Printf("Error: lastN exceeds segment size, resetting to segment size")
	}
	for i := int64(0); i < lastN; i++ {
		sec := now - lastN + 1 + i
		idx := sec % c.segSize
		if c.segments[idx].timestamp == sec {
			sum += c.segments[idx].count
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

	if lastN[order[len(order)-1]] > c.segSize {
		log.Printf("Error: lastN exceeds segment size, resetting to segment size")
	}

	var sum, covered int64
	for _, qi := range order {
		window := min(lastN[qi], c.segSize)
		for covered < window {
			sec := now - covered
			idx := sec % c.segSize
			if c.segments[idx].timestamp == sec {
				sum += c.segments[idx].count
			}
			covered++
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

type Counter struct {
	buckets     []*CounterBucket
	bucketCount uint64
	segSize     int64
}

func NewCounter(bucketCount int, size int64) *Counter {
	tc := &Counter{
		buckets:     make([]*CounterBucket, bucketCount),
		bucketCount: uint64(bucketCount),
		segSize:     size,
	}
	for i := 0; i < bucketCount; i++ {
		tc.buckets[i] = NewCounterBucket()
	}
	return tc
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
