package dataType

import (
	"log"
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

func (c *counterElement) counterElementQueryBatch(lastN []int64, now int64) []int64 {
	querySize := len(lastN)
	lastSec := lastN[querySize-1]
	if lastSec > c.segSize {
		lastSec = c.segSize
		log.Printf("Error: lastSec exceeds segment size, resetting to segment size")
	}

	var sum int64
	var queryIdx = 0
	res := make([]int64, querySize)
	for i := int64(0); i < lastSec; i++ {
		sec := now - lastSec + 1 + i
		idx := sec % c.segSize
		if c.segments[idx].timestamp == sec {
			sum += c.segments[idx].count
			if queryIdx < querySize && lastN[queryIdx] == i+1 {
				res[queryIdx] = sum
				queryIdx++
			}
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

func (tc *Counter) getBucket(key string) *CounterBucket {
	h := xxhash.Sum64String(key)
	idx := h % tc.bucketCount
	return tc.buckets[idx]
}

func (tc *Counter) Add(key string, value int64) {
	now := time.Now().Unix()
	bucket := tc.getBucket(key)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	hashKey := xxhash.Sum64String(key)
	counter, exists := bucket.counters[hashKey]
	if !exists {
		counter = newCounterElement(int(tc.segSize))
		bucket.counters[hashKey] = counter
	}
	counter.counterElementAdd(now, value)
}

func (tc *Counter) Query(key string, lastN int64) int64 {
	now := time.Now().Unix()
	bucket := tc.getBucket(key)
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	hashKey := xxhash.Sum64String(key)
	if counter, exists := bucket.counters[hashKey]; exists {
		return counter.counterElementQuery(lastN, now)
	}
	return 0
}

func (tc *Counter) Reset(key string) {
	bucket := tc.getBucket(key)
	bucket.mu.Lock()
	defer bucket.mu.Unlock()
	hashKey := xxhash.Sum64String(key)
	delete(bucket.counters, hashKey)
}

func (tc *Counter) QueryBatch(key string, lastN []int64) []int64 {
	now := time.Now().Unix()
	bucket := tc.getBucket(key)
	bucket.mu.RLock()
	defer bucket.mu.RUnlock()
	hashKey := xxhash.Sum64String(key)
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

func StartCounterGC(counter *Counter, interval time.Duration, stopCh <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			counter.GC()
		case <-stopCh:
			return
		}
	}
}
