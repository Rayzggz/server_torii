package dataType

import (
	"sync"
	"time"
)

type BlockList struct {
	mu         sync.RWMutex
	blockedIPs map[string]int64
	buckets    map[int64][]string
	lastCheck  int64
}

func NewBlockList() *BlockList {
	return &BlockList{
		blockedIPs: make(map[string]int64),
		buckets:    make(map[int64][]string),
		lastCheck:  time.Now().Unix(),
	}
}

func (bl *BlockList) Block(ip string, duration int64) {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	expiration := time.Now().Unix() + duration

	// If already blocked with a later expiration, ignore
	if existingExp, exists := bl.blockedIPs[ip]; exists && existingExp >= expiration {
		return
	}

	bl.blockedIPs[ip] = expiration
	bl.buckets[expiration] = append(bl.buckets[expiration], ip)
}

func (bl *BlockList) BlockUntil(ip string, expiration int64) {
	duration := expiration - time.Now().Unix()
	if duration <= 0 {
		return
	}
	bl.Block(ip, duration)
}

func (bl *BlockList) IsBlocked(ip string) bool {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	expiration, exists := bl.blockedIPs[ip]
	if !exists {
		return false
	}
	if time.Now().Unix() > expiration {
		return false
	}
	return true
}

// Cleanup processes expired blocked IPs
func (bl *BlockList) Cleanup() {
	bl.mu.Lock()
	defer bl.mu.Unlock()

	now := time.Now().Unix()
	// Process all seconds from lastCheck+1 to now
	for t := bl.lastCheck + 1; t <= now; t++ {
		if ips, exists := bl.buckets[t]; exists {
			for _, ip := range ips {
				// Verify if the IP is still expired (re-blocking might have extended it)
				if exp, ok := bl.blockedIPs[ip]; ok && exp <= now {
					delete(bl.blockedIPs, ip)
				}
			}
			delete(bl.buckets, t)
		}
	}
	bl.lastCheck = now
}

// GetSnapshot returns a copy of the current blocked IPs and their expiration times
func (bl *BlockList) GetSnapshot() map[string]int64 {
	bl.mu.RLock()
	defer bl.mu.RUnlock()

	snapshot := make(map[string]int64, len(bl.blockedIPs))
	now := time.Now().Unix()
	for ip, exp := range bl.blockedIPs {
		if exp > now {
			snapshot[ip] = exp
		}
	}
	return snapshot
}

func StartBlockListGC(blockList *BlockList, _ time.Duration, stopCh <-chan struct{}) {
	// Force 1 second interval for Timing Wheel accuracy
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			blockList.Cleanup()
		case <-stopCh:
			return
		}
	}
}
