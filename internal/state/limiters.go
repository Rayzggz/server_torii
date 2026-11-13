package state

import (
	"context"
	"runtime"
	"server_torii/internal/config"
	"server_torii/internal/dataType"
	"sync/atomic"
	"time"
)

// Limiters are the rate counters shared by every site. Each is nil until the first Resize.
type Limiters struct {
	HTTPFloodSpeedLimitCounter   atomic.Pointer[dataType.Counter]
	HTTPFloodSameURILimitCounter atomic.Pointer[dataType.Counter]
	HTTPFloodFailureLimitCounter atomic.Pointer[dataType.Counter]
	CaptchaFailureLimitCounter   atomic.Pointer[dataType.Counter]
}

// Resize makes every counter cover the given windows.
// A counter whose window is unchanged keeps its records; a resized one starts empty.
func (l *Limiters) Resize(w config.CounterWindows) {
	bucketCount := max(runtime.NumCPU()*8, 16)
	resize := func(p *atomic.Pointer[dataType.Counter], window int64) {
		// At least one second: a zero-size counter would panic.
		window = max(window, 1)
		if c := p.Load(); c == nil || c.GetSegSize() != window {
			p.Store(dataType.NewCounter(bucketCount, window))
		}
	}
	resize(&l.HTTPFloodSpeedLimitCounter, w.HTTPFloodSpeed)
	resize(&l.HTTPFloodSameURILimitCounter, w.HTTPFloodSameURI)
	resize(&l.HTTPFloodFailureLimitCounter, w.HTTPFloodFailure)
	resize(&l.CaptchaFailureLimitCounter, w.CaptchaFailure)
}

// GC drops expired records from every counter.
func (l *Limiters) GC() {
	for _, p := range []*atomic.Pointer[dataType.Counter]{
		&l.HTTPFloodSpeedLimitCounter,
		&l.HTTPFloodSameURILimitCounter,
		&l.HTTPFloodFailureLimitCounter,
		&l.CaptchaFailureLimitCounter,
	} {
		if c := p.Load(); c != nil {
			c.GC()
		}
	}
}

// RunGC calls GC every interval until ctx is done.
func (l *Limiters) RunGC(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			l.GC()
		case <-ctx.Done():
			return
		}
	}
}
