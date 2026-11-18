package state

import (
	"runtime"
	"server_torii/internal/config"
	"server_torii/internal/ratelimit"
	"sync/atomic"
)

// Limiters are the rate counters of one site. Each is nil until the first Resize.
type Limiters struct {
	HTTPFloodSpeedLimitCounter   atomic.Pointer[ratelimit.Counter]
	HTTPFloodSameURILimitCounter atomic.Pointer[ratelimit.Counter]
	HTTPFloodFailureLimitCounter atomic.Pointer[ratelimit.Counter]
	ChallengeFailureLimitCounter atomic.Pointer[ratelimit.Counter]
}

func (l *Limiters) all() []*atomic.Pointer[ratelimit.Counter] {
	return []*atomic.Pointer[ratelimit.Counter]{
		&l.HTTPFloodSpeedLimitCounter,
		&l.HTTPFloodSameURILimitCounter,
		&l.HTTPFloodFailureLimitCounter,
		&l.ChallengeFailureLimitCounter,
	}
}

// Resize makes every counter cover the given windows.
// A counter whose window is unchanged keeps its records; a resized one starts empty.
func (l *Limiters) Resize(w config.CounterWindows) {
	bucketCount := max(runtime.NumCPU()*8, 16)
	resize := func(p *atomic.Pointer[ratelimit.Counter], window int64) {
		// At least one second: a zero-size counter would panic.
		window = max(window, 1)
		if c := p.Load(); c == nil || c.GetSegSize() != window {
			p.Store(ratelimit.NewCounter(bucketCount, window))
		}
	}
	resize(&l.HTTPFloodSpeedLimitCounter, w.HTTPFloodSpeed)
	resize(&l.HTTPFloodSameURILimitCounter, w.HTTPFloodSameURI)
	resize(&l.HTTPFloodFailureLimitCounter, w.HTTPFloodFailure)
	resize(&l.ChallengeFailureLimitCounter, w.ChallengeFailure)
}

// Untracked returns how many events the counters did not count because they were full.
func (l *Limiters) Untracked() uint64 {
	var n uint64
	for _, p := range l.all() {
		if c := p.Load(); c != nil {
			n += c.Untracked()
		}
	}
	return n
}

// GC drops expired records from every counter.
func (l *Limiters) GC() {
	for _, p := range l.all() {
		if c := p.Load(); c != nil {
			c.GC()
		}
	}
}

// SiteLimiters keeps one set of rate counters per site, so the traffic of one site never
// counts against the limits of another.
//
// The embedded Limiters serve a site that has no counters of its own: a request that arrives
// before the first ResizeSites, and code that runs without a site.
type SiteLimiters struct {
	Limiters
	sites atomic.Pointer[map[string]*Limiters]
}

// LimitersFor returns the counters of the site.
func (s *SiteLimiters) LimitersFor(site string) *Limiters {
	if sites := s.sites.Load(); sites != nil {
		if l, ok := (*sites)[site]; ok {
			return l
		}
	}
	return &s.Limiters
}

// ResizeSites makes the counters of every listed site cover its windows. A site that is still
// listed keeps its counters, with their records where the window is unchanged; the counters of
// a site that is no longer listed are dropped. It must not be called concurrently with itself.
func (s *SiteLimiters) ResizeSites(windows map[string]config.CounterWindows) {
	var previous map[string]*Limiters
	if p := s.sites.Load(); p != nil {
		previous = *p
	}
	next := make(map[string]*Limiters, len(windows))
	for site, w := range windows {
		l := previous[site]
		if l == nil {
			l = &Limiters{}
		}
		l.Resize(w)
		next[site] = l
	}
	s.sites.Store(&next)
}

// Untracked returns how many events the counters of every site did not count because they were
// full. A counter that was replaced takes its count with it.
func (s *SiteLimiters) Untracked() uint64 {
	n := s.Limiters.Untracked()
	if sites := s.sites.Load(); sites != nil {
		for _, l := range *sites {
			n += l.Untracked()
		}
	}
	return n
}

// GC drops expired records from the counters of every site.
func (s *SiteLimiters) GC() {
	s.Limiters.GC()
	if sites := s.sites.Load(); sites != nil {
		for _, l := range *sites {
			l.GC()
		}
	}
}
