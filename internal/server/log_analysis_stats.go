package server

import (
	"math"
	"path"
	"sort"
	"strings"
	"time"
)

// Memory bounds for analyzer state.
const (
	maxIPsPerBucket    = 200000
	maxPagesPerIP      = 64
	maxWindowURIs      = 50000
	maxBaselineURIs    = 20000
	maxEvidenceEntries = 1000000
	maxMarkedClients   = 1000000
	baselineStaleAfter = 72 * time.Hour
	offenseMemory      = 24 * time.Hour
	sweepInterval      = time.Minute
	wilsonZ            = 1.96
)

// pageHits counts requests to one page; served excludes ones answered by a challenge, redirect or error.
type pageHits struct {
	all    int64
	served int64
}

// ipBucket is one IP's traffic within a single analysis interval.
type ipBucket struct {
	total     int64
	clientErr int64
	pageTotal int64
	pages     map[string]pageHits // canonical page URI -> hits
	okPages   map[string]struct{} // raw page paths answered with content
	errPaths  map[string]struct{} // canonical URIs answered with 4xx
	evidence  bool                // loaded a static asset or answered from a browser cache (304)
}

type bucket struct {
	at      time.Time
	ips     map[string]*ipBucket
	dropped int64
}

// ipWindow is one IP's traffic merged across the sliding window.
type ipWindow struct {
	total     int64
	clientErr int64
	pageTotal int64
	served    int64
	pages     map[string]pageHits
	okPages   map[string]struct{}
	errPaths  map[string]struct{}
}

// uriWindow splits a page URI's traffic by whether the client behaves like a browser.
type uriWindow struct {
	browser    int64
	nonBrowser int64
	nonIPs     map[string]int64
}

// ewma is a lazily decayed exponentially weighted moving average of a rate.
type ewma struct {
	value   float64
	updated time.Time
	seen    time.Time
}

func (e *ewma) at(now time.Time, halfLife time.Duration) float64 {
	return e.value * math.Pow(0.5, now.Sub(e.updated).Seconds()/halfLife.Seconds())
}

// observe adds one interval's rate. Intervals without observations decay as zeros.
func (e *ewma) observe(now time.Time, rate float64, interval, halfLife time.Duration) {
	alpha := 1 - math.Pow(0.5, interval.Seconds()/halfLife.Seconds())
	e.value = e.at(now, halfLife) + alpha*rate
	e.updated = now
	e.seen = now
}

type offender struct {
	times []time.Time
	until time.Time
}

// recent returns how many offenses happened within offenseMemory.
func (o *offender) recent(now time.Time) int {
	if o == nil {
		return 0
	}
	n := 0
	for _, t := range o.times {
		if now.Sub(t) < offenseMemory {
			n++
		}
	}
	return n
}

// siteState is the analyzer memory for one site; it is reset when the site's window is recreated.
type siteState struct {
	created   time.Time
	buckets   []*bucket
	baseline  map[string]*ewma // browser-like request rate per page URI
	offenders map[string]*offender
	uriRules  map[string]time.Time // URI action applied until
	mode      string               // how hot URIs are currently detected
	lastSweep time.Time
}

func newSiteState(now time.Time) *siteState {
	return &siteState{
		created:   now,
		baseline:  make(map[string]*ewma),
		offenders: make(map[string]*offender),
		uriRules:  make(map[string]time.Time),
		lastSweep: now,
	}
}

// push appends a bucket and drops buckets that left the window.
func (s *siteState) push(b *bucket, window time.Duration, maxBuckets int) {
	s.buckets = append(s.buckets, b)
	cutoff := b.at.Add(-window)
	drop := 0
	for drop < len(s.buckets) && (!s.buckets[drop].at.After(cutoff) || len(s.buckets)-drop > maxBuckets) {
		drop++
	}
	s.buckets = s.buckets[drop:]
}

func (s *siteState) aggregate(scanCap int) map[string]*ipWindow {
	win := make(map[string]*ipWindow)
	for _, b := range s.buckets {
		for ip, ib := range b.ips {
			w := win[ip]
			if w == nil {
				w = &ipWindow{pages: make(map[string]pageHits), okPages: make(map[string]struct{}), errPaths: make(map[string]struct{})}
				win[ip] = w
			}
			w.total += ib.total
			w.clientErr += ib.clientErr
			w.pageTotal += ib.pageTotal
			for u, h := range ib.pages {
				w.served += h.served
				if cur, ok := w.pages[u]; ok || len(w.pages) < maxPagesPerIP {
					w.pages[u] = pageHits{cur.all + h.all, cur.served + h.served}
				}
			}
			for u := range ib.okPages {
				if len(w.okPages) >= maxPagesPerIP {
					break
				}
				w.okPages[u] = struct{}{}
			}
			for u := range ib.errPaths {
				if len(w.errPaths) >= scanCap {
					break
				}
				w.errPaths[u] = struct{}{}
			}
		}
	}
	return win
}

func (s *siteState) sweep(now time.Time) {
	if now.Sub(s.lastSweep) < sweepInterval {
		return
	}
	s.lastSweep = now
	for ip, o := range s.offenders {
		if !o.until.After(now) && o.recent(now) == 0 {
			delete(s.offenders, ip)
		}
	}
	for u, until := range s.uriRules {
		if !until.After(now) {
			delete(s.uriRules, u)
		}
	}
	for u, e := range s.baseline {
		if now.Sub(e.seen) > baselineStaleAfter {
			delete(s.baseline, u)
		}
	}
}

// pruneBaseline keeps the baseline within maxBaselineURIs by dropping the smallest rates.
func (s *siteState) pruneBaseline(now time.Time, halfLife time.Duration) {
	excess := len(s.baseline) - maxBaselineURIs*9/10
	if len(s.baseline) < maxBaselineURIs || excess <= 0 {
		return
	}
	type entry struct {
		uri  string
		rate float64
	}
	entries := make([]entry, 0, len(s.baseline))
	for u, e := range s.baseline {
		entries = append(entries, entry{u, e.at(now, halfLife)})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].rate < entries[j].rate })
	for _, e := range entries[:excess] {
		delete(s.baseline, e.uri)
	}
}

func isClientError(status int) bool { return status >= 400 && status < 500 }

// isServed reports whether the request was answered with content rather than a challenge, redirect or error.
func isServed(status int) bool { return (status >= 200 && status < 300) || status == 304 }

func stripQuery(uri string) string {
	if idx := strings.IndexAny(uri, "?#"); idx != -1 {
		return uri[:idx]
	}
	return uri
}

func isAsset(canonicalURI string, exts map[string]struct{}) bool {
	_, ok := exts[strings.ToLower(path.Ext(canonicalURI))]
	return ok
}

// wilsonLower is the lower bound of the Wilson score interval for k successes in n trials.
func wilsonLower(k, n int64) float64 {
	if n <= 0 {
		return 0
	}
	nf := float64(n)
	p := float64(k) / nf
	z2 := wilsonZ * wilsonZ
	center := p + z2/(2*nf)
	margin := wilsonZ * math.Sqrt(p*(1-p)/nf+z2/(4*nf*nf))
	return (center - margin) / (1 + z2/nf)
}

// weightedMedian returns the value at which cumulative weight reaches half of the total.
func weightedMedian(values, weights []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	idx := make([]int, len(values))
	total := 0.0
	for i := range idx {
		idx[i] = i
		total += weights[i]
	}
	sort.Slice(idx, func(a, b int) bool { return values[idx[a]] < values[idx[b]] })
	acc := 0.0
	for _, i := range idx {
		acc += weights[i]
		if acc >= total/2 {
			return values[i]
		}
	}
	return values[idx[len(idx)-1]]
}
