package check

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeResolver struct {
	ptr      map[string][]string
	forward  map[string][]string
	ptrErr   error
	block    chan struct{} // when set, LookupAddr waits on it or ctx
	ptrCalls atomic.Int32
	ipCalls  atomic.Int32
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.ptrCalls.Add(1)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, &net.DNSError{Err: ctx.Err().Error(), Name: addr, IsTimeout: true}
		}
	}
	if f.ptrErr != nil {
		return nil, f.ptrErr
	}
	names, ok := f.ptr[addr]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
	}
	return names, nil
}

func (f *fakeResolver) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	f.ipCalls.Add(1)
	ips, ok := f.forward[host]
	if !ok {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	out := make([]net.IPAddr, len(ips))
	for i, s := range ips {
		out[i] = net.IPAddr{IP: net.ParseIP(s)}
	}
	return out, nil
}

var googleDomains = []string{"googlebot.com", "google.com"}

func googleResolver() *fakeResolver {
	return &fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1":          {"crawl-66-249-66-1.googlebot.com."},
			"203.0.113.9":          {"crawl.googlebot.com.attacker.example."},
			"203.0.113.7":          {"fake.googlebot.com."}, // PTR claims Google, forward does not agree
			"2001:4860:4801:10::1": {"crawl-2001-4860-4801-10--1.googlebot.com."},
		},
		forward: map[string][]string{
			"crawl-66-249-66-1.googlebot.com.":          {"66.249.66.1"},
			"fake.googlebot.com.":                       {"198.51.100.1"},
			"crawl-2001-4860-4801-10--1.googlebot.com.": {"2001:4860:4801:0010:0000:0000:0000:0001"},
		},
	}
}

func TestBotVerifierVerdicts(t *testing.T) {
	tests := []struct {
		ip      string
		want    bool
		wantErr bool
	}{
		{"66.249.66.1", true, false},
		{"2001:4860:4801:10::1", true, false}, // forward answer in a different textual form
		{"203.0.113.9", false, false},         // PTR outside the crawler domain
		{"203.0.113.7", false, false},         // forward lookup does not return the address
		{"198.51.100.200", false, false},      // no PTR record
	}
	for _, tt := range tests {
		v := newBotVerifier(googleResolver())
		got, fresh, err := v.verify(net.ParseIP(tt.ip), "google", googleDomains)
		if got != tt.want || !fresh || (err != nil) != tt.wantErr {
			t.Errorf("%s: verify = (%v, fresh=%v, %v), want (%v, fresh=true, err=%v)", tt.ip, got, fresh, err, tt.want, tt.wantErr)
		}
	}
}

func TestBotVerifierCachesBothOutcomes(t *testing.T) {
	r := googleResolver()
	v := newBotVerifier(r)
	for i := 0; i < 5; i++ {
		if ok, _, _ := v.verify(net.ParseIP("66.249.66.1"), "google", googleDomains); !ok {
			t.Fatal("real Googlebot rejected")
		}
		if ok, _, _ := v.verify(net.ParseIP("203.0.113.7"), "google", googleDomains); ok {
			t.Fatal("spoofed Googlebot accepted")
		}
	}
	if got := r.ptrCalls.Load(); got != 2 {
		t.Fatalf("reverse lookups = %d, want 2 (one per address)", got)
	}
	if got := r.ipCalls.Load(); got != 2 {
		t.Fatalf("forward lookups = %d, want 2", got)
	}

	// A different crawler claim from the same address is verified separately.
	_, _, _ = v.verify(net.ParseIP("66.249.66.1"), "bing", []string{"search.msn.com"})
	if got := r.ptrCalls.Load(); got != 3 {
		t.Fatalf("reverse lookups = %d after bing claim, want 3", got)
	}
}

func TestBotVerifierTTLs(t *testing.T) {
	r := googleResolver()
	v := newBotVerifier(r)
	now := time.Unix(1_000_000, 0)
	v.now = func() time.Time { return now }

	ip := net.ParseIP("203.0.113.7")
	_, _, _ = v.verify(ip, "google", googleDomains)
	now = now.Add(botRejectedTTL - time.Second)
	_, _, _ = v.verify(ip, "google", googleDomains)
	if got := r.ptrCalls.Load(); got != 1 {
		t.Fatalf("rejection re-looked-up before TTL: %d calls", got)
	}
	now = now.Add(2 * time.Second)
	if _, fresh, _ := v.verify(ip, "google", googleDomains); !fresh {
		t.Fatal("rejection not re-checked after TTL")
	}

	good := net.ParseIP("66.249.66.1")
	_, _, _ = v.verify(good, "google", googleDomains)
	now = now.Add(botVerifiedTTL - time.Second)
	if _, fresh, _ := v.verify(good, "google", googleDomains); fresh {
		t.Fatal("verified crawler re-checked before TTL")
	}
}

func TestBotVerifierCachesLookupErrorsBriefly(t *testing.T) {
	r := googleResolver()
	r.ptrErr = &net.DNSError{Err: "server misbehaving", Name: "x", IsTemporary: true}
	v := newBotVerifier(r)
	now := time.Unix(1_000_000, 0)
	v.now = func() time.Time { return now }

	ip := net.ParseIP("66.249.66.1")
	ok, fresh, err := v.verify(ip, "google", googleDomains)
	if ok || !fresh || err == nil {
		t.Fatalf("verify = (%v, %v, %v), want rejection with error", ok, fresh, err)
	}
	_, _, _ = v.verify(ip, "google", googleDomains)
	if got := r.ptrCalls.Load(); got != 1 {
		t.Fatalf("DNS error not cached: %d calls", got)
	}

	r.ptrErr = nil
	now = now.Add(botLookupErrorTTL + time.Second)
	if ok, _, _ := v.verify(ip, "google", googleDomains); !ok {
		t.Fatal("crawler still rejected after resolver recovered")
	}
}

func TestBotVerifierTimesOut(t *testing.T) {
	r := googleResolver()
	r.block = make(chan struct{}) // never released
	v := newBotVerifier(r)
	v.timeout = 50 * time.Millisecond

	start := time.Now()
	ok, _, err := v.verify(net.ParseIP("66.249.66.1"), "google", googleDomains)
	if ok || err == nil {
		t.Fatalf("verify = (%v, %v), want timeout rejection", ok, err)
	}
	var dnsErr *net.DNSError
	if !errors.As(err, &dnsErr) || !dnsErr.IsTimeout {
		t.Fatalf("err = %v, want DNS timeout", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("verify took %v despite 50ms timeout", elapsed)
	}
}

func TestBotVerifierSharesConcurrentLookups(t *testing.T) {
	r := googleResolver()
	r.block = make(chan struct{})
	v := newBotVerifier(r)

	const n = 50
	var wg sync.WaitGroup
	results := make([]bool, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _, _ = v.verify(net.ParseIP("66.249.66.1"), "google", googleDomains)
		}(i)
	}
	// Let every goroutine reach the cache before the single lookup finishes.
	deadline := time.Now().Add(time.Second)
	for r.ptrCalls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(r.block)
	wg.Wait()

	if got := r.ptrCalls.Load(); got != 1 {
		t.Fatalf("reverse lookups = %d for %d concurrent requests, want 1", got, n)
	}
	for i, ok := range results {
		if !ok {
			t.Fatalf("request %d rejected", i)
		}
	}
}

func TestBotVerifierBoundsCache(t *testing.T) {
	v := newBotVerifier(googleResolver())
	v.rejected = newBotLRU(100)
	for i := 0; i < 1000; i++ {
		_, _, _ = v.verify(net.IPv4(198, 51, byte(i>>8), byte(i)), "google", googleDomains)
		if n := v.rejected.len(); n > 100 {
			t.Fatalf("rejected cache grew to %d entries, cap 100", n)
		}
	}
}

// A flood of spoofed claims from fresh addresses must not evict confirmed crawlers.
func TestBotVerifierFloodKeepsVerifiedCrawlers(t *testing.T) {
	r := googleResolver()
	v := newBotVerifier(r)
	v.rejected = newBotLRU(100)

	good := net.ParseIP("66.249.66.1")
	_, _, _ = v.verify(good, "google", googleDomains)
	for i := 0; i < 10_000; i++ {
		_, _, _ = v.verify(net.IPv4(198, 51, byte(i>>8), byte(i)), "google", googleDomains)
	}
	before := r.ptrCalls.Load()
	if ok, fresh, _ := v.verify(good, "google", googleDomains); !ok || fresh {
		t.Fatalf("verify = (%v, fresh=%v), want cached verification", ok, fresh)
	}
	if r.ptrCalls.Load() != before {
		t.Fatal("verified crawler was re-looked-up after flood")
	}
}

func TestBotLRUEvictsLeastRecentlyUsed(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newBotLRU(2)
	v := botVerdict{verified: true, expires: now.Add(time.Hour)}
	l.put("a", v)
	l.put("b", v)
	l.get("a", now) // a is now most recent
	l.put("c", v)   // evicts b
	if _, ok := l.get("b", now); ok {
		t.Fatal("least recently used entry b survived")
	}
	for _, k := range []string{"a", "c"} {
		if _, ok := l.get(k, now); !ok {
			t.Fatalf("entry %s evicted", k)
		}
	}
}

func TestBotLRUDropsExpired(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := newBotLRU(10)
	l.put("a", botVerdict{expires: now.Add(time.Minute)})
	if _, ok := l.get("a", now.Add(time.Minute)); ok {
		t.Fatal("expired entry returned")
	}
	if l.len() != 0 {
		t.Fatalf("expired entry kept: len %d", l.len())
	}
}

// A flood of spoofed crawler user agents from many addresses must not become as many lookups.
func TestBotVerifierCapsConcurrentLookups(t *testing.T) {
	r := googleResolver()
	r.block = make(chan struct{})
	v := newBotVerifier(r)

	var wg sync.WaitGroup
	for i := 0; i < botMaxLookups; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, _ = v.verify(net.IPv4(198, 51, 100, byte(i)), "google", googleDomains)
		}(i)
	}
	deadline := time.Now().Add(2 * time.Second)
	for int(r.ptrCalls.Load()) < botMaxLookups && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := int(r.ptrCalls.Load()); got != botMaxLookups {
		t.Fatalf("%d lookups in progress, want %d", got, botMaxLookups)
	}

	// At the cap: answered at once as unverified, without a lookup, even for a real crawler.
	crawler := net.ParseIP("66.249.66.1")
	start := time.Now()
	for i := 0; i < 100; i++ {
		ok, fresh, err := v.verify(crawler, "google", googleDomains)
		if ok || fresh || err != nil {
			t.Fatalf("verify at the cap = (%v, %v, %v), want unverified without a lookup", ok, fresh, err)
		}
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("refusals took %v, want them immediate", elapsed)
	}
	if got := int(r.ptrCalls.Load()); got != botMaxLookups {
		t.Fatalf("lookups = %d after refusals, want still %d", got, botMaxLookups)
	}

	// The refusal was not cached: with room again the crawler is verified.
	close(r.block)
	wg.Wait()
	if ok, fresh, err := v.verify(crawler, "google", googleDomains); !ok || !fresh || err != nil {
		t.Fatalf("verify after the flood = (%v, %v, %v), want a fresh verification", ok, fresh, err)
	}
	if len(v.slots) != 0 {
		t.Fatalf("%d lookup slots still held", len(v.slots))
	}
}
