package check

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const (
	// botLookupTimeout bounds both DNS lookups of one verification together.
	botLookupTimeout = 3 * time.Second
	// botVerifiedTTL matches verifiedBotMarkTTL so a crawler is re-checked when its mark lapses.
	botVerifiedTTL = time.Hour
	// botRejectedTTL applies when DNS answered and the address is not the crawler's.
	botRejectedTTL = 10 * time.Minute
	// botLookupErrorTTL applies when DNS failed (timeout, SERVFAIL); short so a resolver outage heals quickly.
	botLookupErrorTTL = time.Minute
	// botVerifiedMaxEntries caps confirmed crawlers. Only real crawler addresses can enter
	// this segment, so spoofed traffic never evicts them.
	botVerifiedMaxEntries = 10_000
	// botRejectedMaxEntries caps rejections and lookup errors, the segment spoofed traffic churns.
	botRejectedMaxEntries = 100_000
)

// botResolver is the part of *net.Resolver that bot verification uses.
type botResolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

type botVerdict struct {
	verified bool
	err      error
	expires  time.Time
}

// botLRU is a fixed-size least-recently-used map of verdicts. Callers hold botVerifier.mu.
type botLRU struct {
	max   int
	order *list.List // front is most recently used; values are *botLRUItem
	items map[string]*list.Element
}

type botLRUItem struct {
	key     string
	verdict botVerdict
}

func newBotLRU(max int) *botLRU {
	return &botLRU{max: max, order: list.New(), items: make(map[string]*list.Element)}
}

// get returns an unexpired verdict and marks it recently used; it drops an expired one.
func (l *botLRU) get(key string, now time.Time) (botVerdict, bool) {
	el, ok := l.items[key]
	if !ok {
		return botVerdict{}, false
	}
	item := el.Value.(*botLRUItem)
	if !now.Before(item.verdict.expires) {
		l.remove(el)
		return botVerdict{}, false
	}
	l.order.MoveToFront(el)
	return item.verdict, true
}

func (l *botLRU) put(key string, v botVerdict) {
	if el, ok := l.items[key]; ok {
		el.Value.(*botLRUItem).verdict = v
		l.order.MoveToFront(el)
		return
	}
	l.items[key] = l.order.PushFront(&botLRUItem{key: key, verdict: v})
	for l.order.Len() > l.max {
		l.remove(l.order.Back())
	}
}

func (l *botLRU) delete(key string) {
	if el, ok := l.items[key]; ok {
		l.remove(el)
	}
}

func (l *botLRU) remove(el *list.Element) {
	l.order.Remove(el)
	delete(l.items, el.Value.(*botLRUItem).key)
}

func (l *botLRU) len() int { return l.order.Len() }

// botInflight lets concurrent requests for one key wait on a single lookup.
type botInflight struct {
	done    chan struct{}
	verdict botVerdict // set before done is closed
}

// botVerifier caches crawler verdicts per address and crawler, and lets concurrent
// requests for the same pair share one lookup, so spoofed user agents cannot turn
// each request into fresh DNS queries.
type botVerifier struct {
	resolver botResolver
	timeout  time.Duration
	now      func() time.Time

	mu       sync.Mutex
	verified *botLRU
	rejected *botLRU
	inflight map[string]*botInflight
}

func newBotVerifier(resolver botResolver) *botVerifier {
	return &botVerifier{
		resolver: resolver,
		timeout:  botLookupTimeout,
		now:      time.Now,
		verified: newBotLRU(botVerifiedMaxEntries),
		rejected: newBotLRU(botRejectedMaxEntries),
		inflight: make(map[string]*botInflight),
	}
}

var defaultBotVerifier = newBotVerifier(net.DefaultResolver)

// verify reports whether ip forward-confirms to a host under one of domains.
// fresh is true when this call performed the lookup; err is set only on fresh calls.
func (v *botVerifier) verify(ip net.IP, bot string, domains []string) (verified, fresh bool, err error) {
	key := bot + "|" + ip.String()

	v.mu.Lock()
	now := v.now()
	if r, ok := v.verified.get(key, now); ok {
		v.mu.Unlock()
		return r.verified, false, nil
	}
	if r, ok := v.rejected.get(key, now); ok {
		v.mu.Unlock()
		return r.verified, false, nil
	}
	if f, ok := v.inflight[key]; ok {
		v.mu.Unlock()
		<-f.done
		return f.verdict.verified, false, nil
	}
	f := &botInflight{done: make(chan struct{})}
	v.inflight[key] = f
	v.mu.Unlock()

	ttl := botLookupErrorTTL
	defer func() {
		v.mu.Lock()
		f.verdict = botVerdict{verified: verified, err: err, expires: v.now().Add(ttl)}
		delete(v.inflight, key)
		if verified {
			v.rejected.delete(key)
			v.verified.put(key, f.verdict)
		} else {
			v.verified.delete(key)
			v.rejected.put(key, f.verdict)
		}
		v.mu.Unlock()
		close(f.done)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), v.timeout)
	defer cancel()
	verified, err = v.lookup(ctx, ip, domains)
	switch {
	case verified:
		ttl = botVerifiedTTL
	case err == nil:
		ttl = botRejectedTTL
	}
	return verified, true, err
}

// lookup returns a nil error with verified=false when DNS answered but did not confirm the crawler.
func (v *botVerifier) lookup(ctx context.Context, ip net.IP, domains []string) (bool, error) {
	names, err := v.resolver.LookupAddr(ctx, ip.String())
	if err != nil {
		if isNotFound(err) {
			return false, nil
		}
		return false, fmt.Errorf("reverse lookup: %w", err)
	}

	var lookupErr error
	for _, name := range names {
		if !hostInAnyDomain(name, domains) {
			continue
		}
		addrs, err := v.resolver.LookupIPAddr(ctx, name)
		if err != nil {
			if !isNotFound(err) && lookupErr == nil {
				lookupErr = fmt.Errorf("forward lookup %s: %w", name, err)
			}
			continue
		}
		for _, a := range addrs {
			if a.IP.Equal(ip) {
				return true, nil
			}
		}
	}
	return false, lookupErr
}

func isNotFound(err error) bool {
	var dnsErr *net.DNSError
	return errors.As(err, &dnsErr) && dnsErr.IsNotFound
}

func hostInAnyDomain(host string, domains []string) bool {
	for _, d := range domains {
		if hostInDomain(host, d) {
			return true
		}
	}
	return false
}
