package iptrie

import (
	"net/netip"
	"testing"
)

func TestTrieMatching(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rules   []string
		matches []string
		misses  []string
	}{
		{"empty", nil, nil, []string{"192.0.2.1", "::1"}},
		{"subnet", []string{"192.0.2.0/24"}, []string{"192.0.2.0", "192.0.2.255", "::ffff:192.0.2.1"}, []string{"192.0.1.255", "192.0.3.0", "2001:db8::1"}},
		{"host", []string{"192.0.2.42"}, []string{"192.0.2.42"}, []string{"192.0.2.41", "192.0.2.43"}},
		{"overlapping", []string{"10.1.2.0/24", "10.0.0.0/8", "10.1.2.0/24", "192.0.2.1/32"}, []string{"10.255.255.255", "10.1.2.3", "192.0.2.1"}, []string{"11.0.0.0", "192.0.2.2"}},
		{"all_ipv4", []string{"0.0.0.0/0"}, []string{"0.0.0.0", "255.255.255.255"}, []string{"::1", "2001:db8::1"}},
		{"unmasked", []string{"192.0.2.77/24"}, []string{"192.0.2.1"}, []string{"192.0.3.1"}},
		{"mapped_host", []string{"::ffff:1.2.3.4/128"}, []string{"1.2.3.4", "::ffff:1.2.3.4"}, []string{"1.2.3.5", "::1"}},
		{"mapped_bare", []string{"::ffff:1.2.3.4"}, []string{"1.2.3.4"}, []string{"1.2.3.5"}},
		{"mapped_subnet", []string{"::ffff:192.0.2.0/120"}, []string{"192.0.2.0", "192.0.2.255"}, []string{"192.0.3.0"}},
		{"mapped_all", []string{"::ffff:0.0.0.0/96"}, []string{"0.0.0.0", "255.255.255.255"}, []string{"::1"}},
		{"ipv6_subnet", []string{"2001:db8:1::/48"}, []string{"2001:db8:1::1", "2001:db8:1:ffff::1"}, []string{"2001:db8:2::1", "192.0.2.1"}},
		{"ipv6_host", []string{"2001:db8::42"}, []string{"2001:db8::42"}, []string{"2001:db8::43"}},
		{"all_ipv6", []string{"::/0"}, []string{"::1", "2001:db8::1"}, []string{"192.0.2.1"}},
		{"both_families", []string{"192.0.2.0/24", "2001:db8::/32"}, []string{"192.0.2.9", "2001:db8:ffff::1"}, []string{"198.51.100.1", "2001:db9::1"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trie := &Trie{}
			for _, rule := range tc.rules {
				prefix, ok := ParsePrefix(rule)
				if !ok {
					t.Fatalf("ParsePrefix(%q) failed", rule)
				}
				trie.Insert(prefix)
			}
			if trie.Len() != len(tc.rules) {
				t.Fatalf("Len = %d, want %d", trie.Len(), len(tc.rules))
			}
			for _, ip := range tc.matches {
				if !trie.Contains(netip.MustParseAddr(ip)) {
					t.Errorf("expected match for %s", ip)
				}
			}
			for _, ip := range tc.misses {
				if trie.Contains(netip.MustParseAddr(ip)) {
					t.Errorf("unexpected match for %s", ip)
				}
			}
		})
	}
}

func TestTrieNilAndInvalid(t *testing.T) {
	var none *Trie
	if none.Len() != 0 || none.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Error("a nil trie is not empty")
	}
	trie := &Trie{}
	trie.Insert(netip.Prefix{})
	trie.Insert(netip.MustParsePrefix("0.0.0.0/0"))
	if trie.Len() != 1 || trie.Contains(netip.Addr{}) {
		t.Error("an invalid prefix was inserted or the zero address matched")
	}
}

func TestParsePrefixRejects(t *testing.T) {
	for _, s := range []string{"", "bad", "192.0.2.1/33", "192.0.2.0/24 extra", "fe80::1%eth0", "192.0.2.300"} {
		if _, ok := ParsePrefix(s); ok {
			t.Errorf("ParsePrefix(%q) accepted", s)
		}
	}
}
