package dataType

import (
	"net"
	"testing"
)

func TestTrieMatching(t *testing.T) {
	for _, tc := range []struct {
		name    string
		rules   []string
		matches []string
		misses  []string
	}{
		{"empty", nil, nil, []string{"192.0.2.1", "::1", "invalid"}},
		{"subnet", []string{"192.0.2.0/24"}, []string{"192.0.2.0", "192.0.2.255", "::ffff:192.0.2.1"}, []string{"192.0.1.255", "192.0.3.0", "2001:db8::1"}},
		{"host", []string{"192.0.2.42/32"}, []string{"192.0.2.42"}, []string{"192.0.2.41", "192.0.2.43"}},
		{"overlapping", []string{"10.1.2.0/24", "10.0.0.0/8", "10.1.2.0/24", "192.0.2.1/32"}, []string{"10.255.255.255", "10.1.2.3", "192.0.2.1"}, []string{"11.0.0.0", "192.0.2.2"}},
		{"all_ipv4", []string{"0.0.0.0/0"}, []string{"0.0.0.0", "255.255.255.255"}, []string{"::1", "invalid"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trie := &TrieNode{}
			for _, cidr := range tc.rules {
				_, network, err := net.ParseCIDR(cidr)
				if err != nil {
					t.Fatal(err)
				}
				trie.Insert(network)
			}
			if trie.IsEmpty() != (len(tc.rules) == 0) {
				t.Fatal("unexpected empty state")
			}
			for _, ip := range tc.matches {
				if !trie.Search(net.ParseIP(ip)) {
					t.Errorf("expected match for %s", ip)
				}
			}
			for _, ip := range tc.misses {
				if trie.Search(net.ParseIP(ip)) {
					t.Errorf("unexpected match for %s", ip)
				}
			}
		})
	}
}

func TestTrieIgnoresIPv6Rules(t *testing.T) {
	var nilTrie *TrieNode
	if !nilTrie.IsEmpty() {
		t.Fatal("nil trie should be empty")
	}
	trie := &TrieNode{}
	_, network, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	trie.Insert(network)
	if !trie.IsEmpty() {
		t.Fatal("unsupported IPv6 rule populated trie")
	}
}
