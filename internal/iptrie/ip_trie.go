// Package iptrie is a set of IP networks that answers, in time independent of the number of
// networks, whether an address lies in one of them.
package iptrie

import "net/netip"

type node struct {
	children [2]*node
	isEnd    bool
}

// Trie is a set of IPv4 and IPv6 networks. The zero Trie is empty and ready to use; a nil Trie
// is empty and can be searched.
type Trie struct {
	v4, v6 node
	count  int
}

// Len returns the number of networks inserted.
func (t *Trie) Len() int {
	if t == nil {
		return 0
	}
	return t.count
}

// Insert adds a network. An IPv4-mapped IPv6 network that lies within IPv4 space (::ffff:0:0/96
// or longer) is added as the IPv4 network it stands for.
func (t *Trie) Insert(prefix netip.Prefix) {
	if !prefix.IsValid() {
		return
	}
	addr, bits := prefix.Addr(), prefix.Bits()
	if addr.Is4In6() && bits >= 96 {
		addr, bits = addr.Unmap(), bits-96
	}
	root, bytes := &t.v6, addr.AsSlice()
	if addr.Is4() {
		root = &t.v4
	}
	current := root
	for i := 0; i < bits; i++ {
		bit := (bytes[i/8] >> (7 - uint(i%8))) & 1
		if current.children[bit] == nil {
			current.children[bit] = &node{}
		}
		current = current.children[bit]
	}
	current.isEnd = true
	t.count++
}

// Contains reports whether addr lies in one of the networks. An IPv4-mapped IPv6 address is
// looked up as the IPv4 address it stands for; the zero Addr lies in none.
func (t *Trie) Contains(addr netip.Addr) bool {
	if t == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		bytes := addr.As4()
		return t.v4.contains(bytes[:])
	}
	bytes := addr.As16()
	return t.v6.contains(bytes[:])
}

func (n *node) contains(bytes []byte) bool {
	current := n
	for i := 0; i < len(bytes)*8; i++ {
		if current.isEnd {
			return true
		}
		current = current.children[(bytes[i/8]>>(7-uint(i%8)))&1]
		if current == nil {
			return false
		}
	}
	return current.isEnd
}

// ParsePrefix parses a network in CIDR notation, or a single address, which becomes the network
// of that one address.
func ParsePrefix(s string) (netip.Prefix, bool) {
	if prefix, err := netip.ParsePrefix(s); err == nil {
		return prefix.Masked(), true
	}
	if addr, err := netip.ParseAddr(s); err == nil && addr.Zone() == "" {
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()), true
	}
	return netip.Prefix{}, false
}
