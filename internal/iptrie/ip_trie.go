package iptrie

import "net"

type TrieNode struct {
	children [2]*TrieNode
	isEnd    bool
}

// IsEmpty reports whether the trie contains any supported IP rules.
func (node *TrieNode) IsEmpty() bool {
	return node == nil || (!node.isEnd && node.children[0] == nil && node.children[1] == nil)
}

// Insert IP or CIDR rule into trie, prefixLength represents the prefix length
func (node *TrieNode) Insert(ipNet *net.IPNet) {
	ones, bits := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
		return
	}
	// An IPv4-mapped IPv6 rule (e.g. ::ffff:1.2.3.4/128) carries a 128-bit
	// mask. Translate it to the equivalent IPv4 prefix; a prefix shorter than
	// the ::ffff:0:0/96 mapping reaches beyond IPv4 space and is unsupported.
	if bits == 8*net.IPv6len {
		if ones < 8*(net.IPv6len-net.IPv4len) {
			return
		}
		ones -= 8 * (net.IPv6len - net.IPv4len)
	}
	if ones > 8*net.IPv4len {
		return
	}
	current := node
	for i := 0; i < ones; i++ {
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if current.children[bit] == nil {
			current.children[bit] = &TrieNode{}
		}
		current = current.children[bit]
	}
	current.isEnd = true
}

// Search if the ip is in the trie
func (node *TrieNode) Search(ip net.IP) bool {
	ip = ip.To4()
	if ip == nil {
		return false
	}
	current := node
	for i := 0; i < 32; i++ {
		if current.isEnd {
			return true
		}
		bit := (ip[i/8] >> (7 - uint(i%8))) & 1
		if current.children[bit] == nil {
			return false
		}
		current = current.children[bit]
	}
	return current.isEnd
}
