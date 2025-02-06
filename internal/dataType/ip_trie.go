package dataType

import "net"

type TrieNode struct {
	children [2]*TrieNode
	isEnd    bool
}

// Insert IP or CIDR rule into trie, prefixLength represents the prefix length
func (node *TrieNode) Insert(ipNet *net.IPNet) {
	ones, _ := ipNet.Mask.Size()
	ip := ipNet.IP.To4()
	if ip == nil {
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
