#!/usr/bin/env bash
test_access() {
    local ip uri
    for ip in 198.51.100.10 198.51.100.17 ::ffff:198.51.100.17; do
        # Allow short-circuits URL block; .10 is also in the IP block list.
        expect pass 1 "$ip" 1101000000000000 /blocked
    done
    for ip in 198.51.100.10 198.51.100.41 ::ffff:198.51.100.41; do expect block 1 "$ip" 0100000000000000; done
    for ip in 198.51.100.48 2001:db8:4::42 invalid-ip; do expect pass 1 "$ip" 0100000000000000; done
    for uri in /allowed /overlap /public/123; do
        expect pass 1 203.0.113.110 0011001000000000 "$uri"
    done
    for uri in /blocked /private/123 /overlap; do expect block 1 203.0.113.110 0001000000000000 "$uri"; done
    for uri in /blocked-extra /private/abc; do expect pass 1 203.0.113.110 0001000000000000 "$uri"; done
    for ip in 198.51.100.60 198.51.100.65 ::ffff:198.51.100.65; do expect captcha 1 "$ip" 0000000001000000; done
    # Native IPv6 rules are intentionally unsupported by the current IPv4 trie.
    expect block 1 2001:db8:1::42 1001000000000000 /blocked
    expect pass 1 2001:db8:2::42 0100000000000000
    expect pass 1 2001:db8:3::42 0000000001000000
    expect pass 1 198.51.100.80 0000000001000000
    for uri in /challenge /protected/123; do expect captcha 1 203.0.113.111 0000000000100000 "$uri"; done
    expect pass 1 203.0.113.111 0000000000100000 /protected/abc
    expect block 1 198.51.100.41 0110000000000000 /allowed
}
