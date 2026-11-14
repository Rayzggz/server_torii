#!/usr/bin/env bash
test_routing() {
    local i
    for ((i=1; i<=NUM_NODES; i++)); do
        request "$i" /torii/health_check
        assert_eq "$HTTP_CODE" 200
        assert_contains "$HTTP_BODY" 'version='
        assert_contains "$HTTP_BODY" "sliver=Node_$i"
        assert_contains "$(header Content-Type)" text/plain
        expect pass "$i" 203.0.113.100
    done
    expect block 1 203.0.113.100 0001000000000000 /exact-site exact.e2e.test
    expect pass 1 203.0.113.100 0001000000000000 /wildcard-site exact.e2e.test
    expect block 1 203.0.113.100 0001000000000000 /wildcard-site child.e2e.test
    # No server block claims this host, so nginx sends no site ID and the default site applies.
    expect pass 1 203.0.113.100 0001000000000000 /exact-site unknown.invalid
    expect block 1 198.51.100.41 '' /neutral default_site
    expect block 1 198.51.100.41 ________________
    expect pass 1 198.51.100.41 "$ZERO"
    expect captcha 1 203.0.113.101 0000001000000000
}
