#!/usr/bin/env bash
test_routing() {
    local i
    for ((i=1; i<=NUM_NODES; i++)); do
        request "$i" /torii/health_check
        assert_eq "$HTTP_CODE" 200
        assert_contains "$HTTP_BODY" 'version='
        assert_contains "$HTTP_BODY" "sliver=Node_$i"
        assert_contains "$(header Content-Type)" text/plain
        expect 200 "$i" 203.0.113.100
    done
    expect 403 1 203.0.113.100 0001000000000000 /exact-site exact.e2e.test
    expect 200 1 203.0.113.100 0001000000000000 /wildcard-site exact.e2e.test
    expect 403 1 203.0.113.100 0001000000000000 /wildcard-site child.e2e.test
    expect 200 1 203.0.113.100 0001000000000000 /exact-site unknown.invalid
    expect 403 1 198.51.100.41 '' /neutral default_site
    expect 403 1 198.51.100.41 ________________
    expect 200 1 198.51.100.41 "$ZERO"
    expect CAPTCHA 1 203.0.113.101 0000001000000000
    request 1 /torii/checker -H 'X-Test-IP: 198.51.100.41' -H 'X-Test-Features: 0100000000000000'
    decision 403
    request 1 /torii/checker -H 'X-Test-IP: 203.0.113.100' -H 'X-Test-Host: exact.e2e.test' \
        -H 'X-Test-URI: /exact-site' -H 'X-Test-Features: 0001000000000000'
    decision 403
    request 1 /torii/checker -H 'Torii-Real-IP: 203.0.113.100, 198.51.100.41' \
        -H 'X-Test-IP: 198.51.100.41' -H 'Torii-Feature-Control: 0100000000000000'
    decision 200
}
