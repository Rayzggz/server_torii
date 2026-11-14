#!/usr/bin/env bash
# Connector protocol v1, as spoken by the ngx_torii module.
v1() {
    local node=$1 path=$2 ip=$3 uri=$4
    shift 4
    request "$node" "$path" -H "Torii-Client-IP: $ip" -H "Torii-URI: $uri" "$@"
}
test_connector() {
    local sock="$RUN/node1/torii.sock"
    # Pass: no body, the decision is in the header.
    v1 1 /v1/check 203.0.113.120 /neutral -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 204 'pass status'
    assert_eq "$(header Torii-Decision)" pass 'pass decision'
    assert_eq "$HTTP_BODY" '' 'pass body'
    # Deny: the response is the page the visitor gets, not a status to translate.
    v1 1 /v1/check 203.0.113.120 /blocked -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 403 'block status'
    assert_eq "$(header Torii-Decision)" block 'block decision'
    assert_eq "$(header Torii-Reason)" URLBlock 'block reason'
    assert_contains "$HTTP_BODY" 'E2E-403 Node_1 203.0.113.120' 'block page'
    v1 1 /v1/check 203.0.113.120 /challenge -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 503 'captcha status'
    assert_eq "$(header Torii-Decision)" captcha 'captcha decision'
    assert_contains "$HTTP_BODY" E2E-ALTCHA 'captcha page'
    assert_contains "$(header Set-Cookie)" __torii_session_id= 'challenge session cookie'
    # Feature overrides are named.
    v1 1 /v1/check 203.0.113.120 /blocked -H 'Torii-Site: default_site' -H 'Torii-Features: -url_block'
    assert_eq "$(header Torii-Decision)" pass 'feature forced off'
    v1 1 /v1/check 203.0.113.120 /neutral -H 'Torii-Site: default_site' -H 'Torii-Features: +captcha'
    assert_eq "$(header Torii-Decision)" captcha 'feature forced on'
    # A named site is used as is.
    v1 1 /v1/check 203.0.113.120 /exact-site -H 'Torii-Site: exact'
    assert_eq "$(header Torii-Decision)" block 'named site'
    # The host never selects the site: without a site ID the request belongs to the default site.
    v1 1 /v1/check 203.0.113.120 /exact-site -H 'Torii-Host: exact.e2e.test'
    assert_eq "$(header Torii-Decision)" pass 'default site without a site ID'
    # No decision header when Torii could not decide.
    v1 1 /v1/check 203.0.113.120 /neutral -H 'Torii-Site: missing_site'
    assert_eq "$HTTP_CODE" 500 'unknown site status'
    assert_eq "$(header Torii-Decision)" '' 'unknown site has no decision'
    request 1 /v1/check -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 400 'missing request headers'
    assert_eq "$(header Torii-Decision)" '' 'bad request has no decision'
    # Browser-facing endpoints.
    v1 1 /v1/public/health_check 203.0.113.120 /torii/health_check
    assert_eq "$HTTP_CODE" 200 'public health check'
    assert_contains "$HTTP_BODY" 'sliver=Node_1' 'public health identity'
    v1 1 /v1/public/nothing 203.0.113.120 /torii/nothing
    assert_eq "$HTTP_CODE" 403 'unknown public endpoint'
    # The Unix socket serves the same protocol as the TCP port.
    ASSERTIONS=$((ASSERTIONS + 1))
    [[ -S "$sock" ]] || fail "Unix socket $sock was not created"
    v1 1 /v1/check 203.0.113.120 /neutral --unix-socket "$sock" -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 204 'unix pass status'
    assert_eq "$(header Torii-Decision)" pass 'unix pass decision'
    v1 1 /v1/check 203.0.113.120 /blocked --unix-socket "$sock" -H 'Torii-Site: default_site'
    assert_eq "$HTTP_CODE" 403 'unix block status'
    assert_contains "$HTTP_BODY" 'E2E-403 Node_1 203.0.113.120' 'unix block page'
}
