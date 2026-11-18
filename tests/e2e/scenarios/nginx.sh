#!/usr/bin/env bash
# What only shows with nginx in front: the module, its directives and the shipped endpoints.
test_nginx() {
    local ip=203.0.113.230 url_block=0001000000000000 challenge=0000001000000000 before
    # A request that passes reaches the application with its method, host, URI and body.
    expect pass 1 "$ip"
    assert_eq "$HTTP_BODY" 'APP GET default_site /neutral' 'application response'
    expect pass 1 "$ip" "$ZERO" '/form?a=1' exact.e2e.test --data 'a=1&b=2'
    assert_eq "$HTTP_BODY" 'APP POST exact.e2e.test /form?a=1' 'application response to a POST'

    # A refused request gets Torii's page in the same response, with nginx's own headers; the
    # page names the address nginx saw. The headers of the connector protocol stay inside.
    expect block 1 "$ip" "$url_block" /blocked
    assert_contains "$HTTP_BODY" "E2E-403 Node_1 $ip" 'block page'
    assert_eq "$HTTP_REASON" Lists:url_block 'reason'
    assert_eq "$(header Torii-Decision)" '' 'the decision header stays inside'
    assert_eq "$(header Torii-Reason)" '' 'the reason header stays inside'
    assert_contains "$(header Content-Type)" text/html 'block content type'
    assert_eq "$(header Content-Length)" "$(wc -c < "$RESPONSE.body" | tr -d ' ')" 'block content length'
    assert_eq "$(grep -ic '^server:' "$RESPONSE.headers")" 1 'one Server header'
    assert_eq "$(grep -ic '^date:' "$RESPONSE.headers")" 1 'one Date header'
    expect block 1 "$ip" "$url_block" /blocked default_site --data 'a=1'
    check 1 "$ip" "$url_block" /blocked default_site --head
    assert_eq "$HTTP_CODE" 403 'HEAD of a blocked URI'
    # The challenge page arrives with its session cookie.
    expect challenge 1 "$ip" "$challenge"
    assert_contains "$(header Set-Cookie)" __torii_session_id= 'challenge session cookie'

    # Nodes with an even number are reached over their Unix socket.
    expect pass 2 "$ip"
    expect block 2 "$ip" "$url_block" /blocked
    assert_contains "$HTTP_BODY" "E2E-403 Node_2 $ip" 'block page over the Unix socket'

    # The client address is the one of the connection. X-Forwarded-For replaces it only for
    # the proxy nginx trusts; what a client says in the headers of the protocol counts for nothing.
    request 1 /blocked -H 'Host: default_site' -H 'X-E2E-Features: +url_block'
    assert_eq "$HTTP_CODE" 403 'no forwarded address'
    assert_contains "$HTTP_BODY" 'E2E-403 Node_1 127.0.0.1' 'address of the connection'
    request 1 /blocked -H 'Host: default_site' -H 'X-E2E-Features: +url_block' \
        -H 'X-Forwarded-For: 203.0.113.231' --interface 127.0.0.2
    assert_eq "$HTTP_CODE" 403 'forwarded address from a client that is not trusted'
    assert_contains "$HTTP_BODY" 'E2E-403 Node_1 127.0.0.2' 'address of a client that is not trusted'
    # 198.51.100.41 is blocked; "exact" blocks /exact-site.
    expect pass 1 203.0.113.232 0101000000000000 /exact-site default_site \
        -H 'Torii-Client-IP: 198.51.100.41' -H 'Torii-Site: exact' -H 'Torii-Features: +challenge'
    expect block 1 198.51.100.41 0100000000000000

    # torii off, and torii_features written in a location instead of taken from the request.
    check 1 "$ip" "$challenge" /e2e-open/page
    assert_eq "$HTTP_CODE" 200 'torii off'
    assert_eq "$HTTP_DECISION" '' 'torii off: no decision'
    expect challenge 1 "$ip" "$ZERO" /e2e-strict/page
    expect pass 1 "$ip" "$challenge" /e2e-relaxed/page

    # A site Torii does not know is no decision: torii_on_error says what happens then.
    check 1 "$ip" "$ZERO" /neutral nosite.test
    assert_eq "$HTTP_CODE" 200 'unknown site, torii_on_error pass'
    assert_eq "$HTTP_DECISION" error 'unknown site decision'
    assert_contains "$HTTP_BODY" 'APP GET nosite.test /neutral' 'unknown site reaches the application'
    check 1 "$ip" "$ZERO" /neutral nosite-deny.test
    assert_eq "$HTTP_CODE" 503 'unknown site, torii_on_error deny'
    assert_eq "$HTTP_DECISION" error 'refused unknown site decision'

    # Only the browser-facing endpoints of Torii are reachable through a site: the check
    # endpoint is an ordinary URI of the application, and peers do not talk through nginx.
    public 1 /torii/health_check "$ip" default_site
    assert_eq "$HTTP_CODE" 200 'health check through a site'
    assert_contains "$HTTP_BODY" 'sliver=Node_1' 'health check identity'
    expect pass 1 "$ip" "$ZERO" /v1/check
    assert_eq "$HTTP_BODY" 'APP GET default_site /v1/check' 'the check endpoint is not exposed'
    public 1 /torii/gossip "$ip" default_site -H 'Content-Type: application/json' --data '{}'
    assert_eq "$HTTP_CODE" 403 'gossip is not reachable through a site'
    public 1 /torii/nothing "$ip" default_site
    assert_eq "$HTTP_CODE" 403 'unknown endpoint of Torii'

    # Every request nginx served is reported to its node.
    # The counters of the health check are for whoever has the health key; nginx forwards it.
    assert_eq "$(grep -c '^reports_\|^counter_' <<< "$HTTP_BODY")" 0 'no counters without the health key'
    public 1 "$(health_uri)" "$ip" default_site
    before=$(sed -n 's/^reports_received=//p' <<< "$HTTP_BODY")
    [[ -n "$before" ]] || fail "health check with the key shows no counters through nginx: <$HTTP_BODY>"
    expect pass 1 "$ip" "$ZERO" /reported
    wait_counter reports_received "$((before+2))"
    public 1 "$(health_uri)" "$ip" default_site
    assert_contains "$HTTP_BODY" 'reports_malformed=0' 'no report of nginx is malformed'

    # The access log of nginx has the site, the decision and the reason of every request.
    local access="$RUN/nginx/logs/access.log"
    log_line "$access" "$ip|default_site|/neutral|200|default_site|pass|"
    log_line "$access" "$ip|default_site|/blocked|403|default_site|block|Lists:url_block"
    log_line "$access" "$ip|default_site|/neutral|503|default_site|challenge|Challenge"
    log_line "$access" "$ip|nosite-deny.test|/neutral|503|nonexistent|error|"
    log_line "$access" '127.0.0.2|default_site|/blocked|403|default_site|block|Lists:url_block'
}
