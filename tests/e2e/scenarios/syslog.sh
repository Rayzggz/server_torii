#!/usr/bin/env bash
# send_log SITE IP URI STATUS: one request report, as the connector sends for a served request.
send_log() {
    local site=$1 ip=$2 uri=$3 status=$4 message
    message=$(cat "$E2E/fixtures/report.json")
    message=${message//@SITE@/"$site"}; message=${message//@IP@/"$ip"}
    message=${message//@URI@/"$uri"}; message=${message//@STATUS@/"$status"}
    printf '%s\n' "$message" > "/dev/udp/127.0.0.1/$((BASE_PORT+1))"
}
test_syslog() {
    local i deadline remaining
    # Controls are observed over more than one complete analyzer window.
    for ((i=0; i<10; i++)); do
        send_log nonexistent 203.0.113.150 /ignored 404
        send_log non200 203.0.113.151 /healthy 200
    done
    send_log non200 203.0.113.152 /below-threshold 404
    printf 'malformed 203.0.113.153\n' > "/dev/udp/127.0.0.1/$((BASE_PORT+1))"
    # The former access-log format is no longer a report.
    printf '%s
' '<190>Jan 01 00:00:00 localhost non200: 203.0.113.153 - - [01/Jan/2026:00:00:00 +0000] "GET /x HTTP/1.1" 404 0 "-" "e2e"'         > "/dev/udp/127.0.0.1/$((BASE_PORT+1))"
    sleep 3
    for i in 150 151 152 153; do expect pass 1 "203.0.113.$i" "$ZERO" /neutral non200.test; done
    # The health check says what became of the reports: 11 for an analyzed site, 10 for a site
    # that does not exist, and 2 that are not reports.
    request 1 /torii/health_check
    assert_contains "$HTTP_BODY" 'reports_accepted=11' 'accepted reports'
    assert_contains "$HTTP_BODY" 'reports_unknown_site=10' 'reports for an unknown site'
    assert_contains "$HTTP_BODY" 'reports_malformed=2' 'malformed reports'
    assert_contains "$HTTP_BODY" 'reports_dropped=0' 'dropped reports' 
    # IP detection scores client errors (4xx); 5xx responses are the origin's fault, not the client's.
    # Send sustained bounded batches to avoid a batch straddling the 2s boundary.
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log non200 203.0.113.154 /failures 404; done
        check 1 203.0.113.154 "$ZERO" /neutral non200.test
        [[ "$HTTP_DECISION" != block ]] || break
        (( SECONDS < deadline )) || fail 'Non-200 analyzer did not block'
        sleep 0.3
    done
    decision block
    cluster_decision block 203.0.113.154 0 "$ZERO" /neutral non200.test
    # The block belongs to the site whose access log produced it.
    expect pass 1 203.0.113.154
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log uri "203.0.113.$((160+i))" '/hot//endpoint?x=1' 500; done
        check 1 203.0.113.180 "$ZERO" /hot/endpoint uri.test
        [[ "$HTTP_DECISION" != captcha ]] || break
        (( SECONDS < deadline )) || fail 'URI analyzer did not challenge'
        sleep 0.3
    done
    decision captcha
    deadline=$((SECONDS+180))
    for ((i=2; i<=NUM_NODES; i++)); do
        remaining=$((deadline-SECONDS))
        (( remaining > 0 )) || fail 'URI rule did not converge within 180 seconds'
        # Stop at the first challenge so polling does not accumulate failures.
        wait_decision captcha "$remaining" "$i" "203.0.113.$((220+i))" "$ZERO" /hot/endpoint uri.test
    done
    expect pass 1 203.0.113.180 "$ZERO" /unrelated uri.test
    expect pass 1 203.0.113.180 "$ZERO" /hot/endpoint
    # Separate short-lived policies prove expiration on the origin without
    # requiring probabilistic dissemination before a short TTL elapses.
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log non200expiry 203.0.113.182 /expiry-ip 404; done
        check 1 203.0.113.182 "$ZERO" /neutral non200expiry.test
        [[ "$HTTP_DECISION" != block ]] || break
        (( SECONDS < deadline )) || fail 'Expiring IP analyzer rule not created'
        sleep 0.3
    done
    decision block
    sleep 7
    expect pass 1 203.0.113.182 "$ZERO" /neutral non200expiry.test
    deadline=$((SECONDS+10))
    while true; do
        # A hot URI needs several distinct non-browser clients.
        for ((i=0; i<10; i++)); do send_log uriexpiry "203.0.113.$((240+i))" /expiry-uri 500; done
        check 1 203.0.113.184 "$ZERO" /expiry-uri uriexpiry.test
        [[ "$HTTP_DECISION" != captcha ]] || break
        (( SECONDS < deadline )) || fail 'Expiring URI analyzer rule not created'
        sleep 0.3
    done
    decision captcha
    sleep 7
    expect pass 1 203.0.113.184 "$ZERO" /expiry-uri uriexpiry.test
}
