#!/usr/bin/env bash
send_log() {
    local tag=$1 ip=$2 uri=$3 status=$4 message
    message=$(cat "$E2E/fixtures/syslog.txt")
    message=${message//@TAG@/"$tag"}; message=${message//@IP@/"$ip"}
    message=${message//@URI@/"$uri"}; message=${message//@STATUS@/"$status"}
    printf '%s\n' "$message" > "/dev/udp/127.0.0.1/$((BASE_PORT+1))"
}
test_syslog() {
    local i deadline remaining
    # Controls are observed over more than one complete analyzer window.
    for ((i=0; i<10; i++)); do
        send_log nonexistent 203.0.113.150 /ignored 500
        send_log e2e-non200 203.0.113.151 /healthy 200
    done
    send_log e2e-non200 203.0.113.152 /below-threshold 500
    printf 'malformed 203.0.113.153\n' > "/dev/udp/127.0.0.1/$((BASE_PORT+1))"
    sleep 3
    for i in 150 151 152 153; do expect 200 1 "203.0.113.$i"; done
    # Send sustained bounded batches to avoid a batch straddling the 2s boundary.
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log e2e-non200 203.0.113.154 /failures 500; done
        check 1 203.0.113.154
        [[ "$HTTP_ACTION" != 403 ]] || break
        (( SECONDS < deadline )) || fail 'Non-200 analyzer did not block'
        sleep 0.3
    done
    decision 403
    cluster_decision 403 203.0.113.154
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log e2e-uri "203.0.113.$((160+i))" '/hot//endpoint?x=1' 500; done
        check 1 203.0.113.180 "$ZERO" /hot/endpoint
        [[ "$HTTP_ACTION" != CAPTCHA ]] || break
        (( SECONDS < deadline )) || fail 'URI analyzer did not challenge'
        sleep 0.3
    done
    decision CAPTCHA
    deadline=$((SECONDS+180))
    for ((i=2; i<=NUM_NODES; i++)); do
        remaining=$((deadline-SECONDS))
        (( remaining > 0 )) || fail 'URI rule did not converge within 180 seconds'
        # Stop at the first challenge so polling does not accumulate failures.
        wait_decision CAPTCHA "$remaining" "$i" "203.0.113.$((220+i))" "$ZERO" /hot/endpoint
    done
    expect 200 1 203.0.113.180 "$ZERO" /unrelated
    # Separate short-lived policies prove expiration on the origin without
    # requiring probabilistic dissemination before a short TTL elapses.
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log e2e-non200expiry 203.0.113.182 /expiry-ip 500; done
        check 1 203.0.113.182
        [[ "$HTTP_ACTION" != 403 ]] || break
        (( SECONDS < deadline )) || fail 'Expiring IP analyzer rule not created'
        sleep 0.3
    done
    decision 403
    sleep 7
    expect 200 1 203.0.113.182
    deadline=$((SECONDS+10))
    while true; do
        for ((i=0; i<10; i++)); do send_log e2e-uriexpiry 203.0.113.183 /expiry-uri 500; done
        check 1 203.0.113.184 "$ZERO" /expiry-uri
        [[ "$HTTP_ACTION" != CAPTCHA ]] || break
        (( SECONDS < deadline )) || fail 'Expiring URI analyzer rule not created'
        sleep 0.3
    done
    decision CAPTCHA
    sleep 7
    expect 200 1 203.0.113.184 "$ZERO" /expiry-uri
}
