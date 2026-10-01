#!/usr/bin/env bash
test_flood() {
    local k start
    start=$SECONDS
    for ((k=1; k<=5; k++)); do expect 200 1 203.0.113.120 0000010000000000 "/speed/$k"; done
    expect 429 1 203.0.113.120 0000010000000000 /speed/6
    (( SECONDS-start < 9 )) || fail 'Flood boundary test took too long for its 10-second window; rerun on an idle machine'
    sleep 11
    expect 200 1 203.0.113.120 0000010000000000 /speed/recovered
    for ((k=1; k<=3; k++)); do expect 200 1 203.0.113.121 0000010000000000 /same; done
    expect 429 1 203.0.113.121 0000010000000000 /same
    expect 200 1 203.0.113.122 0000010000000000 /same
    for ((k=1; k<=5; k++)); do expect 200 1 203.0.113.123 0000010000000000 "/block/$k"; done
    for ((k=6; k<=9; k++)); do expect 429 1 203.0.113.123 0000010000000000 "/block/$k"; done
    expect 403 1 203.0.113.123 0000010000000000 /block/10
    cluster_decision 403 203.0.113.123
    # Expiration is independent of random gossip convergence: use a short-lived
    # policy and assert on its genuine originating node.
    for ((k=1; k<=10; k++)); do
        check 1 203.0.113.124 0000010000000000 "/expiry/$k" expiry.test
        if (( k<=5 )); then decision 200
        elif (( k<=9 )); then decision 429
        else decision 403; fi
    done
    wait_decision 200 8 1 203.0.113.124
}
