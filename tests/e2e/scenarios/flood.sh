#!/usr/bin/env bash
test_flood() {
    local k start
    start=$SECONDS
    for ((k=1; k<=5; k++)); do expect pass 1 203.0.113.120 0000010000000000 "/speed/$k"; done
    expect rate_limit 1 203.0.113.120 0000010000000000 /speed/6
    (( SECONDS-start < 9 )) || fail 'Flood boundary test took too long for its 10-second window; rerun on an idle machine'
    sleep 11
    expect pass 1 203.0.113.120 0000010000000000 /speed/recovered
    for ((k=1; k<=3; k++)); do expect pass 1 203.0.113.121 0000010000000000 /same; done
    expect rate_limit 1 203.0.113.121 0000010000000000 /same
    expect pass 1 203.0.113.122 0000010000000000 /same
    for ((k=1; k<=5; k++)); do expect pass 1 203.0.113.123 0000010000000000 "/block/$k"; done
    for ((k=6; k<=9; k++)); do expect rate_limit 1 203.0.113.123 0000010000000000 "/block/$k"; done
    expect block 1 203.0.113.123 0000010000000000 /block/10
    cluster_decision block 203.0.113.123
    # Expiration is independent of random gossip convergence: use a short-lived
    # policy and assert on its genuine originating node.
    for ((k=1; k<=10; k++)); do
        check 1 203.0.113.124 0000010000000000 "/expiry/$k" expiry.test
        if (( k<=5 )); then decision pass
        elif (( k<=9 )); then decision rate_limit
        else decision block; fi
    done
    # The block exists on the site that made it, and nowhere else.
    expect pass 1 203.0.113.124
    expect block 1 203.0.113.124 "$ZERO" /neutral expiry.test
    wait_decision pass 8 1 203.0.113.124 "$ZERO" /neutral expiry.test
}
