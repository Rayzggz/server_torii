#!/usr/bin/env bash
gossip_payload() {
    local ip=$1 expires=$2 id=$3 origin=$4 stamp=$5 site=${6-default_site} content
    content=$(jq -cn --arg ip "$ip" --argjson expires "$expires" --arg site "$site" \
        '{site:$site,rule_type:"IP",value:$ip,action:"BLOCK",expires_at:$expires}')
    PAYLOAD=$(jq -cn --arg id "$id" --arg origin "$origin" --arg content "$content" --argjson stamp "$stamp" \
        '{id:$id,type:"ACTION_RULE",content:$content,origin_node:$origin,timestamp:$stamp,seq:1}')
    SIG=$(hmac "$PAYLOAD" "$SECRET")
}
post_gossip() {
    request "${1:-1}" /torii/gossip -H 'Content-Type: application/json' -H "X-Torii-Signature: $SIG" --data-binary "$PAYLOAD"
}
ack() { assert_eq "$HTTP_CODE" 200; assert_eq "$HTTP_BODY" ACK; }
test_gossip() {
    local i ip stamp expiration id origin expected case_name count content deadline synced
    # Genuine origin: generate the rule through HTTPFlood and check every node.
    for ((i=1; i<=10; i++)); do
        check 1 203.0.113.200 0000010000000000 "/gossip/$i"
        if (( i <= 5 )); then decision pass
        elif (( i <= 9 )); then decision rate_limit
        else decision block; fi
    done
    cluster_decision block 203.0.113.200
    stamp=$(date +%s); expiration=$((stamp+45))
    # Deliver a shared absolute expiry directly to all receivers. A short TTL
    # must not be used as a deadline for probabilistic epidemic propagation.
    for ((i=1; i<=NUM_NODES; i++)); do
        origin=Node_2
        (( i != 2 )) || origin=Node_1
        gossip_payload 203.0.113.201 "$expiration" "$(uuid)" "$origin" "$stamp"
        post_gossip "$i"; ack
        expect block "$i" 203.0.113.201
    done
    wait_decision pass 50 1 203.0.113.201
    cluster_decision pass 203.0.113.201
    gossip_payload 203.0.113.202 "$(( $(date +%s)+300 ))" "$(uuid)" Node_2 "$(date +%s)"
    for ((i=0; i<5; i++)); do post_gossip; ack; done
    # This injected message claims Node_2 as origin, so only require the other nodes.
    cluster_decision block 203.0.113.202 2
    count=$(grep -Fc '[GOSSIP] Received ActionRule for IP:203.0.113.202 on site default_site from ' "$RUN/node1/log/server_torii.log" || true)
    assert_eq "$count" 1 'duplicate application'
    i=203
    for case_name in signature origin empty_id invalid_id non_v4 old future private no_site bad_site; do
        ip="203.0.113.$i"; i=$((i+1)); stamp=$(date +%s); id=$(uuid); origin=Node_2; expected=ACK
        local rule_site=default_site
        case "$case_name" in
            signature) expected=Forbidden ;;
            origin) origin=UnknownAttacker; expected='Forbidden: Unknown OriginNode' ;;
            empty_id) id=''; expected='Forbidden: Empty Message ID' ;;
            invalid_id) id=not-a-uuid; expected='Forbidden: Invalid Message ID' ;;
            non_v4) id=00000000-0000-1000-8000-000000000000; expected='Forbidden: UUID v4 required' ;;
            old) stamp=$((stamp-660)) ;;
            future) stamp=$((stamp+300)) ;;
            private) ip=192.168.10.10 ;;
            # A rule must name the site it belongs to.
            no_site) rule_site='' ;;
            bad_site) rule_site='../default_site' ;;
        esac
        gossip_payload "$ip" "$(( $(date +%s)+120 ))" "$id" "$origin" "$stamp" "$rule_site"
        if [[ "$case_name" == signature ]]; then
            if [[ ${SIG:0:1} == 0 ]]; then SIG="1${SIG:1}"; else SIG="0${SIG:1}"; fi
        fi
        post_gossip
        if [[ "$expected" == ACK ]]; then ack; else assert_eq "$HTTP_CODE" 403; assert_eq "$HTTP_BODY" "$expected"; fi
        # Observe a full gossip broadcast interval before asserting no side effects.
        sleep 1
        for ((count=1; count<=NUM_NODES; count++)); do expect pass "$count" "$ip"; done
    done
    PAYLOAD='{invalid'; SIG=$(hmac "$PAYLOAD" "$SECRET")
    post_gossip
    assert_eq "$HTTP_CODE" 400 'malformed gossip JSON'
    dd if=/dev/zero of="$RUN/oversized.json" bs=1048576 count=11 status=none
    request 1 /torii/gossip -H 'Expect: 100-continue' -H 'Content-Type: application/json' --data-binary "@$RUN/oversized.json"
    assert_eq "$HTTP_CODE" 413
    request 1 /torii/gossip
    assert_eq "$HTTP_CODE" 405
    # SYNC exercises the snapshot receiver and all three dynamic rule types.
    stamp=$(date +%s)
    content=$(jq -cn --argjson expiry "$((stamp+120))" '{rules:[
        {site:"default_site",rule_type:"IP",value:"203.0.113.220",action:"BLOCK",expires_at:$expiry},
        {site:"default_site",rule_type:"UA",value:"ToriiE2EUA/1.0",action:"BLOCK",expires_at:$expiry},
        {site:"default_site",rule_type:"URI",value:"/sync/limited",action:"CAPTCHA",expires_at:$expiry},
        {site:"default_site",rule_type:"IP",value:"192.168.10.20",action:"BLOCK",expires_at:$expiry}]}')
    PAYLOAD=$(jq -cn --arg id "$(uuid)" --arg content "$content" --argjson stamp "$stamp" \
        '{id:$id,type:"SYNC",content:$content,origin_node:"Node_2",timestamp:$stamp,seq:1}')
    SIG=$(hmac "$PAYLOAD" "$SECRET")
    post_gossip; ack
    expect block 1 203.0.113.220
    expect block 1 203.0.113.221 "$ZERO" /neutral default_site -A ToriiE2EUA/1.0
    expect captcha 1 203.0.113.221 "$ZERO" /sync/limited
    expect pass 1 192.168.10.20
    # The synchronized rules stay on their site.
    expect pass 1 203.0.113.220 "$ZERO" /neutral exact.e2e.test
    # SYNC is not epidemically relayed. The real 30s anti-entropy tick must
    # deliver its snapshot to at least one other peer; do not assume which one.
    deadline=$((SECONDS+40)); synced=0
    while (( ! synced )); do
        for ((i=2; i<=NUM_NODES; i++)); do
            check "$i" 203.0.113.220
            if [[ "$HTTP_DECISION" == block ]]; then decision block; synced=1; break; fi
            decision pass
        done
        (( synced )) && break
        (( SECONDS < deadline )) || fail 'Periodic anti-entropy did not deliver the SYNC snapshot'
        sleep 0.5
    done
}
