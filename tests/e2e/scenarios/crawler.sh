#!/usr/bin/env bash
test_crawler() {
    local prefixes candidate hostname addresses selected='' base attempts=0
    # Official list; never send application traffic to the crawler address.
    # Torii receives it through its configured reverse-proxy client-IP header.
    if ! curl --fail --silent --show-error --connect-timeout 5 --max-time 30 \
        https://developers.google.com/static/crawling/ipranges/common-crawlers.json > "$RUN/google-crawlers.json"; then
        fail 'DEPENDENCY: unable to download Google crawler ranges'
    fi
    prefixes=$(jq -er '[.prefixes[] | .ipv4Prefix // empty] | if length > 0 then .[] else error("no IPv4 prefixes") end' "$RUN/google-crawlers.json")
    while IFS= read -r base; do
        base=${base%/*}
        # Use only the network address itself (always in its published prefix).
        candidate=$base
        attempts=$((attempts+1))
        (( attempts <= 30 )) || break
        if ! hostname=$(dig +time=2 +tries=1 +short -x "$candidate" | awk 'NR==1 {print}'); then continue; fi
        hostname=${hostname%.}
        case "$hostname" in *.googlebot.com|*.google.com|*.googleusercontent.com) ;; *) continue ;; esac
        if ! addresses=$(dig +time=2 +tries=1 +short A "$hostname"); then continue; fi
        if grep -Fxq "$candidate" <<< "$addresses"; then selected=$candidate; break; fi
    done <<< "$prefixes"
    [[ -n "$selected" ]] || fail 'DEPENDENCY: no forward/reverse verified Google crawler found within 30 published prefixes'
    log "Verified Google crawler $selected -> $hostname (saved official range list)"
    # CAPTCHA proves that VerifyBot actually short-circuits the remaining checks.
    expect 200 1 "$selected" 0000101000000000 /neutral default_site -A 'Googlebot/2.1'
    expect CAPTCHA 1 "$selected" 0000001000000000 /neutral default_site -A 'Googlebot/2.1'
    expect 403 1 192.0.2.1 0000100000000000 /neutral default_site -A 'Googlebot/2.1'
    expect 200 1 192.0.2.1 "$ZERO" /neutral default_site -A 'Googlebot/2.1'
    expect 200 1 203.0.113.210 0000100000000000
}
