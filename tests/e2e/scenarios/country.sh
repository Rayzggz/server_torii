#!/usr/bin/env bash
test_country() {
    local ip country expected
    while IFS=$'\t' read -r ip country expected; do
        [[ "$ip" != \#* && -n "$ip" ]] || continue
        log "GeoIP fixture: $ip ($country) -> $expected"
        expect "$expected" 1 "$ip" 0000000010000000
        if [[ "$country" == AU ]]; then
            # Unknown=block proves this is a resolved country override, not fallback.
            expect 200 1 "$ip" 0000000010000000 /neutral unknown.test
        fi
    done < "$E2E/fixtures/countries.tsv"
    for ip in 127.0.0.1 192.168.1.1 invalid-ip; do
        expect 200 1 "$ip" 0000000010000000
        expect 403 1 "$ip" 0000000010000000 /neutral unknown.test
    done
    expect 200 "$NUM_NODES" 8.8.8.8 0000000010000000
    expect 403 "$NUM_NODES" 8.8.8.8 0000000010000000 /neutral unknown.test
    expect 200 1 8.8.8.8 "$ZERO"
    # IP allow wins over the country's unknown=block policy.
    expect 200 1 198.51.100.10 1000000010000000 /neutral unknown.test
}
