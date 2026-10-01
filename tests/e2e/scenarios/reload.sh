#!/usr/bin/env bash
test_reload() {
    local rules="$RUN/node1/rules/default" logfile="$RUN/node1/log/server_torii.log" before deadline
    expect 200 1 203.0.113.190 0001000000000000 /reloaded
    printf '/reloaded\n' >> "$rules/URL_BlockList.conf"
    kill -HUP "${NODE_PIDS[0]}"
    wait_decision 403 10 1 203.0.113.190 0001000000000000 /reloaded
    expect 200 2 203.0.113.190 0001000000000000 /reloaded
    cp "$rules/Server.yml" "$RUN/valid-server.yml"
    before=$(grep -Fc 'Reload failed:' "$logfile" || true)
    printf 'CAPTCHA: [invalid yaml\n' > "$rules/Server.yml"
    kill -HUP "${NODE_PIDS[0]}"
    deadline=$((SECONDS+10))
    while (( $(grep -Fc 'Reload failed:' "$logfile" || true) <= before )); do
        alive
        (( SECONDS < deadline )) || fail 'Invalid reload not rejected'
        sleep 0.2
    done
    expect 403 1 203.0.113.190 0001000000000000 /reloaded
    cp "$RUN/valid-server.yml" "$rules/Server.yml"
    cp "$E2E/fixtures/rules/URL_BlockList.conf" "$rules/URL_BlockList.conf"
    kill -HUP "${NODE_PIDS[0]}"
    wait_decision 200 10 1 203.0.113.190 0001000000000000 /reloaded
    # A failed database reload retains the previous successful database reader.
    mv "$RUN/node1/data/GeoLite2-Country.mmdb" "$RUN/country.saved.mmdb"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" 'retaining the previous reader'
    expect CAPTCHA 1 8.8.8.8 0000000010000000
    mv "$RUN/country.saved.mmdb" "$RUN/node1/data/GeoLite2-Country.mmdb"
    kill -HUP "${NODE_PIDS[0]}"
}
