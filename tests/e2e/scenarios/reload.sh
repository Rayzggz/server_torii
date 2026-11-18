#!/usr/bin/env bash
test_reload() {
    local rules="$RUN/node1/rules/default" logfile="$RUN/node1/log/server_torii.log" before deadline
    expect pass 1 203.0.113.190 0001000000000000 /reloaded
    printf '/reloaded\n' >> "$rules/URL_BlockList.conf"
    kill -HUP "${NODE_PIDS[0]}"
    wait_decision block 10 1 203.0.113.190 0001000000000000 /reloaded
    expect pass 2 203.0.113.190 0001000000000000 /reloaded
    cp "$rules/Server.yml" "$RUN/valid-server.yml"
    before=$(grep -Fc '[error] reload failed' "$logfile" || true)
    printf 'CAPTCHA: [invalid yaml\n' > "$rules/Server.yml"
    kill -HUP "${NODE_PIDS[0]}"
    deadline=$((SECONDS+10))
    while (( $(grep -Fc '[error] reload failed' "$logfile" || true) <= before )); do
        alive
        (( SECONDS < deadline )) || fail 'Invalid reload not rejected'
        sleep 0.2
    done
    expect block 1 203.0.113.190 0001000000000000 /reloaded
    cp "$RUN/valid-server.yml" "$rules/Server.yml"
    cp "$E2E/fixtures/rules/URL_BlockList.conf" "$rules/URL_BlockList.conf"
    kill -HUP "${NODE_PIDS[0]}"
    wait_decision pass 10 1 203.0.113.190 0001000000000000 /reloaded
    # A failed database reload retains the previous successful database reader.
    mv "$RUN/node1/data/GeoLite2-Country.mmdb" "$RUN/country.saved.mmdb"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" 'retaining the previous reader'
    expect challenge 1 8.8.8.8 0000000010000000
    mv "$RUN/country.saved.mmdb" "$RUN/node1/data/GeoLite2-Country.mmdb"
    kill -HUP "${NODE_PIDS[0]}"
    # SIGHUP opens the log files again: after a rotation the log goes on in new files.
    local events="$RUN/node1/log/default_site/events.log"
    mv "$logfile" "$logfile.1"
    mv "$events" "$events.1"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" '[info] reloading'
    expect block 1 203.0.113.191 0001000000000000 /blocked
    log_line "$events" '[info] decision ip=203.0.113.191 verdict=block reason=Lists:' ' uri=/blocked '
    if grep -Fq '203.0.113.191' "$events.1"; then fail 'An event went to the rotated file'; fi
    ASSERTIONS=$((ASSERTIONS+1))
    # SIGHUP also reads the log level again. At error a blocked request is not logged; at
    # debug a request that is let through is, with what every check did.
    printf 'log_level: error
' >> "$RUN/node1/torii.yml"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" '[notice] log level changed log_level=error'
    expect block 1 203.0.113.192 0001000000000000 /blocked
    sed -i 's/^log_level: error$/log_level: debug/' "$RUN/node1/torii.yml"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" '[notice] log level changed log_level=debug'
    expect pass 1 203.0.113.193 0001000000000000 /let-through
    log_line "$events" '[debug] decision ip=203.0.113.193 verdict=pass checks="Lists:continue ' ' uri=/let-through '
    if grep -Fq '203.0.113.192' "$events"; then fail 'A decision was logged at the error level'; fi
    ASSERTIONS=$((ASSERTIONS+1))
    sed -i '/^log_level: debug$/d' "$RUN/node1/torii.yml"
    kill -HUP "${NODE_PIDS[0]}"
    wait_log "$logfile" '[notice] log level changed log_level=info'
}
