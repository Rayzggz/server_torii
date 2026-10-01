#!/usr/bin/env bash
# Sourced by test.sh; shared globals intentionally carry HTTP results and counts.
# shellcheck disable=SC2034
NUM_NODES=${NUM_NODES:-10}
BASE_PORT=${BASE_PORT:-25000}
KEEP_ARTIFACTS=${KEEP_ARTIFACTS:-0}
ZERO=0000000000000000
SECRET=e2e-only-global-secret-never-use-in-production
EXTERNAL_SECRET=e2e-only-external-secret-never-use-in-production
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36'
NODE_PIDS=()
ASSERTIONS=0
PASSED_GROUPS=0
REQUESTS=0
CURRENT=setup
log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
fail() {
    log "FAIL [$CURRENT]: $*" >&2
    if [[ -n ${RESPONSE:-} ]]; then log "Last request/response: $RESPONSE.*" >&2; fi
    exit 1
}
assert_eq() {
    ASSERTIONS=$((ASSERTIONS + 1))
    [[ "$1" == "$2" ]] || fail "${3:-assertion}: expected <$2>, got <$1>"
}
assert_contains() {
    ASSERTIONS=$((ASSERTIONS + 1))
    [[ "$1" == *"$2"* ]] || fail "${3:-assertion}: missing <$2> in <$1>"
}
alive() {
    local pid
    for pid in "${NODE_PIDS[@]}"; do kill -0 "$pid" 2>/dev/null || fail "Server PID $pid exited"; done
}
cleanup() {
    local status=$? pid deadline file
    trap - EXIT ERR INT TERM
    for pid in "${NODE_PIDS[@]}"; do kill -TERM "$pid" 2>/dev/null || true; done
    deadline=$((SECONDS + 5))
    for pid in "${NODE_PIDS[@]}"; do
        while kill -0 "$pid" 2>/dev/null && (( SECONDS < deadline )); do sleep 0.1; done
        if kill -0 "$pid" 2>/dev/null; then kill -KILL "$pid" 2>/dev/null || true; fi
        wait "$pid" 2>/dev/null || true
    done
    if (( status != 0 )); then
        log "FAILED: $PASSED_GROUPS completed groups, $ASSERTIONS assertions; exit $status"
        for file in "$RUN"/node*/log/{startup,server_torii}.log; do
            [[ -f "$file" ]] || continue
            log "$file"; tail -n 8 "$file" || true
        done
    fi
    if (( status != 0 )) || [[ "$KEEP_ARTIFACTS" == 1 ]]; then
        log "Artifacts: $RUN"
    else
        # RUN is exclusively the directory returned by mktemp in preflight.
        rm -rf -- "$RUN"
    fi
    exit "$status"
}
preflight() {
    local tool listeners port
    [[ $(uname -s) == Linux ]] || fail 'Run in Linux or Ubuntu WSL'
    if [[ ! "$NUM_NODES" =~ ^[1-9][0-9]?$ ]] || (( NUM_NODES < 3 || NUM_NODES > 32 )); then
        fail 'NUM_NODES must be 3..32 (default 10)'
    fi
    if [[ ! "$BASE_PORT" =~ ^[1-9][0-9]{3,4}$ ]] || (( BASE_PORT < 1024 || BASE_PORT + NUM_NODES > 65535 )); then
        fail 'Invalid BASE_PORT'
    fi
    for tool in go curl jq openssl dig ss awk sed grep head tail mktemp date base64 tr dd cp mv rm mkdir cat sleep uname; do
        command -v "$tool" >/dev/null || fail "Missing dependency: $tool (see tests/e2e/README.md)"
    done
    openssl version | grep -Eq '^OpenSSL [3-9]\.' || fail 'OpenSSL 3+ is required for PBKDF2'
    # Probe KDF support, including binary-safe hex passwords, before launching nodes.
    openssl kdf -keylen 32 -kdfopt digest:SHA512 -kdfopt hexpass:00000000 -kdfopt hexsalt:00 -kdfopt iter:1 PBKDF2 >/dev/null
    listeners=$(ss -H -lntu)
    for ((port=BASE_PORT+1; port<=BASE_PORT+NUM_NODES; port++)); do
        if awk -v p="$port" '$5 ~ (":" p "$") {found=1} END {exit !found}' <<< "$listeners"; then
            fail "TCP or UDP port $port already in use; choose BASE_PORT"
        fi
    done
    RUN=$(mktemp -d "${TMPDIR:-/tmp}/torii-e2e.XXXXXXXX")
    trap cleanup EXIT
    trap 'log "Unexpected failure at ${BASH_SOURCE[0]}:$LINENO: $BASH_COMMAND" >&2' ERR
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mkdir -p "$RUN/responses"
    ALLOWED=$(jq -r .allowed.body "$E2E/fixtures/responses.json")
    CHALLENGED=$(jq -r .challenged.body "$E2E/fixtures/responses.json")
    log "Artifacts: $RUN"
}
setup_cluster() {
    local i j node site cfg deadline
    log "Building Torii and preparing $NUM_NODES processes"
    (cd "$ROOT" && go build -o "$RUN/server_torii" .)
    for ((i=1; i<=NUM_NODES; i++)); do
        node="$RUN/node$i"
        mkdir -p "$node/log" "$node/data" "$node/rules"
        cp -R "$E2E/fixtures/pages" "$node/pages"
        # Last node intentionally has no database, testing the unknown-country policy.
        if (( i < NUM_NODES )); then cp "$ROOT/config_example/data/GeoLite2-Country.mmdb" "$node/data/"; fi
        for site in default exact wildcard failures unknown non200 uri expiry non200expiry uriexpiry; do
            cp -R "$E2E/fixtures/rules" "$node/rules/$site"
        done
        printf '/exact-site\n' >> "$node/rules/exact/URL_BlockList.conf"
        printf '/wildcard-site\n' >> "$node/rules/wildcard/URL_BlockList.conf"
        sed -i 's/20\/30s/2\/30s/; s/captcha_challenge_session_timeout: 120/captcha_challenge_session_timeout: 2/' "$node/rules/failures/Server.yml"
        sed -i 's/unknown_action: continue/unknown_action: block/' "$node/rules/unknown/Server.yml"
        sed -i 's/failure_block_duration: 300/failure_block_duration: 3/g' "$node/rules/expiry/Server.yml"
        for site in non200 uri non200expiry uriexpiry; do
            cfg="$node/rules/$site/Server.yml"
            sed -i "/^AdaptiveTrafficAnalyzer:/,/^  non_200_analysis:/s/enabled: false/enabled: true/; s/tag: disabled/tag: e2e-$site/" "$cfg"
            if [[ "$site" == non200* ]]; then
                sed -i '/^  non_200_analysis:/,/^  uri_analysis:/s/enabled: false/enabled: true/' "$cfg"
            else
                sed -i '/^  uri_analysis:/,$s/enabled: false/enabled: true/' "$cfg"
            fi
            if [[ "$site" == *expiry ]]; then sed -i 's/block_duration: 300/block_duration: 3/g' "$cfg"; fi
        done
        # Bash replacement keeps paths literal even when TMPDIR contains sed metacharacters.
        cfg=$(cat "$E2E/fixtures/torii.yml")
        cfg=${cfg//@PORT@/$((BASE_PORT+i))}; cfg=${cfg//@INDEX@/"$i"}; cfg=${cfg//@NODE@/"$node"}
        printf '%s\n' "$cfg" > "$node/torii.yml"
        for ((j=1; j<=NUM_NODES; j++)); do
            (( i != j )) || continue
            printf '  - name: "Node_%s"\n    address: "http://127.0.0.1:%s"\n    host: "node-%s.local"\n' "$j" "$((BASE_PORT+j))" "$j" >> "$node/torii.yml"
        done
        "$RUN/server_torii" -config "$node/torii.yml" > "$node/log/startup.log" 2>&1 &
        NODE_PIDS+=("$!")
    done
    printf '%s\n' "${NODE_PIDS[@]}" > "$RUN/pids"
    deadline=$((SECONDS+30))
    for ((i=1; i<=NUM_NODES; i++)); do
        until curl --silent --noproxy '*' --connect-timeout 1 --max-time 2 "http://127.0.0.1:$((BASE_PORT+i))/torii/health_check" > "$RUN/ready"; do
            alive
            (( SECONDS < deadline )) || fail "Node $i not ready within 30 seconds"
            sleep 0.2
        done
        assert_contains "$(cat "$RUN/ready")" "sliver=Node_$i" 'readiness identity'
    done
    alive
}
request() {
    local node=$1 endpoint=$2
    shift 2
    REQUESTS=$((REQUESTS+1))
    RESPONSE="$RUN/responses/$REQUESTS"
    printf '%q ' "node=$node" "$endpoint" "$@" > "$RESPONSE.request"
    printf '\n' >> "$RESPONSE.request"
    if ! HTTP_CODE=$(curl --silent --show-error --noproxy '*' --connect-timeout 2 --max-time 15 \
        -A "$UA" -D "$RESPONSE.headers" -o "$RESPONSE.body" -w '%{http_code}' \
        "http://127.0.0.1:$((BASE_PORT+node))$endpoint" "$@"); then
        fail "Request $REQUESTS to node $node $endpoint failed (transport)"
    fi
    HTTP_BODY=$(cat "$RESPONSE.body")
    HTTP_ACTION=$(header Torii-Action)
}
header() { awk -v key="$1:" 'tolower($1)==tolower(key) {$1=""; sub(/^ /, ""); sub(/\r$/, ""); print}' "$RESPONSE.headers"; }
check() {
    local node=$1 ip=$2 features=${3-$ZERO} uri=${4:-/neutral} host=${5:-default_site}
    shift "$(( $# < 5 ? $# : 5 ))"
    request "$node" /torii/checker -H "Torii-Real-IP: $ip" -H "Torii-Feature-Control: $features" \
        -H "Torii-Original-URI: $uri" -H "Torii-Real-Host: $host" "$@"
}
decision() {
    local expected=$1
    if [[ "$expected" == 200 ]]; then
        assert_eq "$HTTP_CODE" 200 'checker status'
        assert_eq "$HTTP_BODY" "$ALLOWED" 'checker body'
        assert_eq "$HTTP_ACTION" '' 'allowed action header'
    else
        assert_eq "$HTTP_CODE" 445 'checker status'
        assert_eq "$HTTP_BODY" "$CHALLENGED" 'checker body'
        assert_eq "$HTTP_ACTION" "$expected" 'checker action'
    fi
}
expect() { local expected=$1; shift; check "$@"; decision "$expected"; }
wait_decision() {
    local expected=$1 seconds=$2 deadline=$((SECONDS+$2))
    shift 2
    while true; do
        check "$@"
        case "$HTTP_CODE/$HTTP_ACTION" in
            200/) decision 200 ;;
            445/403|445/429|445/CAPTCHA|445/EXTERNAL) decision "$HTTP_ACTION" ;;
            *) fail "Unexpected checker response while polling: $HTTP_CODE/$HTTP_ACTION" ;;
        esac
        if [[ "$expected" == 200 && "$HTTP_CODE" == 200 ]] || [[ "$HTTP_CODE" == 445 && "$HTTP_ACTION" == "$expected" ]]; then
            return
        fi
        alive
        (( SECONDS < deadline )) || fail "Expected $expected within ${seconds}s; got $HTTP_CODE/$HTTP_ACTION"
        sleep 0.2
    done
}
cluster_decision() {
    local expected=$1 ip=$2 skip=${3:-0} node remaining deadline=$((SECONDS+180))
    for ((node=1; node<=NUM_NODES; node++)); do
        (( node != skip )) || continue
        remaining=$((deadline-SECONDS))
        (( remaining > 0 )) || fail 'Cluster convergence exceeded 180 seconds'
        wait_decision "$expected" "$remaining" "$node" "$ip"
    done
}
hmac() { printf '%s' "$1" | openssl dgst -sha512 -hmac "$2" | awk '{print $NF}'; }
uuid() { cat /proc/sys/kernel/random/uuid; }
wait_log() {
    local file=$1 pattern=$2 deadline=$((SECONDS+10))
    until grep -Fq "$pattern" "$file"; do
        alive
        (( SECONDS < deadline )) || fail "Missing log: $pattern"
        sleep 0.2
    done
    ASSERTIONS=$((ASSERTIONS+1))
}
