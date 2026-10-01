#!/usr/bin/env bash
# Run on Linux/WSL with Go, curl, OpenSSL and uuidgen installed.
set -euo pipefail

BASE_PORT=25000
NUM_NODES=5
WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$WORK_DIR/../../.." && pwd)"
SECRET="test_secret_key_0123456789012345678901234567890"
WEB_PATH="/torii"
NODE_PIDS=()

log() { printf '[%s] %s\n' "$(date +'%H:%M:%S')" "$*"; }
pass() { log "PASS: $*"; }
fail() { log "FAIL: $*" >&2; exit 1; }

for tool in go curl openssl uuidgen awk sed grep tail mktemp; do
    command -v "$tool" >/dev/null || fail "Missing dependency: $tool"
done
TEMP_DIR="$(mktemp -d "$WORK_DIR/test_data.XXXXXX")"
BIN_PATH="$TEMP_DIR/server_torii_test"

cleanup() {
    local status=$? pid file
    trap - EXIT
    for pid in "${NODE_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${NODE_PIDS[@]}"; do wait "$pid" 2>/dev/null || true; done
    if (( status != 0 )); then
        for file in "$TEMP_DIR"/node*/log/{startup,server_torii}.log; do
            if [[ -f "$file" ]]; then
                log "Last lines of $file"
                tail -n 30 "$file" || true
            fi
        done
        log "Failure diagnostics retained at $TEMP_DIR"
    else
        # TEMP_DIR is the unique directory created by mktemp above.
        rm -rf -- "$TEMP_DIR"
    fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# Transport errors must never count as an allowed request.
request() {
    HTTP_CODE=""
    HTTP_BODY=""
    HTTP_ACTION=""
    if ! HTTP_CODE=$(curl --silent --show-error --noproxy '*' \
        --connect-timeout 1 --max-time 2 \
        -D "$TEMP_DIR/response.headers" -o "$TEMP_DIR/response.body" \
        -w '%{http_code}' "$@"); then
        return 1
    fi
    HTTP_BODY=$(cat "$TEMP_DIR/response.body")
    HTTP_ACTION=$(awk 'tolower($1) == "torii-action:" {gsub(/\r/, "", $2); print $2}' "$TEMP_DIR/response.headers")
}

checker() {
    local node=$1 ip=$2 features=${3:-0000000000000000}
    request -A 'Mozilla/5.0' -H "Torii-Real-IP: $ip" \
        -H "Torii-Feature-Control: $features" \
        "http://127.0.0.1:$((BASE_PORT + node))$WEB_PATH/checker"
}

read_state() {
    local node=$1 ip=$2
    checker "$node" "$ip" || fail "Node $node request failed for $ip"
    if [[ "$HTTP_CODE" == 200 && "$HTTP_BODY" == 'Server Torii Access Passed' ]]; then
        STATE=allowed
    elif [[ "$HTTP_CODE" == 445 && "$HTTP_ACTION" == 403 && "$HTTP_BODY" == 'Server Torii Auth Required' ]]; then
        STATE=blocked
    else
        fail "Node $node unexpected response: HTTP $HTTP_CODE action=$HTTP_ACTION body=$HTTP_BODY"
    fi
}

assert_state() {
    read_state "$1" "$2"
    [[ "$STATE" == "$3" ]] || fail "Node $1: $2 is $STATE, expected $3"
}

wait_nodes_state() {
    local ip=$1 expected=$2 timeout=$3 deadline node pending
    shift 3
    deadline=$((SECONDS + timeout))
    while true; do
        pending=0
        for node in "$@"; do
            read_state "$node" "$ip"
            [[ "$STATE" == "$expected" ]] || pending=$((pending + 1))
        done
        if (( pending == 0 )); then
            pass "Nodes $* report $ip as $expected"
            return
        fi
        (( SECONDS < deadline )) || fail "$pending nodes did not report $ip as $expected within ${timeout}s"
        sleep 0.2
    done
}

# Inputs are test-controlled IPs, UUIDs and node names.
make_payload() {
    local ip=$1 expiration=$2 id=$3 origin=$4 timestamp=$5 content
    printf -v content '{"rule_type":"IP","value":"%s","action":"BLOCK","expires_at":%s}' "$ip" "$expiration"
    content=$(printf '%s' "$content" | sed 's/"/\\"/g')
    printf -v PAYLOAD '{"id":"%s","type":"ACTION_RULE","content":"%s","origin_node":"%s","timestamp":%s,"seq":1}' \
        "$id" "$content" "$origin" "$timestamp"
    SIG=$(printf '%s' "$PAYLOAD" | openssl dgst -sha512 -hmac "$SECRET" | awk '{print $NF}')
}

post_gossip() {
    request -X POST "http://127.0.0.1:$((BASE_PORT + 1))$WEB_PATH/gossip" \
        -H 'Content-Type: application/json' -H "X-Torii-Signature: $SIG" \
        --data-binary "$PAYLOAD" || fail 'Gossip request failed'
}

assert_ack() {
    [[ "$HTTP_CODE" == 200 && "$HTTP_BODY" == ACK ]] || fail "Expected gossip ACK, got HTTP $HTTP_CODE: $HTTP_BODY"
}

log 'Compiling server...'
cd "$PROJECT_ROOT"
go build -o "$BIN_PATH" .

for i in $(seq 1 $NUM_NODES); do
    NODE_LOG_DIR="$TEMP_DIR/node$i/log"
    NODE_CONF_DIR="$TEMP_DIR/node$i/config"
    mkdir -p "$NODE_LOG_DIR" "$NODE_CONF_DIR"

    # Copy rules
    cp -r config_example/rules "$NODE_CONF_DIR/"
    cp -r config_example/error_page "$NODE_CONF_DIR/"

    # Overwrite Server.yml with minimal config for testing
    cat > "$NODE_CONF_DIR/rules/default/Server.yml" <<EOF
IPAllow:
  enabled: false
IPBlock:
  enabled: true
URLAllow:
  enabled: false
URLBlock:
  enabled: false
CAPTCHA:
  enabled: false
  secret_key: "0378b0f84c4310279918d71a5647ba5d"
  captcha_validate_time: 600
  captcha_challenge_session_timeout: 120
  hcaptcha_secret: ""
  CaptchaFailureLimit:
    - "300/300s"
  failure_block_duration: 1200
HTTPFlood:
  enabled: true
  HTTPFloodSpeedLimit:
    - "5/10s"
  HTTPFloodSameURILimit:
    - "50/10s"
  # Low failure limit to trigger BroadcastBlock
  HTTPFloodFailureLimit:
    - "5/300s" 
  failure_block_duration: 1200
VerifyBot:
  enabled: false
ExternalMigration:
  enabled: false
  redirect_url: "https://example.com/migration"
  secret_key: "0378b0f84c4310279918d71a5647ba5d"
  session_timeout: 1800
EOF

    # Generate torii.yml
    PORT=$((BASE_PORT + i))
    
    cat > "$NODE_CONF_DIR/torii.yml" <<EOF
port: "$PORT"
web_path: "$WEB_PATH"
error_page: "$NODE_CONF_DIR/error_page"
log_path: "$NODE_LOG_DIR"
global_secret: "$SECRET"
node_name: "Node_$i"
enable_gossip: true
connecting_host_headers: ["Torii-Real-Host"]
connecting_ip_headers: ["Torii-Real-IP"]
connecting_uri_headers: ["Torii-Original-URI"]
connecting_feature_control_headers: ["Torii-Feature-Control"]
sites:
  - host: "default_site"
    rule_path: "$NODE_CONF_DIR/rules/default"
peers:
EOF

    # Add peers (Full mesh)
    for j in $(seq 1 $NUM_NODES); do
        if [ "$i" -ne "$j" ]; then
            PEER_PORT=$((BASE_PORT + j))
            echo "  - name: \"Node_$j\"" >> "$NODE_CONF_DIR/torii.yml"
            echo "    address: \"http://127.0.0.1:$PEER_PORT\"" >> "$NODE_CONF_DIR/torii.yml"
            echo "    host: \"node-$j.local\"" >> "$NODE_CONF_DIR/torii.yml"
        fi
    done
done

log "Starting $NUM_NODES nodes..."
for ((i=1; i<=NUM_NODES; i++)); do
    "$BIN_PATH" -config "$TEMP_DIR/node$i/config/torii.yml" > "$TEMP_DIR/node$i/log/startup.log" 2>&1 &
    NODE_PIDS+=("$!")
done

deadline=$((SECONDS + 20))
for ((i=1; i<=NUM_NODES; i++)); do
    while true; do
        kill -0 "${NODE_PIDS[i-1]}" 2>/dev/null || fail "Node $i exited during startup"
        if checker "$i" '203.0.113.254' 2>/dev/null; then
            [[ "$HTTP_CODE" == 200 && "$HTTP_BODY" == 'Server Torii Access Passed' ]] || fail "Node $i readiness returned HTTP $HTTP_CODE: $HTTP_BODY"
            break
        fi
        (( SECONDS < deadline )) || fail 'Nodes did not become ready within 20s'
        sleep 0.2
    done
    [[ -s "$TEMP_DIR/node$i/log/server_torii.log" ]] || fail "Node $i main log is missing from its log directory"
done
pass 'Nodes ready; main logs exist at the configured paths'

log 'Test 1: Basic propagation'
ATTACKER_IP='203.0.113.1'
for ((i=1; i<=NUM_NODES; i++)); do assert_state "$i" "$ATTACKER_IP" allowed; done
# Only bit 5 (HTTPFlood) is enabled for triggering. Checks use zero bits.
for ((k=0; k<20; k++)); do
    checker 1 "$ATTACKER_IP" '0000010000000000' || fail 'Flood trigger request failed'
    if [[ "$HTTP_CODE" == 445 && "$HTTP_ACTION" == 403 && "$HTTP_BODY" == 'Server Torii Auth Required' ]]; then break; fi
    if [[ "$HTTP_CODE" == 200 && "$HTTP_BODY" == 'Server Torii Access Passed' ]]; then continue; fi
    [[ "$HTTP_CODE" == 445 && "$HTTP_ACTION" == 429 && "$HTTP_BODY" == 'Server Torii Auth Required' ]] || fail "Unexpected flood response: HTTP $HTTP_CODE action=$HTTP_ACTION body=$HTTP_BODY"
done
assert_state 1 "$ATTACKER_IP" blocked
wait_nodes_state "$ATTACKER_IP" blocked 15 1 2 3 4 5

log 'Test 2: TTL expiration'
TTL_IP='203.0.113.2'
EXPIRATION=$(( $(date +%s) + 15 ))
make_payload "$TTL_IP" "$EXPIRATION" "$(uuidgen -r)" Node_2 "$(date +%s)"
post_gossip
assert_ack
# Node_2 is the claimed origin, not a real producer of this injected rule.
# Its peers exclude itself, so it correctly rejects messages returning to it.
wait_nodes_state "$TTL_IP" blocked 10 1 3 4 5
remaining=$((EXPIRATION + 1 - $(date +%s)))
if (( remaining > 0 )); then sleep "$remaining"; fi
wait_nodes_state "$TTL_IP" allowed 3 1 3 4 5

log 'Test 3: Idempotency'
IDEM_IP='203.0.113.3'
make_payload "$IDEM_IP" "$(( $(date +%s) + 120 ))" "$(uuidgen -r)" Node_2 "$(date +%s)"
for ((k=0; k<5; k++)); do post_gossip; assert_ack; done
wait_nodes_state "$IDEM_IP" blocked 15 1 3 4 5
count=$(grep -Fc "[GOSSIP] Received ActionRule for IP:$IDEM_IP from " "$TEMP_DIR/node1/log/server_torii.log" || true)
[[ "$count" == 1 ]] || fail "Duplicate message processed $count times, expected exactly once"
pass 'Duplicate message applied exactly once'

log 'Tests 4-6: Invalid signature, unknown node and empty ID'
for case_name in signature unknown_node empty_id; do
    id=$(uuidgen -r)
    origin=Node_2
    expected_body=Forbidden
    case "$case_name" in
        signature) ip='203.0.113.4' ;;
        unknown_node) ip='203.0.113.5'; origin=UnknownAttacker; expected_body='Forbidden: Unknown OriginNode' ;;
        empty_id) ip='203.0.113.6'; id=''; expected_body='Forbidden: Empty Message ID' ;;
    esac
    make_payload "$ip" "$(( $(date +%s) + 120 ))" "$id" "$origin" "$(date +%s)"
    if [[ "$case_name" == signature ]]; then
        # Change one hex character while preserving valid SHA-512 length.
        if [[ "${SIG:0:1}" == 0 ]]; then SIG="1${SIG:1}"; else SIG="0${SIG:1}"; fi
    fi
    post_gossip
    [[ "$HTTP_CODE" == 403 && "$HTTP_BODY" == "$expected_body" ]] || fail "$case_name: expected 403 $expected_body, got $HTTP_CODE $HTTP_BODY"
    for ((i=1; i<=NUM_NODES; i++)); do assert_state "$i" "$ip" allowed; done
    pass "$case_name rejected without applying block"
done

log 'Test 7: Reject private IP'
make_payload '192.168.1.100' "$(( $(date +%s) + 120 ))" "$(uuidgen -r)" Node_2 "$(date +%s)"
post_gossip
assert_ack
for ((i=1; i<=NUM_NODES; i++)); do assert_state "$i" '192.168.1.100' allowed; done

log 'Test 8: Old timestamp'
make_payload '203.0.113.10' "$(( $(date +%s) + 120 ))" "$(uuidgen -r)" Node_2 "$(( $(date +%s) - 660 ))"
post_gossip
assert_ack
for ((i=1; i<=NUM_NODES; i++)); do assert_state "$i" '203.0.113.10' allowed; done

log 'Test 9: Oversized request'
dd if=/dev/zero of="$TEMP_DIR/large_payload.json" bs=1048576 count=11 2>/dev/null
request -X POST "http://127.0.0.1:$((BASE_PORT + 1))$WEB_PATH/gossip" \
    -H 'Content-Type: application/json' -H 'Expect: 100-continue' \
    --data-binary "@$TEMP_DIR/large_payload.json" || fail 'Oversized request failed without an HTTP response'
[[ "$HTTP_CODE" == 413 ]] || fail "Expected 413 for oversized request, got $HTTP_CODE"

pass 'End-to-end tests completed successfully'
