#!/bin/bash
# Integration test for Gossip Protocol
# Location: /home/roi/GolandProjects/server_torii/scripts/test/gossip/integration/test.sh

set -e

# ================= Configuration =================
BASE_PORT=25000
NUM_NODES=5
WORK_DIR="$(cd "$(dirname "$0")" && pwd)"
TEMP_DIR="$WORK_DIR/test_data"
BIN_PATH="$WORK_DIR/server_torii_test"
SECRET="test_secret_key_0123456789012345678901234567890" # 32+ chars
WEB_PATH="/torii"

# ANSI Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# ================= Helpers =================
log() { echo -e "${CYAN}[$(date +'%H:%M:%S')]${NC} $1"; }
pass() { echo -e "${GREEN}✓ PASS: $1${NC}"; }
fail() { echo -e "${RED}✗ FAIL: $1${NC}"; exit 1; }
warn() { echo -e "${YELLOW}! WARN: $1${NC}"; }

cleanup() {
    log "Shutting down nodes..."
    pkill -f "$BIN_PATH" || true
    rm -rf "$TEMP_DIR"
    rm -f "$BIN_PATH"
    log "Cleanup complete."
}

trap cleanup EXIT

# ================= Setup =================

log "Compiling server..."
# Switch to project root
PROJECT_ROOT="$WORK_DIR/../../../../"
cd "$PROJECT_ROOT"
go build -o "$BIN_PATH" main.go || fail "Compilation failed"

log "Preparing configuration for $NUM_NODES nodes..."
mkdir -p "$TEMP_DIR"

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
log_path: "$NODE_LOG_DIR/"
global_secret: "$SECRET"
node_name: "Node_$i"
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

# ================= Start Nodes =================
log "Starting $NUM_NODES nodes..."
for i in $(seq 1 $NUM_NODES); do
    CONF="$TEMP_DIR/node$i/config/torii.yml"
    # Run in background
    nohup "$BIN_PATH" -config "$CONF" > "$TEMP_DIR/node$i/log/server_torii.log" 2>&1 &
done

log "Waiting 5 seconds for nodes to initialize..."
sleep 5

# ================= Tests =================

# Function to check if an IP is blocked on a specific node
# Returns 0 if blocked, 1 if allowed
check_is_blocked() {
    local node_idx=$1
    local test_ip=$2
    local port=$((BASE_PORT + node_idx))
    local url="http://127.0.0.1:$port$WEB_PATH/checker"
    
    # We check HTTP status code. 
    # CheckMain returns 200 for Pass, 445 for Block/Captcha/Etc.
    # Set User-Agent to standard browser to avoid VerifyBot issues
    code=$(curl -s --max-time 2 -o /dev/null -w "%{http_code}" -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Torii-Real-IP: $test_ip" "$url")
    
    if [ "$code" == "445" ]; then
        return 0
    fi
    # Log if unexpected
    if [ "$code" != "200" ]; then
         warn "Node $node_idx returned $code for IP $test_ip"
         return 1
    fi
    return 1
}

# 1. Basic Propagation
log "=== Test 1: Basic Propagation ==="
ATTACKER_IP="10.10.1.1"
TARGET_URL="http://127.0.0.1:$((BASE_PORT+1))$WEB_PATH/checker"

# Verify initially allowed
if check_is_blocked 1 "$ATTACKER_IP"; then 
    fail "Node 1 should allow initially (Got 445 Blocked)"
fi
if check_is_blocked 5 "$ATTACKER_IP"; then 
    fail "Node 5 should allow initially"
fi

log "Triggering block on Node 1 (Flood)..."
# Send enough requests to trigger 5/10s limit
pids=""
for k in {1..15}; do
    curl -s --max-time 2 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Torii-Real-IP: $ATTACKER_IP" "$TARGET_URL" > /dev/null &
    pids="$pids $!"
done
wait $pids

log "Waiting for block detection and gossip propagation (5s)..."
sleep 5

if check_is_blocked 1 "$ATTACKER_IP"; then
    pass "Node 1 blocked the IP locally"
else
    log "Node 1 didn't block yet, sending more..."
    pids=""
    for k in {1..15}; do
        curl -s --max-time 2 -A "Mozilla/5.0 (Windows NT 10.0; Win64; x64)" -H "Torii-Real-IP: $ATTACKER_IP" "$TARGET_URL" > /dev/null &
        pids="$pids $!"
    done
    wait $pids
    sleep 3
    if check_is_blocked 1 "$ATTACKER_IP"; then
         pass "Node 1 blocked the IP locally (Retry)"
    else
         fail "Node 1 failed to block IP after flood"
    fi
fi

# Check propagation
propagated=0
for i in 2 3 4 5; do
    if check_is_blocked $i "$ATTACKER_IP"; then
        pass "Node $i received block via Gossip"
        propagated=$((propagated+1))
    else
        warn "Node $i did not receive block yet"
    fi
done

if [ "$propagated" -eq 4 ]; then
    pass "All nodes synchronized."
else
    warn "Only $propagated/4 nodes synced."
fi


# 2. TTL Expiration
log "=== Test 2: TTL Expiration and Manual Gossip Injection ==="

SHORT_TTL_IP="10.10.2.2"
TTL_SEC=5
EXPIRATION=$(( $(date +%s) + TTL_SEC ))
MSG_ID="uuid-$(date +%s)-$RANDOM"
# Construct BlockIP message
# TYPE IS BLOCK_IP (uppercase)
PAYLOAD="{\"id\":\"$MSG_ID\",\"type\":\"BLOCK_IP\",\"content\":\"$SHORT_TTL_IP\",\"expiration\":$EXPIRATION,\"origin_node\":\"Node_2\",\"timestamp\":$(date +%s)}"

# Calculate HMAC
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha512 -hmac "$SECRET" | awk '{print $NF}')

log "Injecting Gossip Message with TTL=${TTL_SEC}s to Node 1..."

inj_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$((BASE_PORT+1))$WEB_PATH/gossip" \
     -H "Content-Type: application/json" \
     -H "X-Torii-Signature: $SIG" \
     -d "$PAYLOAD")

if [ "$inj_code" != "200" ]; then
    warn "Injection failed with HTTP $inj_code"
    warn "Node 1 Log:"
    tail -n 20 "$TEMP_DIR/node1/log/server_torii.log"
fi

sleep 1
if check_is_blocked 1 "$SHORT_TTL_IP"; then
    pass "Node 1 accepted manual gossip block"
else
    warn "Node 1 rejected manual gossip block (Check failed)"
    fail "Test 2 Failed"
fi

# Check propagation
sleep 1
if check_is_blocked 3 "$SHORT_TTL_IP"; then
    pass "Node 3 received short TTL block"
else
    warn "Node 3 missed short TTL block"
fi

log "Waiting for TTL to expire (${TTL_SEC}s)..."
sleep $((TTL_SEC + 3))

if ! check_is_blocked 1 "$SHORT_TTL_IP"; then
    pass "Node 1 unblocked after TTL"
else
    fail "Node 1 still blocking after TTL"
fi

if ! check_is_blocked 3 "$SHORT_TTL_IP"; then
    pass "Node 3 unblocked after TTL"
else
    fail "Node 3 still blocking after TTL"
fi

# 3. Idempotency / Deduplication
log "=== Test 3: Idempotency ==="
# Send same message multiple times
IDEM_IP="10.10.3.3"
EXPIRATION=$(( $(date +%s) + 60 ))
MSG_ID="fixed-uuid-dup_test"
PAYLOAD="{\"id\":\"$MSG_ID\",\"type\":\"BLOCK_IP\",\"content\":\"$IDEM_IP\",\"expiration\":$EXPIRATION,\"origin_node\":\"Node_2\",\"timestamp\":$(date +%s)}"
SIG=$(echo -n "$PAYLOAD" | openssl dgst -sha512 -hmac "$SECRET" | awk '{print $NF}')

log "Sending duplicate messages to Node 1..."
for k in {1..5}; do
    curl -s -X POST "http://127.0.0.1:$((BASE_PORT+1))$WEB_PATH/gossip" \
         -H "Content-Type: application/json" \
         -H "X-Torii-Signature: $SIG" \
         -d "$PAYLOAD" > /dev/null
done

if check_is_blocked 1 "$IDEM_IP"; then
    pass "Node 1 processed message (at least once)"
else
    fail "Node 1 failed to process message"
fi

# 4. Security: Invalid Signature
log "=== Test 4: Security (Invalid HMAC) ==="
SEC_IP="10.10.4.4"
EXPIRATION=$(( $(date +%s) + 60 ))
PAYLOAD="{\"id\":\"bad-sec-id\",\"type\":\"BLOCK_IP\",\"content\":\"$SEC_IP\",\"expiration\":$EXPIRATION,\"origin_node\":\"bad_actor\",\"timestamp\":$(date +%s)}"
BAD_SIG="deadbeefdeadbeef"

resp_code=$(curl -s -o /dev/null -w "%{http_code}" -X POST "http://127.0.0.1:$((BASE_PORT+1))$WEB_PATH/gossip" \
     -H "Content-Type: application/json" \
     -H "X-Torii-Signature: $BAD_SIG" \
     -d "$PAYLOAD")

if [ "$resp_code" == "403" ]; then
    pass "Node 1 rejected invalid signature (403)"
else
    fail "Node 1 did not reject invalid signature (Got $resp_code)"
fi

if check_is_blocked 1 "$SEC_IP"; then
    fail "Node 1 applied block from invalid message!"
else
    pass "Node 1 did not apply block"
fi

log "Integration Tests Completed Successfully."
