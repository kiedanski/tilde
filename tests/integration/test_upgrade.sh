#!/usr/bin/env bash
# SIGUSR2 in-place upgrade: swap the binary the way `tilde update apply` does
# (write next to it, rename over), signal, and keep requesting /health
# throughout. The PID must survive, the new image must adopt the listening
# socket, and no request may fail. On Linux the swap also makes the running
# image "<path> (deleted)", which is the case a re-exec has to get right.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Config ---
PORT=$(( (RANDOM % 10000) + 30000 ))
TEST_DIR=$(mktemp -d)
DATA_DIR="$TEST_DIR/data"
CONFIG_FILE="$TEST_DIR/config.toml"
TILDE_BIN="$TEST_DIR/tilde"
BASE_URL="http://127.0.0.1:$PORT"
PASS=0
FAIL=0
TESTS=0

cleanup() {
    if [ -f "$TEST_DIR/tilde.pid" ]; then
        kill "$(cat "$TEST_DIR/tilde.pid")" 2>/dev/null || true
        wait "$(cat "$TEST_DIR/tilde.pid")" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

log()    { echo "  [TEST] $*"; }
pass()   { PASS=$((PASS + 1)); TESTS=$((TESTS + 1)); log "PASS: $1"; }
fail()   { FAIL=$((FAIL + 1)); TESTS=$((TESTS + 1)); log "FAIL: $1 — $2"; }

# --- Build & start ---
log "Building tilde..."
[ -f "$PROJECT_ROOT/target/debug/tilde" ] || cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --no-default-features 2>&1 | tail -1
# Run a private copy: the test replaces it on disk.
cp "$PROJECT_ROOT/target/debug/tilde" "$TILDE_BIN"

mkdir -p "$DATA_DIR/files"
cat > "$CONFIG_FILE" <<EOF
[server]
hostname = "localhost"
listen_addr = "127.0.0.1"
listen_port = $PORT
[tls]
mode = "upstream"
[photos]
enabled = false
[logging]
level = "info"
format = "pretty"
EOF

export TILDE_ADMIN_PASSWORD="test-pw-$(date +%s)" TILDE_DATA_DIR="$DATA_DIR"
"$TILDE_BIN" init --config "$CONFIG_FILE" >/dev/null 2>&1 || true
"$TILDE_BIN" serve --config "$CONFIG_FILE" >"$TEST_DIR/serve.log" 2>&1 &
PID=$!
echo "$PID" > "$TEST_DIR/tilde.pid"

for _ in $(seq 1 60); do
    if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
    echo "FATAL: tilde did not start"; cat "$TEST_DIR/serve.log"; exit 1
fi

# --- Upgrade under load ---
(
    end=$((SECONDS + 20))
    while [ $SECONDS -lt $end ]; do
        curl -s -o /dev/null -w "%{http_code}\n" --max-time 60 "$BASE_URL/health" || echo "ERR"
        sleep 0.02
    done
) > "$TEST_DIR/load.log" &
LOAD=$!

sleep 3
cp "$TILDE_BIN" "$TILDE_BIN.new" && mv "$TILDE_BIN.new" "$TILDE_BIN"
kill -USR2 "$PID"
wait "$LOAD"

if kill -0 "$PID" 2>/dev/null; then
    pass "process survives SIGUSR2 with the same PID"
else
    fail "process survives SIGUSR2 with the same PID" "PID $PID exited"
fi

if grep -aq "adopted the listening socket" "$TEST_DIR/serve.log"; then
    pass "new image adopts the inherited listening socket"
else
    fail "new image adopts the inherited listening socket" "no adoption logged"
fi

TOTAL=$(wc -l < "$TEST_DIR/load.log" | tr -d ' ')
BAD=$(grep -vc "^200$" "$TEST_DIR/load.log" || true)
if [ "$BAD" -eq 0 ] && [ "$TOTAL" -gt 0 ]; then
    pass "all $TOTAL requests during the upgrade succeed"
else
    fail "all requests during the upgrade succeed" "$BAD of $TOTAL failed"
fi

# --- SIGTERM still stops it, without a re-exec ---
STARTS=$(grep -ac "Starting tilde server" "$TEST_DIR/serve.log")
kill -TERM "$PID"
for _ in $(seq 1 40); do kill -0 "$PID" 2>/dev/null || break; sleep 0.5; done
if ! kill -0 "$PID" 2>/dev/null \
    && [ "$(grep -ac "Starting tilde server" "$TEST_DIR/serve.log")" -eq "$STARTS" ]; then
    pass "SIGTERM stops the server without re-executing"
    rm -f "$TEST_DIR/tilde.pid"
else
    fail "SIGTERM stops the server without re-executing" "still running or restarted"
fi

if [ "$FAIL" -ne 0 ]; then
    echo "--- server log"; cat "$TEST_DIR/serve.log"
fi
echo ""
echo "  Upgrade tests: $PASS/$TESTS passed"
[ "$FAIL" -eq 0 ] || exit 1
