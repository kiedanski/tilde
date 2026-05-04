#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Config ---
PORT=$(( (RANDOM % 10000) + 30000 ))
ADMIN_PW="test-pw-$(date +%s)"
TEST_DIR=$(mktemp -d)
DATA_DIR="$TEST_DIR/data"
CONFIG_FILE="$TEST_DIR/config.toml"
TILDE_BIN="$PROJECT_ROOT/target/debug/tilde"
BASE_URL="http://127.0.0.1:$PORT"
AUTH="admin:$ADMIN_PW"
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
[ -f "$TILDE_BIN" ] || cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" --no-default-features 2>&1 | tail -1

mkdir -p "$DATA_DIR/files"
cat > "$CONFIG_FILE" <<EOF
[server]
hostname = "localhost"
listen_addr = "127.0.0.1"
listen_port = $PORT
[tls]
mode = "upstream"
[auth]
session_ttl_hours = 1
[photos]
enabled = false
[logging]
level = "warn"
format = "pretty"
EOF

TILDE_ADMIN_PASSWORD="$ADMIN_PW" TILDE_DATA_DIR="$DATA_DIR" \
  "$TILDE_BIN" serve --config "$CONFIG_FILE" &
echo $! > "$TEST_DIR/tilde.pid"

for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
    echo "FATAL: tilde did not start"; exit 1
fi
log "Server is up on port $PORT."

# ========================================
# Path Traversal Tests
# ========================================

log "--- Path Traversal ---"

# GET with .. in path (--path-as-is prevents curl from resolving ..)
CODE=$(curl -s -o /dev/null -w "%{http_code}" --path-as-is -u "$AUTH" \
    "$BASE_URL/dav/files/../../../etc/passwd")
if [ "$CODE" = "400" ] || [ "$CODE" = "403" ] || [ "$CODE" = "404" ]; then
    pass "GET with .. blocked ($CODE)"
else
    fail "GET path traversal" "expected 400/403/404, got $CODE"
fi

# MOVE with traversal in Destination header
# First create a file to move
curl -sf -u "$AUTH" -X PUT "$BASE_URL/dav/files/traversal-test.txt" \
    -H "Content-Type: text/plain" -d "test" > /dev/null

CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X MOVE "$BASE_URL/dav/files/traversal-test.txt" \
    -H "Destination: $BASE_URL/dav/files/../../../etc/evil")
if [ "$CODE" = "400" ] || [ "$CODE" = "403" ]; then
    pass "MOVE with .. in Destination blocked ($CODE)"
else
    fail "MOVE Destination traversal" "expected 400/403, got $CODE"
fi

# COPY with traversal in Destination
CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X COPY "$BASE_URL/dav/files/traversal-test.txt" \
    -H "Destination: $BASE_URL/dav/files/../../../etc/evil")
if [ "$CODE" = "400" ] || [ "$CODE" = "403" ]; then
    pass "COPY with .. in Destination blocked ($CODE)"
else
    fail "COPY Destination traversal" "expected 400/403, got $CODE"
fi

# URL-encoded traversal: %2e%2e = ..
CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    "$BASE_URL/dav/files/%2e%2e/%2e%2e/etc/passwd")
if [ "$CODE" = "400" ] || [ "$CODE" = "403" ] || [ "$CODE" = "404" ]; then
    pass "GET with URL-encoded .. blocked ($CODE)"
else
    fail "URL-encoded traversal" "expected 400/403/404, got $CODE"
fi

# Clean up
curl -sf -u "$AUTH" -X DELETE "$BASE_URL/dav/files/traversal-test.txt" > /dev/null 2>&1 || true

# ========================================
# Symlink Escape Tests
# ========================================

log "--- Symlink Escape ---"

# Create a symlink inside the files directory pointing outside
ln -sf /etc "$DATA_DIR/files/escape-link" 2>/dev/null || true

if [ -L "$DATA_DIR/files/escape-link" ]; then
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
        "$BASE_URL/dav/files/escape-link/passwd")
    if [ "$CODE" = "403" ] || [ "$CODE" = "404" ]; then
        pass "GET via symlink escape blocked ($CODE)"
    else
        fail "Symlink escape GET" "expected 403/404, got $CODE"
    fi

    # PROPFIND on symlink
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
        -X PROPFIND "$BASE_URL/dav/files/escape-link/" -H "Depth: 0")
    if [ "$CODE" = "403" ] || [ "$CODE" = "404" ]; then
        pass "PROPFIND on symlink escape blocked ($CODE)"
    else
        fail "Symlink PROPFIND" "expected 403/404, got $CODE"
    fi

    # DELETE on symlink should not follow it
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
        -X DELETE "$BASE_URL/dav/files/escape-link")
    if [ "$CODE" = "403" ]; then
        pass "DELETE on symlink escape blocked ($CODE)"
    else
        fail "Symlink DELETE" "expected 403, got $CODE"
    fi

    rm -f "$DATA_DIR/files/escape-link"
else
    log "SKIP: could not create symlink (permission denied)"
fi

# ========================================
# Depth: infinity handling
# ========================================

log "--- Depth infinity ---"

INFINITY_RESP=$(curl -s -u "$AUTH" \
    -X PROPFIND "$BASE_URL/dav/files/" -H "Depth: infinity" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0"?><D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>')
INFINITY_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PROPFIND "$BASE_URL/dav/files/" -H "Depth: infinity")
if [ "$INFINITY_CODE" = "403" ]; then
    pass "Depth: infinity returns 403"
elif echo "$INFINITY_RESP" | grep -q "propfind-finite-depth"; then
    pass "Depth: infinity returns propfind-finite-depth error"
else
    fail "Depth infinity" "expected 403 with propfind-finite-depth, got $INFINITY_CODE"
fi

# ========================================
# Auth Boundary Tests
# ========================================

log "--- Auth Boundaries ---"

# No auth on DAV
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PROPFIND "$BASE_URL/dav/files/" -H "Depth: 0")
if [ "$CODE" = "401" ]; then
    pass "DAV without auth returns 401"
else
    fail "DAV no auth" "expected 401, got $CODE"
fi

# No auth on CalDAV
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PROPFIND "$BASE_URL/caldav/admin/" -H "Depth: 0")
if [ "$CODE" = "401" ]; then
    pass "CalDAV without auth returns 401"
else
    fail "CalDAV no auth" "expected 401, got $CODE"
fi

# No auth on CardDAV
CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -X PROPFIND "$BASE_URL/carddav/admin/" -H "Depth: 0")
if [ "$CODE" = "401" ]; then
    pass "CardDAV without auth returns 401"
else
    fail "CardDAV no auth" "expected 401, got $CODE"
fi

# Session auth — login, use token
LOGIN_RESP=$(curl -sf -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"$ADMIN_PW\"}")
TOKEN=$(echo "$LOGIN_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])" 2>/dev/null)

if [ -n "$TOKEN" ]; then
    pass "Login returns session token"

    # Use token for API
    VERIFY_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "Authorization: Bearer $TOKEN" \
        "$BASE_URL/api/auth/verify")
    if [ "$VERIFY_CODE" = "200" ]; then
        pass "Session token authenticates API request"
    else
        fail "Session token auth" "expected 200, got $VERIFY_CODE"
    fi
else
    fail "Login" "no token in response: $LOGIN_RESP"
fi

# Rate limiting — many wrong passwords should trigger 429
log "--- Rate Limiting ---"
GOT_429=false
for i in $(seq 1 10); do
    RL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/api/auth/login" \
        -H "Content-Type: application/json" \
        -d '{"password":"wrong"}')
    if [ "$RL_CODE" = "429" ]; then
        GOT_429=true
        break
    fi
done
if $GOT_429; then
    pass "Rate limiting triggers 429 after repeated failures"
else
    fail "Rate limiting" "never got 429 after 10 wrong attempts"
fi

# ========================================
# LOCK returns 405 (not 200)
# ========================================

log "--- LOCK method ---"

LOCK_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X LOCK "$BASE_URL/dav/files/")
if [ "$LOCK_CODE" = "405" ]; then
    pass "LOCK returns 405 (Class-1 server)"
else
    fail "LOCK method" "expected 405, got $LOCK_CODE"
fi

# ========================================
# Summary
# ========================================

echo ""
echo "======================================"
echo "  Security Results: $PASS passed, $FAIL failed (of $TESTS)"
echo "======================================"
[ "$FAIL" -eq 0 ] || exit 1
