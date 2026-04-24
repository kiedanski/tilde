#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# --- Prerequisites ---
for cmd in rclone curl; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "FATAL: $cmd is required. Install it first."
        echo "  brew install $cmd"
        exit 1
    fi
done

# --- Config ---
PORT=$(( (RANDOM % 10000) + 30000 ))
ADMIN_PW="test-pw-$(date +%s)"
TEST_DIR=$(mktemp -d)
DATA_DIR="$TEST_DIR/data"
CONFIG_FILE="$TEST_DIR/config.toml"
RCLONE_CONF="$TEST_DIR/rclone.conf"
PID_FILE="$TEST_DIR/tilde.pid"
TILDE_BIN="$PROJECT_ROOT/target/debug/tilde"
BASE_URL="http://127.0.0.1:$PORT"
PASS=0
FAIL=0
TESTS=0

cleanup() {
    if [ -f "$PID_FILE" ]; then
        kill "$(cat "$PID_FILE")" 2>/dev/null || true
        wait "$(cat "$PID_FILE")" 2>/dev/null || true
    fi
    rm -rf "$TEST_DIR"
}
trap cleanup EXIT

# --- Helpers ---
log()    { echo "  [TEST] $*"; }
pass()   { PASS=$((PASS + 1)); TESTS=$((TESTS + 1)); log "PASS: $1"; }
fail()   { FAIL=$((FAIL + 1)); TESTS=$((TESTS + 1)); log "FAIL: $1 — $2"; }
rclone() { command rclone --config "$RCLONE_CONF" "$@"; }

# --- Build ---
log "Building tilde..."
cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 | tail -1

# --- Generate tilde config ---
mkdir -p "$DATA_DIR"
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

# --- Generate rclone config ---
OBSCURED_PW=$(command rclone obscure "$ADMIN_PW")
cat > "$RCLONE_CONF" <<EOF
[tilde]
type = webdav
url = http://127.0.0.1:$PORT/dav/files
vendor = other
user = admin
pass = $OBSCURED_PW

[tilde-notes]
type = webdav
url = http://127.0.0.1:$PORT/dav/notes
vendor = other
user = admin
pass = $OBSCURED_PW

[tilde-badpw]
type = webdav
url = http://127.0.0.1:$PORT/dav/files
vendor = other
user = admin
pass = $(command rclone obscure "wrong-password")
EOF

# --- Start server ---
log "Starting tilde on port $PORT..."
TILDE_ADMIN_PASSWORD="$ADMIN_PW" \
TILDE_DATA_DIR="$DATA_DIR" \
  "$TILDE_BIN" serve --config "$CONFIG_FILE" &
echo $! > "$PID_FILE"

# Wait for health
for i in $(seq 1 30); do
    if curl -sf "$BASE_URL/health" > /dev/null 2>&1; then break; fi
    sleep 0.5
done
if ! curl -sf "$BASE_URL/health" > /dev/null 2>&1; then
    echo "FATAL: tilde did not start within 15 seconds"
    exit 1
fi
log "Server is up on port $PORT."

# ========================================
# Nextcloud Discovery (what real clients do first)
# ========================================

log "--- Nextcloud Discovery Tests ---"

# status.php — clients check this first to confirm it's a Nextcloud-compatible server
STATUS_JSON=$(curl -sf "$BASE_URL/status.php")
if echo "$STATUS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['installed']==True; assert d['productname']=='tilde'" 2>/dev/null; then
    pass "GET /status.php returns valid Nextcloud status"
else
    fail "status.php" "unexpected response: $STATUS_JSON"
fi

# OCS capabilities — clients check supported features (chunking, etc.)
CAPS_JSON=$(curl -sf "$BASE_URL/ocs/v2.php/cloud/capabilities")
if echo "$CAPS_JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); assert d['ocs']['data']['capabilities']['dav']['chunking']=='1.0'" 2>/dev/null; then
    pass "GET /ocs/v2.php/cloud/capabilities returns DAV capabilities"
else
    fail "OCS capabilities" "unexpected response"
fi

# well-known CalDAV/CardDAV redirects — DAVx5 uses these
CALDAV_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/.well-known/caldav")
if [ "$CALDAV_CODE" = "301" ]; then
    pass "GET /.well-known/caldav returns 301 redirect"
else
    fail ".well-known/caldav" "expected 301, got $CALDAV_CODE"
fi

CARDDAV_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/.well-known/carddav")
if [ "$CARDDAV_CODE" = "301" ]; then
    pass "GET /.well-known/carddav returns 301 redirect"
else
    fail ".well-known/carddav" "expected 301, got $CARDDAV_CODE"
fi

# Root PROPFIND — DAVx5 does this for current-user-principal discovery
PROPFIND_RESP=$(curl -sf -X PROPFIND "$BASE_URL/" -H "Depth: 0" -H "Content-Type: application/xml")
if echo "$PROPFIND_RESP" | grep -q "current-user-principal"; then
    pass "PROPFIND / returns current-user-principal"
else
    fail "Root PROPFIND" "missing current-user-principal in response"
fi

# remote.php/dav redirect — Nextcloud desktop client uses this path
REMOTE_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/remote.php/dav/files/admin/")
if [ "$REMOTE_CODE" = "308" ]; then
    pass "GET /remote.php/dav/files/admin/ redirects (308)"
else
    fail "remote.php redirect" "expected 308, got $REMOTE_CODE"
fi

# ========================================
# Nextcloud Login Flow v2 (app password provisioning)
# ========================================

log "--- Login Flow v2 Tests ---"

# Initiate flow
FLOW_JSON=$(curl -sf -X POST "$BASE_URL/login/v2")
POLL_TOKEN=$(echo "$FLOW_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['poll']['token'])")
LOGIN_URL=$(echo "$FLOW_JSON" | python3 -c "import sys,json; print(json.load(sys.stdin)['login'])")

if [ -n "$POLL_TOKEN" ] && [ -n "$LOGIN_URL" ]; then
    pass "POST /login/v2 returns poll token and login URL"
else
    fail "Login Flow v2 initiate" "missing token or login URL"
fi

# Poll before auth — should return 404 (not yet authenticated)
POLL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$BASE_URL/login/v2/poll" \
    -d "token=$POLL_TOKEN")
if [ "$POLL_CODE" = "404" ]; then
    pass "Poll before auth returns 404"
else
    fail "Pre-auth poll" "expected 404, got $POLL_CODE"
fi

# Build local auth URL (login URL may use https:// due to tls.mode=upstream)
LOCAL_AUTH_URL="$BASE_URL/login/v2/auth?token=$POLL_TOKEN"

# Load the auth page — should return HTML with CSRF token
AUTH_PAGE=$(curl -sf "$LOCAL_AUTH_URL")
if echo "$AUTH_PAGE" | grep -q "csrf_token"; then
    pass "GET /login/v2/auth returns login page with CSRF"
else
    fail "Auth page" "missing csrf_token in HTML"
fi

# Extract CSRF token from the hidden form field
CSRF_TOKEN=$(echo "$AUTH_PAGE" | python3 -c "
import sys, re
html = sys.stdin.read()
m = re.search(r'name=\"csrf_token\"[^>]*value=\"([^\"]+)\"', html)
print(m.group(1) if m else '')
")

# Submit credentials
AUTH_SUBMIT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$LOCAL_AUTH_URL" \
    -d "password=$ADMIN_PW&csrf_token=$CSRF_TOKEN&token=$POLL_TOKEN")
if [ "$AUTH_SUBMIT_CODE" = "200" ]; then
    pass "POST /login/v2/auth with correct password succeeds"
else
    fail "Auth submit" "expected 200, got $AUTH_SUBMIT_CODE"
fi

# Poll after auth — should return app password
POLL_RESP=$(curl -sf -X POST "$BASE_URL/login/v2/poll" -d "token=$POLL_TOKEN")
APP_PASSWORD=$(echo "$POLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('appPassword',''))" 2>/dev/null)
LOGIN_NAME=$(echo "$POLL_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('loginName',''))" 2>/dev/null)

if [ -n "$APP_PASSWORD" ] && [ "$LOGIN_NAME" = "admin" ]; then
    pass "Poll after auth returns appPassword and loginName=admin"
else
    fail "Post-auth poll" "missing appPassword or wrong loginName: $POLL_RESP"
fi

# Use the app password for WebDAV access
APP_AUTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -u "admin:$APP_PASSWORD" -X PROPFIND "$BASE_URL/dav/files/" -H "Depth: 0")
if [ "$APP_AUTH_CODE" = "207" ]; then
    pass "App password authenticates WebDAV PROPFIND (207)"
else
    fail "App password WebDAV" "expected 207, got $APP_AUTH_CODE"
fi

# Wrong password on Login Flow — should return error page
AUTH_WRONG_CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST "$LOCAL_AUTH_URL" \
    -d "password=wrong&csrf_token=$CSRF_TOKEN&token=$POLL_TOKEN")
# Flow is already consumed, so expect 200 with error or 404
if [ "$AUTH_WRONG_CODE" = "200" ] || [ "$AUTH_WRONG_CODE" = "404" ]; then
    pass "Login Flow rejects consumed/wrong attempts"
else
    fail "Login Flow wrong password" "unexpected code $AUTH_WRONG_CODE"
fi

# ========================================
# Auth Tests (curl — rclone hides HTTP codes)
# ========================================

log "--- Auth Tests ---"

# 1. No credentials → 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/dav/files/")
if [ "$HTTP_CODE" = "401" ]; then
    pass "Unauthenticated request returns 401"
else
    fail "Unauthenticated request" "expected 401, got $HTTP_CODE"
fi

# 2. Wrong password → 401
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
    -H "Authorization: Basic $(echo -n 'admin:wrong' | base64)" \
    "$BASE_URL/dav/files/")
if [ "$HTTP_CODE" = "401" ]; then
    pass "Wrong password returns 401"
else
    fail "Wrong password" "expected 401, got $HTTP_CODE"
fi

# 3. rclone with bad password fails
if rclone lsf tilde-badpw: 2>/dev/null; then
    fail "rclone bad password" "should have failed but succeeded"
else
    pass "rclone rejects bad credentials"
fi

# ========================================
# rclone WebDAV Discovery & Listing
# ========================================

log "--- Discovery Tests ---"

# 4. rclone can list root (PROPFIND discovery)
if rclone lsf tilde: 2>/dev/null; then
    pass "rclone lists root via PROPFIND"
else
    fail "rclone root listing" "PROPFIND discovery failed"
fi

# 5. rclone about (quota/capabilities check)
if rclone about tilde: 2>/dev/null; then
    pass "rclone about (capabilities)"
else
    # Some servers don't support this — soft fail
    log "SKIP: rclone about not supported (non-fatal)"
fi

# ========================================
# rclone File Operations (real WebDAV client)
# ========================================

log "--- File CRUD Tests ---"

# 6. mkdir via rclone
if rclone mkdir tilde:test-rclone 2>/dev/null; then
    pass "rclone mkdir creates directory"
else
    fail "rclone mkdir" "failed to create directory"
fi

# 7. Upload a file via rclone copy
echo "rclone test content" > "$TEST_DIR/testfile.txt"
if rclone copy "$TEST_DIR/testfile.txt" tilde:test-rclone/ 2>/dev/null; then
    pass "rclone copy uploads file"
else
    fail "rclone copy upload" "failed to upload file"
fi

# 8. List directory — verify file appears
LISTING=$(rclone lsf tilde:test-rclone/ 2>/dev/null)
if echo "$LISTING" | grep -q "testfile.txt"; then
    pass "rclone lsf shows uploaded file"
else
    fail "rclone lsf" "testfile.txt not in listing: $LISTING"
fi

# 9. Download and verify content
rclone copy tilde:test-rclone/testfile.txt "$TEST_DIR/download/" 2>/dev/null
if [ -f "$TEST_DIR/download/testfile.txt" ]; then
    CONTENT=$(cat "$TEST_DIR/download/testfile.txt")
    if [ "$CONTENT" = "rclone test content" ]; then
        pass "rclone download content matches"
    else
        fail "rclone download content" "expected 'rclone test content', got '$CONTENT'"
    fi
else
    fail "rclone download" "file not downloaded"
fi

# 10. Copy file (server-side COPY if supported, else re-upload)
if rclone copyto tilde:test-rclone/testfile.txt tilde:test-rclone/testfile-copy.txt 2>/dev/null; then
    pass "rclone copyto duplicates file"
else
    fail "rclone copyto" "failed to copy file"
fi

# 11. Move/rename file (MOVE method)
if rclone moveto tilde:test-rclone/testfile-copy.txt tilde:test-rclone/testfile-moved.txt 2>/dev/null; then
    pass "rclone moveto renames file"
else
    fail "rclone moveto" "failed to move file"
fi

# Verify the moved file exists and old one doesn't
LISTING2=$(rclone lsf tilde:test-rclone/ 2>/dev/null)
if echo "$LISTING2" | grep -q "testfile-moved.txt"; then
    pass "Moved file exists at new path"
else
    fail "Move destination" "testfile-moved.txt not found in listing"
fi
if echo "$LISTING2" | grep -q "testfile-copy.txt"; then
    fail "Move source cleanup" "testfile-copy.txt still exists after move"
else
    pass "Move source removed"
fi

# 12. Overwrite existing file
echo "updated by rclone" > "$TEST_DIR/testfile.txt"
if rclone copy "$TEST_DIR/testfile.txt" tilde:test-rclone/ 2>/dev/null; then
    pass "rclone overwrites existing file"
else
    fail "rclone overwrite" "failed to overwrite"
fi
rm -f "$TEST_DIR/download/testfile.txt"
rclone copy tilde:test-rclone/testfile.txt "$TEST_DIR/download/" 2>/dev/null
UPDATED=$(cat "$TEST_DIR/download/testfile.txt" 2>/dev/null)
if [ "$UPDATED" = "updated by rclone" ]; then
    pass "Overwritten content is correct"
else
    fail "Overwrite verification" "expected 'updated by rclone', got '$UPDATED'"
fi

# 13. Upload a binary file (catches content-type / encoding bugs)
dd if=/dev/urandom of="$TEST_DIR/binary.dat" bs=1024 count=64 2>/dev/null
ORIG_SHA=$(shasum -a 256 "$TEST_DIR/binary.dat" | cut -d' ' -f1)
if rclone copy "$TEST_DIR/binary.dat" tilde:test-rclone/ 2>/dev/null; then
    pass "rclone uploads binary file"
else
    fail "rclone binary upload" "failed"
fi
rclone copy tilde:test-rclone/binary.dat "$TEST_DIR/download/" 2>/dev/null
DL_SHA=$(shasum -a 256 "$TEST_DIR/download/binary.dat" 2>/dev/null | cut -d' ' -f1)
if [ "$ORIG_SHA" = "$DL_SHA" ]; then
    pass "Binary file round-trip integrity (SHA-256 match)"
else
    fail "Binary integrity" "SHA mismatch: $ORIG_SHA vs $DL_SHA"
fi

# 14. Delete file
if rclone delete tilde:test-rclone/testfile.txt 2>/dev/null; then
    pass "rclone deletes file"
else
    fail "rclone delete file" "failed"
fi

# 15. Purge directory (recursive delete)
if rclone purge tilde:test-rclone 2>/dev/null; then
    pass "rclone purge removes directory recursively"
else
    fail "rclone purge" "failed to remove directory"
fi

# Verify directory is gone
if rclone lsf tilde:test-rclone/ 2>/dev/null; then
    fail "Directory still exists" "test-rclone/ should be gone after purge"
else
    pass "Directory confirmed deleted"
fi

# ========================================
# rclone Notes WebDAV (separate mount point)
# ========================================

log "--- Notes WebDAV Tests ---"

# 16. Upload a markdown note via the /dav/notes endpoint
echo "# Test Note" > "$TEST_DIR/test-note.md"
if rclone copy "$TEST_DIR/test-note.md" tilde-notes: 2>/dev/null; then
    pass "rclone uploads note to /dav/notes"
else
    fail "rclone notes upload" "failed"
fi

# 17. List notes
NOTES_LIST=$(rclone lsf tilde-notes: 2>/dev/null)
if echo "$NOTES_LIST" | grep -q "test-note.md"; then
    pass "Note appears in /dav/notes listing"
else
    fail "Notes listing" "test-note.md not found: $NOTES_LIST"
fi

# 18. Clean up
rclone delete tilde-notes:test-note.md 2>/dev/null || true

# ========================================
# rclone sync test (multi-file batch)
# ========================================

log "--- Sync Tests ---"

# 19. Create a local directory tree and sync it
mkdir -p "$TEST_DIR/sync-source/subdir"
echo "file1" > "$TEST_DIR/sync-source/a.txt"
echo "file2" > "$TEST_DIR/sync-source/b.txt"
echo "file3" > "$TEST_DIR/sync-source/subdir/c.txt"

if rclone sync "$TEST_DIR/sync-source/" tilde:sync-test/ 2>/dev/null; then
    pass "rclone sync uploads directory tree"
else
    fail "rclone sync" "failed to sync directory tree"
fi

# 20. Verify all files arrived
SYNC_LIST=$(rclone lsf -R tilde:sync-test/ 2>/dev/null)
EXPECTED_FILES=("a.txt" "b.txt" "subdir/c.txt")
ALL_FOUND=true
for f in "${EXPECTED_FILES[@]}"; do
    if ! echo "$SYNC_LIST" | grep -q "$f"; then
        ALL_FOUND=false
        fail "Sync verify" "missing $f"
    fi
done
if $ALL_FOUND; then
    pass "All synced files present (including subdirectory)"
fi

# 21. Cleanup
rclone purge tilde:sync-test/ 2>/dev/null || true

# ========================================
# Summary
# ========================================

echo ""
echo "======================================"
echo "  Results: $PASS passed, $FAIL failed (of $TESTS)"
echo "======================================"
[ "$FAIL" -eq 0 ] || exit 1
