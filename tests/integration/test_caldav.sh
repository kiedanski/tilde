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
cargo build --manifest-path "$PROJECT_ROOT/Cargo.toml" 2>&1 | tail -1

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

CAL_BASE="$BASE_URL/caldav/admin"

# ========================================
# CalDAV Discovery
# ========================================

log "--- CalDAV Discovery ---"

# PROPFIND on principal
CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PROPFIND "$CAL_BASE/" -H "Depth: 0" -H "Content-Type: application/xml")
if [ "$CODE" = "207" ]; then
    pass "PROPFIND /caldav/admin/ returns 207"
else
    fail "CalDAV PROPFIND" "expected 207, got $CODE"
fi

# ========================================
# Calendar CRUD
# ========================================

log "--- Calendar MKCALENDAR ---"

# Create calendar via MKCALENDAR
MKCAL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X MKCALENDAR "$CAL_BASE/test-cal/" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="utf-8"?>
<C:mkcalendar xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:set><D:prop>
    <D:displayname>Test Calendar</D:displayname>
  </D:prop></D:set>
</C:mkcalendar>')
if [ "$MKCAL_CODE" = "201" ]; then
    pass "MKCALENDAR creates calendar (201)"
else
    fail "MKCALENDAR" "expected 201, got $MKCAL_CODE"
fi

# List calendars via PROPFIND Depth:1
PROPFIND_RESP=$(curl -sf -u "$AUTH" -X PROPFIND "$CAL_BASE/" -H "Depth: 1" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="utf-8"?>
<D:propfind xmlns:D="DAV:"><D:prop><D:displayname/></D:prop></D:propfind>')
if echo "$PROPFIND_RESP" | grep -q "test-cal"; then
    pass "PROPFIND lists created calendar"
else
    fail "Calendar listing" "test-cal not in PROPFIND response"
fi

# ========================================
# Event CRUD
# ========================================

log "--- Event CRUD ---"

EVENT_UID="test-event-$(date +%s)@tilde"
EVENT_ICS="BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//tilde//test//EN
BEGIN:VEVENT
UID:$EVENT_UID
DTSTART:20260601T100000Z
DTEND:20260601T110000Z
SUMMARY:Test Event
END:VEVENT
END:VCALENDAR"

# PUT event
PUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PUT "$CAL_BASE/test-cal/$EVENT_UID.ics" \
    -H "Content-Type: text/calendar" \
    -d "$EVENT_ICS")
if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ]; then
    pass "PUT event returns $PUT_CODE"
else
    fail "PUT event" "expected 201/204, got $PUT_CODE"
fi

# GET event
GET_RESP=$(curl -sf -u "$AUTH" "$CAL_BASE/test-cal/$EVENT_UID.ics")
if echo "$GET_RESP" | grep -q "Test Event"; then
    pass "GET event returns iCalendar data"
else
    fail "GET event" "SUMMARY not found in response"
fi

# Update event (PUT with If-Match)
ETAG=$(curl -sI -u "$AUTH" "$CAL_BASE/test-cal/$EVENT_UID.ics" | grep -i etag | tr -d '\r' | awk '{print $2}')
UPDATED_ICS=$(echo "$EVENT_ICS" | sed 's/Test Event/Updated Event/')
UPDATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PUT "$CAL_BASE/test-cal/$EVENT_UID.ics" \
    -H "Content-Type: text/calendar" \
    -H "If-Match: $ETAG" \
    -d "$UPDATED_ICS")
if [ "$UPDATE_CODE" = "204" ] || [ "$UPDATE_CODE" = "201" ]; then
    pass "PUT update with If-Match returns $UPDATE_CODE"
else
    fail "PUT update" "expected 204, got $UPDATE_CODE"
fi

# ========================================
# CalDAV REPORT: calendar-multiget
# ========================================

log "--- CalDAV REPORT ---"

MULTIGET_RESP=$(curl -sf -u "$AUTH" \
    -X REPORT "$CAL_BASE/test-cal/" \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\" encoding=\"utf-8\"?>
<C:calendar-multiget xmlns:D=\"DAV:\" xmlns:C=\"urn:ietf:params:xml:ns:caldav\">
  <D:prop><D:getetag/><C:calendar-data/></D:prop>
  <D:href>/caldav/admin/test-cal/$EVENT_UID.ics</D:href>
</C:calendar-multiget>")
if echo "$MULTIGET_RESP" | grep -q "Updated Event"; then
    pass "calendar-multiget returns event data"
else
    fail "calendar-multiget" "event data not found in response"
fi

# ========================================
# DELETE event
# ========================================

DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X DELETE "$CAL_BASE/test-cal/$EVENT_UID.ics")
if [ "$DEL_CODE" = "204" ]; then
    pass "DELETE event returns 204"
else
    fail "DELETE event" "expected 204, got $DEL_CODE"
fi

# Verify gone
GONE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    "$CAL_BASE/test-cal/$EVENT_UID.ics")
if [ "$GONE_CODE" = "404" ]; then
    pass "Deleted event returns 404"
else
    fail "Deleted event check" "expected 404, got $GONE_CODE"
fi

# ========================================
# Summary
# ========================================

echo ""
echo "======================================"
echo "  CalDAV Results: $PASS passed, $FAIL failed (of $TESTS)"
echo "======================================"
[ "$FAIL" -eq 0 ] || exit 1
