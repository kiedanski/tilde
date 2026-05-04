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

CARD_BASE="$BASE_URL/carddav/admin"

# ========================================
# CardDAV Discovery
# ========================================

log "--- CardDAV Discovery ---"

# PROPFIND on principal
CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PROPFIND "$CARD_BASE/" -H "Depth: 0" -H "Content-Type: application/xml")
if [ "$CODE" = "207" ]; then
    pass "PROPFIND /carddav/admin/ returns 207"
else
    fail "CardDAV PROPFIND" "expected 207, got $CODE"
fi

# ========================================
# Addressbook creation
# ========================================

log "--- Addressbook MKCOL ---"

MKCOL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X MKCOL "$CARD_BASE/test-ab/" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="utf-8"?>
<D:mkcol xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">
  <D:set><D:prop>
    <D:displayname>Test Addressbook</D:displayname>
    <D:resourcetype><D:collection/><CR:addressbook/></D:resourcetype>
  </D:prop></D:set>
</D:mkcol>')
if [ "$MKCOL_CODE" = "201" ]; then
    pass "MKCOL creates addressbook (201)"
else
    fail "MKCOL addressbook" "expected 201, got $MKCOL_CODE"
fi

# ========================================
# Contact CRUD
# ========================================

log "--- Contact CRUD ---"

CONTACT_UID="test-contact-$(date +%s)"
VCARD="BEGIN:VCARD
VERSION:3.0
UID:$CONTACT_UID
FN:John Doe
N:Doe;John;;;
EMAIL:john@example.com
TEL:+1-555-0123
END:VCARD"

# PUT contact
PUT_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PUT "$CARD_BASE/test-ab/$CONTACT_UID.vcf" \
    -H "Content-Type: text/vcard" \
    -d "$VCARD")
if [ "$PUT_CODE" = "201" ] || [ "$PUT_CODE" = "204" ]; then
    pass "PUT contact returns $PUT_CODE"
else
    fail "PUT contact" "expected 201/204, got $PUT_CODE"
fi

# GET contact
GET_RESP=$(curl -sf -u "$AUTH" "$CARD_BASE/test-ab/$CONTACT_UID.vcf")
if echo "$GET_RESP" | grep -q "John Doe"; then
    pass "GET contact returns vCard data"
else
    fail "GET contact" "FN not found in response"
fi

# Update contact
UPDATED_VCARD=$(echo "$VCARD" | sed 's/John Doe/Jane Doe/' | sed 's/Doe;John/Doe;Jane/')
UPDATE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X PUT "$CARD_BASE/test-ab/$CONTACT_UID.vcf" \
    -H "Content-Type: text/vcard" \
    -d "$UPDATED_VCARD")
if [ "$UPDATE_CODE" = "204" ] || [ "$UPDATE_CODE" = "201" ]; then
    pass "PUT update contact returns $UPDATE_CODE"
else
    fail "PUT update contact" "expected 204, got $UPDATE_CODE"
fi

# Verify update
GET_UPDATED=$(curl -sf -u "$AUTH" "$CARD_BASE/test-ab/$CONTACT_UID.vcf")
if echo "$GET_UPDATED" | grep -q "Jane Doe"; then
    pass "Updated contact has new name"
else
    fail "Contact update verify" "Jane Doe not found"
fi

# ========================================
# CardDAV REPORT: addressbook-multiget
# ========================================

log "--- CardDAV REPORT ---"

MULTIGET_RESP=$(curl -sf -u "$AUTH" \
    -X REPORT "$CARD_BASE/test-ab/" \
    -H "Content-Type: application/xml" \
    -d "<?xml version=\"1.0\" encoding=\"utf-8\"?>
<CR:addressbook-multiget xmlns:D=\"DAV:\" xmlns:CR=\"urn:ietf:params:xml:ns:carddav\">
  <D:prop><D:getetag/><CR:address-data/></D:prop>
  <D:href>/carddav/admin/test-ab/$CONTACT_UID.vcf</D:href>
</CR:addressbook-multiget>")
if echo "$MULTIGET_RESP" | grep -q "Jane Doe"; then
    pass "addressbook-multiget returns contact data"
else
    fail "addressbook-multiget" "contact data not found"
fi

# REPORT: addressbook-query with prop-filter
QUERY_RESP=$(curl -sf -u "$AUTH" \
    -X REPORT "$CARD_BASE/test-ab/" \
    -H "Content-Type: application/xml" \
    -d '<?xml version="1.0" encoding="utf-8"?>
<CR:addressbook-query xmlns:D="DAV:" xmlns:CR="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><CR:address-data/></D:prop>
  <CR:filter><CR:prop-filter name="EMAIL"/></CR:filter>
</CR:addressbook-query>')
if echo "$QUERY_RESP" | grep -q "Jane Doe"; then
    pass "addressbook-query with prop-filter returns matching contact"
else
    fail "addressbook-query" "contact not returned for EMAIL filter"
fi

# ========================================
# DELETE contact
# ========================================

DEL_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    -X DELETE "$CARD_BASE/test-ab/$CONTACT_UID.vcf")
if [ "$DEL_CODE" = "204" ]; then
    pass "DELETE contact returns 204"
else
    fail "DELETE contact" "expected 204, got $DEL_CODE"
fi

GONE_CODE=$(curl -s -o /dev/null -w "%{http_code}" -u "$AUTH" \
    "$CARD_BASE/test-ab/$CONTACT_UID.vcf")
if [ "$GONE_CODE" = "404" ]; then
    pass "Deleted contact returns 404"
else
    fail "Deleted contact check" "expected 404, got $GONE_CODE"
fi

# ========================================
# Summary
# ========================================

echo ""
echo "======================================"
echo "  CardDAV Results: $PASS passed, $FAIL failed (of $TESTS)"
echo "======================================"
[ "$FAIL" -eq 0 ] || exit 1
