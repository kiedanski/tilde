#!/usr/bin/env bash
# Full deploy rehearsal: populated pre-009 instance -> upgrade -> exercise everything.
set -uo pipefail
# Dress rehearsal for upgrading a populated pre-009 tilde deployment.
# Builds a realistic 4-month-old instance, upgrades it with the current binary,
# and exercises migration, merge, streaming, revocation and data integrity.
#
#   cargo build --release --no-default-features && ./scripts/rehearse-upgrade.sh
SP="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$SP/.." && pwd)"
TILDE=$REPO/target/release/tilde
RUN=${TMPDIR:-/tmp}/tilde-rehearsal
DATA=$RUN/data
CFG=$RUN/config.toml
PORT=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
URL="http://127.0.0.1:$PORT"

pass=0; fail=0
ok()   { echo "  ✓ $1"; pass=$((pass+1)); }
bad()  { echo "  ✗ $1"; fail=$((fail+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi; }

rm -rf "$RUN"; mkdir -p "$DATA"
cat > "$CFG" <<EOF
[server]
hostname = "localhost"
listen_addr = "127.0.0.1"
listen_port = $PORT

[tls]
mode = "upstream"

[photos]
enabled = true
EOF

echo "═══ 1. Build a 4-month-old pre-009 instance ═══"
python3 "$SP/rehearse-fixture.py" "$DATA" "$REPO/migrations" || exit 1

# a real video, so Range streaming is exercised against actual mp4 bytes
ffmpeg -v error -f lavfi -i testsrc=duration=8:size=640x360:rate=25 \
       -c:v libx264 -pix_fmt yuv420p "$DATA/photos/2026/05/clip.mp4" -y 2>/dev/null
VIDSIZE=$(stat -c%s "$DATA/photos/2026/05/clip.mp4")
echo "  video: $VIDSIZE bytes"

BEFORE_VER=$(sqlite3 "$DATA/tilde.db" "SELECT MAX(version) FROM migrations;")
check "starts at migration 008" "$BEFORE_VER" "8"
BEFORE_TREE=$(find "$DATA" -type f ! -name '*.db*' -exec sha256sum {} \; | sed "s|$DATA||" | sort | sha256sum | cut -c1-16)
BEFORE_FILES=$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files;")
BEFORE_RECS=$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM records;")

echo
echo "═══ 2. Upgrade (NOTE: status does NOT migrate; usage/reindex/serve do) ═══"
TILDE_DATA_DIR="$DATA" TILDE_HOSTNAME=localhost TILDE_TLS_MODE=upstream RUST_LOG=error \
  "$TILDE" --config "$CFG" status --json >/dev/null 2>&1
check "status alone does NOT migrate (documents the gotcha)" \
  "$(sqlite3 "$DATA/tilde.db" 'SELECT MAX(version) FROM migrations;')" "8"

T0=$(date +%s%N)
TILDE_DATA_DIR="$DATA" TILDE_HOSTNAME=localhost TILDE_TLS_MODE=upstream RUST_LOG=error \
  "$TILDE" --config "$CFG" usage > "$RUN/upgrade.log" 2>&1
T1=$(date +%s%N)
echo "  upgrade command took $(( (T1-T0)/1000000 ))ms"
AFTER_VER=$(sqlite3 "$DATA/tilde.db" "SELECT MAX(version) FROM migrations;")
check "migrated to 010" "$AFTER_VER" "10"
check "files rows preserved" "$(sqlite3 "$DATA/tilde.db" 'SELECT COUNT(*) FROM files;')" "$BEFORE_FILES"
check "records preserved"    "$(sqlite3 "$DATA/tilde.db" 'SELECT COUNT(*) FROM records;')" "$BEFORE_RECS"
check "stat-cache columns added" \
  "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM pragma_table_info('files') WHERE name IN ('mtime_nanos','inode');")" "2"
check "client_base_versions added" \
  "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='client_base_versions';")" "1"

echo
echo "═══ 3. Credentials (one per device) ═══"
mk_pw() { TILDE_DATA_DIR="$DATA" "$TILDE" --config "$CFG" auth app-password create --name "$1" --scope '*' 2>/dev/null | grep -o 'tilde_app_[A-Za-z0-9]*'; }
PHONE=$(mk_pw phone); LAPTOP=$(mk_pw laptop)
[ -n "$PHONE" ] && [ -n "$LAPTOP" ] && ok "created two device credentials" || bad "credential creation"

echo
echo "═══ 4. Warm the cache (tilde reindex) ═══"
T0=$(date +%s%N)
TILDE_DATA_DIR="$DATA" "$TILDE" --config "$CFG" reindex --type all 2>/dev/null | grep -E "Reindexing|Collecting" | sed 's/^/  /'
T1=$(date +%s%N)
echo "  reindex took $(( (T1-T0)/1000000 ))ms for $BEFORE_FILES files"
check "stale etags healed" \
  "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files WHERE etag='0000000000000000';")" "0"
check "stat cache warm" \
  "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files WHERE mtime_nanos IS NULL AND is_directory=0;")" "0"

echo
echo "═══ 4b. Prune removes rows whose files are gone ═══"
sqlite3 "$DATA/tilde.db" "INSERT INTO files (id,path,parent_path,name,size_bytes,content_type,etag,is_directory,created_at,modified_at,hlc) VALUES ('ghost','documents/deleted.txt','documents','deleted.txt',5,'text/plain','abc',0,'2026-05-01T00:00:00+00:00','2026-05-01T00:00:00+00:00','2026-05-01T00:00:00+00:00');" 2>/dev/null
PHOTOS_BEFORE=$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files WHERE path LIKE 'photos/%';")
TILDE_DATA_DIR="$DATA" "$TILDE" --config "$CFG" reindex --type all --prune >/dev/null 2>&1
check "orphan row pruned" "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files WHERE path='documents/deleted.txt';")" "0"
check "notes rows survived files prune" "$(sqlite3 "$DATA/tilde.db" "SELECT COUNT(*) FROM files WHERE path LIKE 'notes/%';")" "120"

echo
echo "═══ 5. Start server ═══"
TILDE_DATA_DIR="$DATA" RUST_LOG=error "$TILDE" --config "$CFG" serve > "$RUN/serve.log" 2>&1 &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
for i in $(seq 1 100); do curl -sf "$URL/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -sf "$URL/health" >/dev/null && ok "server healthy" || { bad "server never became healthy"; cat "$RUN/serve.log"; exit 1; }

P="-u admin:$PHONE"; L="-u admin:$LAPTOP"

echo
echo "═══ 6. Legacy note: stale etag heals, content correct ═══"
BODY=$(curl -s $P "$URL/dav/notes/note-000.md")
echo "$BODY" | grep -q "^# Note 0" && ok "legacy note served correctly" || bad "legacy note content"
ET=$(curl -sI $P "$URL/dav/notes/note-000.md" | grep -i '^etag:' | tr -d '\r' | cut -d' ' -f2)
[ "$ET" != '"0000000000000000"' ] && ok "etag no longer stale ($ET)" || bad "etag still stale"

echo
echo "═══ 7. Concurrent edit on a legacy note (the original bug) ═══"
curl -s $P "$URL/dav/notes/note-001.md" > "$RUN/phone_copy.md"
curl -s $L "$URL/dav/notes/note-001.md" > "$RUN/laptop_copy.md"
{ cat "$RUN/laptop_copy.md"; echo "LAPTOP APPENDED"; } > "$RUN/laptop_edit.md"
curl -s $L -X PUT --data-binary @"$RUN/laptop_edit.md" "$URL/dav/notes/note-001.md" >/dev/null
{ echo "PHONE PREPENDED"; cat "$RUN/phone_copy.md"; } > "$RUN/phone_edit.md"
curl -s $P -X PUT --data-binary @"$RUN/phone_edit.md" "$URL/dav/notes/note-001.md" >/dev/null
FINAL=$(curl -s $P "$URL/dav/notes/note-001.md")
echo "$FINAL" | grep -q "LAPTOP APPENDED" && ok "laptop edit survived" || bad "LAPTOP EDIT LOST"
echo "$FINAL" | grep -q "PHONE PREPENDED" && ok "phone edit survived"  || bad "PHONE EDIT LOST"

echo
echo "═══ 8. Agent write vs client write ═══"
curl -s $P "$URL/dav/notes/note-002.md" > "$RUN/agent_base.md"
{ cat "$RUN/agent_base.md"; echo "AGENT WROTE THIS"; } > "$DATA/notes/note-002.md"
{ echo "PHONE WROTE THIS"; cat "$RUN/agent_base.md"; } > "$RUN/phone2.md"
curl -s $P -X PUT --data-binary @"$RUN/phone2.md" "$URL/dav/notes/note-002.md" >/dev/null
A=$(curl -s $P "$URL/dav/notes/note-002.md")
echo "$A" | grep -q "AGENT WROTE THIS" && ok "agent write survived" || bad "AGENT WRITE LOST"
echo "$A" | grep -q "PHONE WROTE THIS" && ok "phone write survived" || bad "PHONE WRITE LOST"

echo
echo "═══ 9. Video streaming (real mp4, ExoPlayer pattern) ═══"
AR=$(curl -sI $P "$URL/dav/photos/2026/05/clip.mp4" | grep -i '^accept-ranges:' | tr -d '\r' | cut -d' ' -f2)
check "Accept-Ranges advertised" "$AR" "bytes"
CT=$(curl -sI $P "$URL/dav/photos/2026/05/clip.mp4" | grep -i '^content-type:' | tr -d '\r' | cut -d' ' -f2)
check "video content-type" "$CT" "video/mp4"
SEEK=$((VIDSIZE / 2))
CODE=$(curl -s -o "$RUN/seek.bin" -w '%{http_code}' $P -H "Range: bytes=$SEEK-" "$URL/dav/photos/2026/05/clip.mp4")
check "seek returns 206" "$CODE" "206"
check "seek sends only remainder" "$(stat -c%s "$RUN/seek.bin")" "$((VIDSIZE - SEEK))"
tail -c $((VIDSIZE - SEEK)) "$DATA/photos/2026/05/clip.mp4" > "$RUN/expect.bin"
cmp -s "$RUN/seek.bin" "$RUN/expect.bin" && ok "seeked bytes are correct" || bad "seeked bytes WRONG"
C416=$(curl -s -o /dev/null -w '%{http_code}' $P -H "Range: bytes=99999999-" "$URL/dav/photos/2026/05/clip.mp4")
check "out-of-range is 416" "$C416" "416"

echo
echo "═══ 10. Revoke actually revokes ═══"
TILDE_DATA_DIR="$DATA" "$TILDE" --config "$CFG" auth app-password revoke laptop >/dev/null 2>&1
RC=$(curl -s -o /dev/null -w '%{http_code}' $L "$URL/dav/notes/note-003.md")
check "revoked-by-name credential rejected" "$RC" "401"
RC2=$(curl -s -o /dev/null -w '%{http_code}' $P "$URL/dav/notes/note-003.md")
check "other credential still works" "$RC2" "200"
TILDE_DATA_DIR="$DATA" "$TILDE" --config "$CFG" auth app-password revoke nonexistent >/dev/null 2>&1 \
  && bad "revoking a nonexistent name reported success" || ok "revoking nonexistent name fails loudly"

echo
echo "═══ 11. No data was lost ═══"
UNTOUCHED=$(find "$DATA/files" "$DATA/notes" -type f ! -name 'note-00[123].md' -exec sha256sum {} \; | sed "s|$DATA||" | sort | sha256sum | cut -c1-16)
BEFORE_UNTOUCHED=$(echo "$BEFORE_TREE" | cut -c1-16)
NFILES=$(find "$DATA/notes" "$DATA/files" -type f | wc -l)
check "all 160 content files still present" "$NFILES" "160"
BLOBS=$(find "$DATA/blobs/by-id" -type f 2>/dev/null | wc -l)
echo "  archived versions in blob store: $BLOBS"
[ "$BLOBS" -gt 0 ] && ok "displaced versions were archived (recoverable)" || bad "nothing archived"

kill $SRV 2>/dev/null
echo
echo "═══════════════════════════════════════"
echo "  PASSED: $pass    FAILED: $fail"
echo "═══════════════════════════════════════"
[ "$fail" -eq 0 ]
