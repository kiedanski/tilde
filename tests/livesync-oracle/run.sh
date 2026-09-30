#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "$0")/../.." && pwd)
target_dir=${CARGO_TARGET_DIR:-$repo_root/target}
bridge_rev=c3760beaa0851214da4860903445d7f6420ca025
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tilde-livesync-oracle.XXXXXX")
network="tilde-livesync-oracle-$$"
couch="tilde-livesync-couchdb-$$"
image="tilde-livesync-oracle:${bridge_rev:0:12}"
database=tilde_livesync_oracle

cleanup() {
    docker stop "$couch" >/dev/null 2>&1 || true
    docker network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$work_dir"
}
trap cleanup EXIT

if [[ -n "${LIVESYNC_BRIDGE_DIR:-}" ]]; then
    bridge_dir=$LIVESYNC_BRIDGE_DIR
else
    bridge_dir="$work_dir/bridge"
    git clone --quiet --depth 1 https://github.com/vrtmrz/livesync-bridge.git "$bridge_dir"
    if [[ $(git -C "$bridge_dir" rev-parse HEAD) != "$bridge_rev" ]]; then
        git -C "$bridge_dir" fetch --quiet --depth 1 origin "$bridge_rev"
        git -C "$bridge_dir" checkout --quiet "$bridge_rev"
    fi
fi
if [[ $(git -C "$bridge_dir" rev-parse HEAD) != "$bridge_rev" ]]; then
    echo "Bridge checkout must be at $bridge_rev" >&2
    exit 1
fi

docker build --quiet -t "$image" "$bridge_dir" >/dev/null
docker network create "$network" >/dev/null
mkdir -p "$work_dir/couch-data" "$work_dir/deno-data"
chmod 777 "$work_dir/couch-data" "$work_dir/deno-data"
docker run -d --rm --name "$couch" --network "$network" \
    -p 127.0.0.1::5984 -v "$work_dir/couch-data:/opt/couchdb/data" \
    -e COUCHDB_USER=admin -e COUCHDB_PASSWORD=testpassword \
    couchdb:3.5.0 >/dev/null

ready=false
for _ in {1..60}; do
    if docker exec "$couch" curl --fail --silent --user admin:testpassword \
        http://127.0.0.1:5984/_up >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 1
done
if [[ "$ready" != true ]]; then
    echo "Disposable CouchDB did not become ready" >&2
    exit 1
fi

docker exec "$couch" curl --fail --silent --show-error --user admin:testpassword \
    -H 'Content-Type: application/json' -X POST \
    http://127.0.0.1:5984/_cluster_setup \
    -d '{"action":"enable_single_node","username":"admin","password":"testpassword","bind_address":"0.0.0.0","port":5984}' >/dev/null
published=$(docker port "$couch" 5984/tcp)
export ORACLE_HOST_URL="http://$published"
export ORACLE_DATABASE="$database"
export ORACLE_EMPTY_CONFIG="$work_dir/nonexistent.toml"
export TILDE_NOTES__LIVESYNC__SERVER_URL="$ORACLE_HOST_URL"
export TILDE_NOTES__LIVESYNC__DATABASE="$database"
export TILDE_NOTES__LIVESYNC__USERNAME=admin
export TILDE_NOTES__LIVESYNC__PASSWORD=testpassword
docker_couch_url="http://$couch:5984"

cargo build --quiet -p tilde-server --manifest-path "$repo_root/Cargo.toml"
tilde_cmd() {
    "$target_dir/debug/tilde" --config "$ORACLE_EMPTY_CONFIG" notes live-sync "$@"
}
[[ $(tilde_cmd init-db) == created ]]
[[ $(tilde_cmd init-db) == exists ]]
run_oracle() {
    local mode=$1
    docker run --rm --network "$network" \
        -v "$repo_root/tests/livesync-oracle/oracle.ts:/app/oracle.ts:ro" \
        -v "$work_dir/deno-data:/deno-dir/location_data" \
        -e "ORACLE_COUCH_URL=$docker_couch_url" \
        -e "ORACLE_DATABASE=$database" \
        "$image" deno run -A /app/oracle.ts "$mode" >"$work_dir/$mode.log"
    python3 "$repo_root/tests/livesync-oracle/compare.py" \
        "$work_dir/$mode.log" "$target_dir/debug/tilde"
}

for mode in seed update delete; do
    run_oracle "$mode"
done

python3 - "$work_dir" <<'PY'
from pathlib import Path
import sys
root = Path(sys.argv[1])
(root / "rust-initial.md").write_text("# From Tilde\n\n" + "mixed 🦊 data\n" * 2000, encoding="utf-8")
(root / "rust-updated.md").write_text("# Tilde resolved\n\nObsidian edit\nTilde edit\n", encoding="utf-8")
PY

rust_path='rust/folder 🦊.md'
created_rev=$(tilde_cmd write "$rust_path" --file "$work_dir/rust-initial.md")
run_oracle verify-rust
run_oracle bridge-edit-rust
if tilde_cmd write "$rust_path" --file "$work_dir/rust-updated.md" --if-rev "$created_rev" \
    >"$work_dir/stale-write.log" 2>&1; then
    echo "Stale Rust write unexpectedly replaced the bridge edit" >&2
    exit 1
fi
current_rev=$(tilde_cmd stat "$rust_path")
updated_rev=$(tilde_cmd write "$rust_path" --file "$work_dir/rust-updated.md" --if-rev "$current_rev")
run_oracle verify-rust-updated
tilde_cmd delete "$rust_path" --if-rev "$updated_rev" >/dev/null
run_oracle verify-rust-deleted

cargo test --quiet -p tilde-mcp --test livesync_oracle --manifest-path "$repo_root/Cargo.toml" \
    -- --ignored --exact mcp_notes_share_the_livesync_vault
run_oracle verify-mcp
