# Newt Tunnel Integration + WebDAV Integration Tests

## Overview

Bundle the Pangolin Newt tunnel agent as a managed child process of tilde, configured
via `[tunnel]` in config.toml. Then build a Docker-based integration test suite that
exercises the WebDAV endpoints through a real WebDAV client, verifying the full
upload/download/delete lifecycle.

## Current State

- Tilde listens on `127.0.0.1:8080` (plain HTTP, `tls.mode = "upstream"`)
- Newt runs as a separate launchd agent (`com.pangolin.newt.plist`) with hardcoded
  `--id`, `--secret`, `--endpoint` flags
- No lifecycle coordination — Newt can start before tilde is ready, or tilde can
  crash without Newt knowing
- Newt logs go to flat files, invisible to tilde's tracing
- No integration tests exist — only 27 inline unit tests

## Desired End State

1. `tilde serve` optionally spawns Newt as a child process when `[tunnel]` is configured
2. Newt stdout/stderr are captured and emitted through tilde's `tracing` infrastructure
3. Newt is restarted automatically if it crashes, with backoff
4. A `tests/integration/` suite runs a Docker container that:
   - Starts tilde with a test config (no tunnel needed for local tests)
   - Uses `rclone` (or `cadaver`) as a WebDAV client
   - Tests: mkdir, upload, download, list, delete, overwrite
   - Tests: auth rejection (wrong password), unauthenticated access blocked
5. The separate `com.pangolin.newt.plist` launchd agent is no longer needed

## What We're NOT Doing

- Not shipping tilde via Docker (Docker is test-only infrastructure)
- Not rewriting Newt in Rust or embedding WireGuard
- Not adding Pangolin server management
- Not testing CalDAV/CardDAV in this phase (WebDAV files only)
- Not adding TLS termination (Pangolin still handles that)

---

## Phase 1: Add `[tunnel]` Config Section

### Overview
Add a `TunnelConfig` struct so Newt parameters live in config.toml instead of a
separate launchd plist.

### Changes Required

#### 1. `crates/tilde-core/src/config.rs`

Add `TunnelConfig` struct and field to `Config`:

```rust
#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct TunnelConfig {
    /// Enable tunnel (requires newt binary). Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the newt binary. Default: "newt" (found via PATH).
    #[serde(default = "default_newt_binary")]
    pub binary: String,
    /// Pangolin server endpoint (e.g., "https://pangolin.example.com")
    #[serde(default)]
    pub endpoint: String,
    /// Newt client ID
    #[serde(default)]
    pub id: String,
    /// Newt client secret (prefer secret_env for production)
    #[serde(default)]
    pub secret: String,
    /// Env var name containing the secret (preferred over inline secret)
    #[serde(default)]
    pub secret_env: String,
    /// Log level for newt (DEBUG, INFO, WARN, ERROR). Default: INFO.
    #[serde(default = "default_newt_log_level")]
    pub log_level: String,
    /// Restart delay after crash, in seconds. Default: 5.
    #[serde(default = "default_restart_delay")]
    pub restart_delay_seconds: u64,
    /// Max restart delay (exponential backoff cap), in seconds. Default: 300.
    #[serde(default = "default_max_restart_delay")]
    pub max_restart_delay_seconds: u64,
}

fn default_newt_binary() -> String { "newt".to_string() }
fn default_newt_log_level() -> String { "INFO".to_string() }
fn default_restart_delay() -> u64 { 5 }
fn default_max_restart_delay() -> u64 { 300 }
```

Add to `Config` struct:
```rust
#[serde(default)]
pub tunnel: TunnelConfig,
```

#### 2. Example config.toml addition

```toml
[tunnel]
enabled = true
endpoint = "https://pangolin.kiedanski.xyz"
id = "oafyczpoyqi0sq1"
secret_env = "TILDE_TUNNEL_SECRET"
# binary = "/usr/local/bin/newt"  # default: finds "newt" in PATH
# log_level = "INFO"
# restart_delay_seconds = 5
# max_restart_delay_seconds = 300
```

### Success Criteria

#### Automated Verification:
- [x] `cargo build` compiles cleanly
- [x] `cargo test` — existing tests still pass
- [x] Config loads with and without `[tunnel]` section (backward compatible)

---

## Phase 2: Newt Subprocess Manager with Diagnostics

### Overview
Add a module that spawns Newt as a child process after the TCP listener is bound,
captures its output into tilde's tracing, parses log lines for diagnostic signals,
tracks tunnel health state, and restarts with exponential backoff on crash.

### Diagnostic Log Patterns (from real Newt output)

Newt emits structured log lines with these known patterns:

| Pattern | Meaning | Action |
|---|---|---|
| `Tunnel connection to server established successfully!` | Connected | Set state → connected, reset backoff |
| `Started tcp proxy to localhost:8080` | Proxy ready | Confirm traffic can flow |
| `Periodic ping failed (N consecutive failures)` | Health degraded | Track consecutive failures, warn |
| `Ping attempt N failed:` | Single ping fail | Increment ping failure counter |
| `Error connecting to target: dial tcp 127.0.0.1:8080` | Tilde unreachable | Error — tilde might be down |
| `Failed to connect: failed to get token:` | Auth/DNS failure | Error — Pangolin server unreachable |
| `Websocket connected` | WS link up | Intermediate connected state |
| `Exiting...` | Clean shutdown | Expected during restart |

### Changes Required

#### 1. New file: `crates/tilde-server/src/tunnel.rs`

```rust
//! Newt tunnel subprocess manager with log-based diagnostics

use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use tokio::process::Command;
use tokio::io::{AsyncBufReadExt, BufReader};
use tilde_core::config::TunnelConfig;
use tracing::{info, warn, error};

/// Observable tunnel health state, shared with the health endpoint.
#[derive(Debug)]
pub struct TunnelStatus {
    /// Whether the tunnel subprocess is currently running
    pub running: AtomicBool,
    /// Whether we've seen a "Tunnel connection ... established" log line
    pub connected: AtomicBool,
    /// Consecutive ping failures (reset to 0 on success/reconnect)
    pub consecutive_ping_failures: AtomicU64,
    /// Total number of times Newt has been (re)started
    pub restart_count: AtomicU64,
    /// Timestamp of last successful connection (unix secs, 0 = never)
    pub last_connected_at: AtomicU64,
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            running: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            consecutive_ping_failures: AtomicU64::new(0),
            restart_count: AtomicU64::new(0),
            last_connected_at: AtomicU64::new(0),
        }
    }
}

impl TunnelStatus {
    /// Summary string for health endpoint
    pub fn summary(&self) -> &'static str {
        if !self.running.load(Ordering::Relaxed) {
            "stopped"
        } else if self.connected.load(Ordering::Relaxed) {
            let failures = self.consecutive_ping_failures.load(Ordering::Relaxed);
            if failures > 5 {
                "degraded"
            } else {
                "connected"
            }
        } else {
            "connecting"
        }
    }
}

pub type SharedTunnelStatus = Arc<TunnelStatus>;

/// Parse a Newt log line and update tunnel status accordingly.
fn classify_and_log(line: &str, status: &TunnelStatus) {
    // Determine the Newt log level prefix
    let (level, msg) = if let Some(rest) = line.strip_prefix("INFO: ") {
        ("info", rest)
    } else if let Some(rest) = line.strip_prefix("WARN: ") {
        ("warn", rest)
    } else if let Some(rest) = line.strip_prefix("ERROR: ") {
        ("error", rest)
    } else if let Some(rest) = line.strip_prefix("FATAL: ") {
        ("fatal", rest)
    } else {
        ("info", line)
    };

    // Strip the timestamp (format: "2026/04/24 10:11:54 ") to get the message
    let msg_body = if msg.len() > 20 && msg.as_bytes()[4] == b'/' {
        msg[20..].trim_start()
    } else {
        msg
    };

    // Classify and update state
    if msg_body.contains("Tunnel connection to server established") {
        status.connected.store(true, Ordering::Relaxed);
        status.consecutive_ping_failures.store(0, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        status.last_connected_at.store(now, Ordering::Relaxed);
        info!(target: "newt", "Tunnel connected");
    } else if msg_body.contains("Periodic ping failed") {
        // Extract consecutive failure count if present
        if let Some(start) = msg_body.find('(') {
            if let Some(end) = msg_body.find(" consecutive") {
                if let Ok(n) = msg_body[start + 1..end].parse::<u64>() {
                    status.consecutive_ping_failures.store(n, Ordering::Relaxed);
                }
            }
        }
        warn!(target: "newt", consecutive_failures = status.consecutive_ping_failures.load(Ordering::Relaxed), "Ping check failing");
    } else if msg_body.contains("Error connecting to target") {
        status.connected.store(false, Ordering::Relaxed);
        error!(target: "newt", "{}", msg_body);
    } else if msg_body.contains("Failed to connect") {
        status.connected.store(false, Ordering::Relaxed);
        error!(target: "newt", "{}", msg_body);
    } else if msg_body.contains("Exiting") {
        status.connected.store(false, Ordering::Relaxed);
        status.running.store(false, Ordering::Relaxed);
        info!(target: "newt", "Newt exiting");
    } else {
        // Pass through at the original level
        match level {
            "warn" => warn!(target: "newt", "{}", msg_body),
            "error" | "fatal" => error!(target: "newt", "{}", msg_body),
            _ => info!(target: "newt", "{}", msg_body),
        }
    }
}

/// Spawn and supervise the Newt tunnel process.
/// Returns the shared status handle (for health endpoint) and a JoinHandle.
pub fn spawn_tunnel_supervisor(
    config: TunnelConfig,
) -> (SharedTunnelStatus, tokio::task::JoinHandle<()>) {
    let status = Arc::new(TunnelStatus::default());
    let status_clone = status.clone();

    let handle = tokio::spawn(async move {
        let mut delay = config.restart_delay_seconds;
        let max_delay = config.max_restart_delay_seconds;

        // Resolve secret
        let secret = if !config.secret_env.is_empty() {
            std::env::var(&config.secret_env).unwrap_or_else(|_| {
                warn!(env_var = %config.secret_env,
                    "Tunnel secret env var not set, falling back to inline secret");
                config.secret.clone()
            })
        } else {
            config.secret.clone()
        };

        if secret.is_empty() {
            error!("Tunnel enabled but no secret configured \
                    (set tunnel.secret or tunnel.secret_env)");
            return;
        }
        if config.endpoint.is_empty() {
            error!("Tunnel enabled but no endpoint configured");
            return;
        }
        if config.id.is_empty() {
            error!("Tunnel enabled but no id configured");
            return;
        }

        loop {
            status_clone.restart_count.fetch_add(1, Ordering::Relaxed);
            info!(
                binary = %config.binary,
                endpoint = %config.endpoint,
                id = %config.id,
                restart_count = status_clone.restart_count.load(Ordering::Relaxed),
                "Starting tunnel (newt)..."
            );

            let result = Command::new(&config.binary)
                .arg("--id")
                .arg(&config.id)
                .arg("--secret")
                .arg(&secret)
                .arg("--endpoint")
                .arg(&config.endpoint)
                .arg("--log-level")
                .arg(&config.log_level)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match result {
                Ok(mut child) => {
                    status_clone.running.store(true, Ordering::Relaxed);
                    // Reset backoff on successful spawn
                    delay = config.restart_delay_seconds;

                    // Pipe stdout — this is where Newt writes its structured logs
                    if let Some(stdout) = child.stdout.take() {
                        let st = status_clone.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stdout);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                classify_and_log(&line, &st);
                            }
                        });
                    }

                    // Pipe stderr (Newt rarely uses stderr, but capture it)
                    if let Some(stderr) = child.stderr.take() {
                        tokio::spawn(async move {
                            let reader = BufReader::new(stderr);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                warn!(target: "newt::stderr", "{}", line);
                            }
                        });
                    }

                    // Wait for exit
                    match child.wait().await {
                        Ok(status) => {
                            warn!(exit_code = ?status.code(), "Tunnel (newt) exited");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to wait on tunnel process");
                        }
                    }
                    status_clone.running.store(false, Ordering::Relaxed);
                    status_clone.connected.store(false, Ordering::Relaxed);
                }
                Err(e) => {
                    error!(error = %e, binary = %config.binary,
                        "Failed to spawn tunnel (newt)");
                }
            }

            // Exponential backoff restart
            warn!(delay_seconds = delay, "Restarting tunnel after delay...");
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            delay = (delay * 2).min(max_delay);
        }
    });

    (status, handle)
}
```

#### 2. `crates/tilde-server/src/lib.rs`

Add `pub mod tunnel;` declaration.

Add `tunnel_status: Option<tunnel::SharedTunnelStatus>` to `AppState`.

Update `health_handler` to include tunnel diagnostics:

```rust
// In health_handler, after the database check:
let tunnel = state.tunnel_status.as_ref().map(|ts| {
    serde_json::json!({
        "status": ts.summary(),
        "connected": ts.connected.load(std::sync::atomic::Ordering::Relaxed),
        "consecutive_ping_failures": ts.consecutive_ping_failures.load(std::sync::atomic::Ordering::Relaxed),
        "restart_count": ts.restart_count.load(std::sync::atomic::Ordering::Relaxed),
        "last_connected_at": ts.last_connected_at.load(std::sync::atomic::Ordering::Relaxed),
    })
});

// Add to the health JSON body:
// "tunnel": tunnel,
```

#### 3. `crates/tilde-server/src/commands.rs`

Clone tunnel config early (before `config` moves into `AppState`):

```rust
// Near line 403, alongside state_config_tls:
let tunnel_config = config.tunnel.clone();
```

After the TCP listener is bound (after line 689):

```rust
// Start tunnel (newt) subprocess if configured
let tunnel_status = if tunnel_config.enabled {
    info!("Tunnel configured — starting newt subprocess");
    let (status, _handle) = tunnel::spawn_tunnel_supervisor(tunnel_config);
    Some(status)
} else {
    None
};
```

Pass `tunnel_status` into `AppState` construction.

### Success Criteria

#### Automated Verification:
- [x] `cargo build` compiles cleanly
- [x] `cargo test` passes
- [x] With `[tunnel] enabled = false` or omitted: no newt process spawned, `/health` has no tunnel field
- [x] With `[tunnel] enabled = true` + valid config: newt starts, logs appear in tilde output
- [x] `/health` returns tunnel status JSON when tunnel is enabled

#### Manual Verification:
- [x] Run tilde with `[tunnel]` configured, confirm newt starts
- [x] Kill newt process manually, confirm it restarts with backoff
- [x] Observe tunnel status transitions: connecting → connected → degraded (if ping fails)
- [x] Verify phone can connect through `tilde.kiedanski.xyz`
- [x] Check `/health` endpoint shows `"tunnel": {"status": "connected", ...}`

---

## Phase 3: Integration Test Suite (rclone as real WebDAV client)

### Overview
Create an integration test using `rclone` — a production WebDAV client that performs
real discovery (OPTIONS, PROPFIND at root, capability negotiation) just like DAVx5,
Nextcloud desktop, or Obsidian would. This catches protocol-level bugs that raw curl
tests miss.

rclone is configurable entirely via environment variables — no interactive setup
needed. It speaks WebDAV natively with Basic Auth support.

### Why rclone, not curl

Real WebDAV clients do things curl doesn't:
- **Discovery**: PROPFIND on `/` and `/dav/files/` with `Depth: 0` and `Depth: 1`
- **Capability negotiation**: OPTIONS request to check supported methods
- **Content-Type handling**: Sets proper MIME types on uploads
- **ETag/If-Match**: Uses conditional requests for overwrites
- **Directory semantics**: Expects trailing slashes, proper `<multistatus>` XML
- **Chunked transfers**: For larger files
- **Error recovery**: Retries on transient failures

If our WebDAV works with rclone, it works with real clients.

### Changes Required

#### 1. New file: `tests/integration/test_webdav.sh`

```bash
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
    cat "$TEST_DIR/data"/*.log 2>/dev/null || true
    exit 1
fi
log "Server is up on port $PORT."

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
```

#### 2. Update production config

Add to `~/.config/tilde/.env`:
```
TILDE_TUNNEL_SECRET=6dk1yhbontoxtc11ws04f14or9q6wvj9osk4rx45xrido0nc
```

Add to `~/.config/tilde/config.toml`:
```toml
[tunnel]
enabled = true
endpoint = "https://pangolin.kiedanski.xyz"
id = "oafyczpoyqi0sq1"
secret_env = "TILDE_TUNNEL_SECRET"
binary = "/usr/local/bin/newt"
```

### What rclone exercises that curl doesn't

- **PROPFIND with Depth headers** for listing (tests XML multistatus response parsing)
- **OPTIONS pre-flight** for capability discovery
- **Content-Type negotiation** on uploads
- **Recursive operations** (sync, purge) that stress multi-request sequences
- **Binary file integrity** — catches encoding/transfer bugs
- **Multiple mount points** — tests `/dav/files` and `/dav/notes` independently
- **Server-side COPY/MOVE** — uses the actual WebDAV methods, not re-upload

### Success Criteria

#### Automated Verification:
- [x] `cargo build` compiles
- [x] `bash tests/integration/test_webdav.sh` — all tests pass
- [x] Auth rejection: no creds (401), wrong creds (401), rclone bad-pw remote fails
- [x] Full CRUD via rclone: mkdir, copy, list, download, copyto, moveto, overwrite, delete, purge
- [x] Binary file round-trip integrity (SHA-256 match)
- [x] Notes mount point works independently
- [x] Directory tree sync with subdirectories works

#### Manual Verification:
- [x] Run integration tests, see green output
- [x] Start tilde with tunnel, verify phone connects via `tilde.kiedanski.xyz`

---

## Phase 4: Clean Up Old Newt Launchd Agent

### Overview
Remove the standalone Newt launchd agent since tilde now manages it.

### Steps:
1. `launchctl unload ~/Library/LaunchAgents/com.pangolin.newt.plist`
2. Remove or archive the plist file
3. Verify tilde's managed Newt still works after reboot

### Success Criteria:
- [x] Only one Newt process running (child of tilde)
- [x] `launchctl list | grep newt` returns nothing
- [ ] Phone connects successfully after Mac reboot

---

## Testing Strategy

### Unit Tests:
- `TunnelConfig` default values (enabled=false, binary="newt")
- Config loads correctly with/without `[tunnel]` section
- `classify_and_log` parses known Newt log patterns correctly

### Integration Tests (Phase 3):
- **rclone as real WebDAV client** — does proper discovery, PROPFIND, OPTIONS
- Auth enforcement (curl for HTTP codes, rclone for client-level rejection)
- Full CRUD: mkdir, upload, download, copy, move, overwrite, delete, purge
- Binary file round-trip integrity (SHA-256)
- Multi-mount-point: `/dav/files` and `/dav/notes`
- Directory tree sync with subdirectories
- Prerequisite: `brew install rclone` (test script checks and exits early if missing)

### Manual Testing:
1. Start tilde with `[tunnel]` enabled
2. Check `tilde.kiedanski.xyz` responds from phone
3. Upload photo from phone, verify it appears in tilde
4. Kill newt subprocess, verify tilde restarts it
5. Check `/health` — tunnel status shows "connected" / "degraded" / "stopped"
6. Reboot Mac, verify everything comes back up

---

## Implementation Order

1. **Phase 1** — Config struct (~15 lines of Rust) — safe, no behavior change
2. **Phase 2** — tunnel.rs subprocess manager — test with real Newt
3. **Phase 3** — Integration test script — validates everything works
4. **Phase 4** — Remove old launchd agent — only after manual verification

Each phase is independently shippable. Phase 3 can be worked on in parallel with
Phase 1+2 since the test script doesn't depend on the tunnel feature.
