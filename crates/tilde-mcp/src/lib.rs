//! tilde-mcp: Model Context Protocol (MCP) Streamable HTTP endpoint
//!
//! Implements JSON-RPC 2.0 over HTTP with MCP protocol methods:
//! - initialize, tools/list, tools/call
//!
//! Bearer token auth with scope enforcement, rate limiting, and audit logging.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tracing::{info, warn};

/// MCP server state
pub struct McpState {
    pub db: Arc<Mutex<Connection>>,
    pub data_dir: PathBuf,
    /// Token name → list of recent request timestamps for rate limiting
    pub rate_limits: Mutex<HashMap<String, Vec<Instant>>>,
}

pub type SharedMcpState = Arc<McpState>;

// ─── JSON-RPC 2.0 types ─────────────────────────────────────────────────

#[derive(Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Serialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    fn success(id: Option<Value>, result: Value) -> Self {
        Self { jsonrpc: "2.0".into(), id, result: Some(result), error: None }
    }
    fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(), id,
            result: None,
            error: Some(JsonRpcError { code, message: message.into(), data: None }),
        }
    }
}

// ─── Tool definitions ────────────────────────────────────────────────────

#[derive(Serialize)]
struct ToolDef {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: Value,
}

fn all_tools() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "notes.search".into(),
            description: "Search notes by full-text query. Returns matching notes with path, title, and snippet.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "limit": {"type": "integer", "description": "Max results (default 20)"}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "notes.read".into(),
            description: "Read a note's content and metadata by path.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'my-note.md')"}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "notes.append".into(),
            description: "Append content to an existing note. Requires notes:write scope.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path"},
                    "content": {"type": "string", "description": "Content to append"}
                },
                "required": ["path", "content"]
            }),
        },
        ToolDef {
            name: "files.list".into(),
            description: "List files and directories at a path.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path (default: root)"},
                    "recursive": {"type": "boolean", "description": "List recursively (default false)"}
                }
            }),
        },
        ToolDef {
            name: "files.read".into(),
            description: "Read a text file's content (max 1MB).".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to files root"}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "files.search".into(),
            description: "Search file contents using full-text search.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Search query"},
                    "path": {"type": "string", "description": "Restrict to subdirectory"}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "trackers.log".into(),
            description: "Log a new entry to a collection/tracker. Requires trackers:write scope.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Collection name"},
                    "data": {"type": "object", "description": "Record data"}
                },
                "required": ["collection", "data"]
            }),
        },
        ToolDef {
            name: "trackers.query".into(),
            description: "Query records from a collection/tracker.".into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Collection name"},
                    "since": {"type": "string", "description": "Filter records since date (ISO 8601)"},
                    "limit": {"type": "integer", "description": "Max results (default 50)"}
                },
                "required": ["collection"]
            }),
        },
    ]
}

// ─── Scope checking ──────────────────────────────────────────────────────

fn tool_required_scope(tool_name: &str) -> &'static str {
    match tool_name {
        "notes.search" | "notes.read" => "notes:read",
        "notes.append" => "notes:write",
        "files.list" | "files.read" | "files.search" => "files:read",
        "trackers.query" => "trackers:read",
        "trackers.log" => "trackers:write",
        "calendar.list_events" => "calendar:read",
        "calendar.create_event" => "calendar:write",
        "contacts.search" => "contacts:read",
        "tasks.list" => "tasks:read",
        "tasks.add" => "tasks:write",
        "email.search" | "email.thread" | "email.recent" => "email:read",
        _ => "unknown",
    }
}

fn check_scope(scopes: &str, required: &str) -> bool {
    let scope_list: Vec<&str> = scopes.split(',').map(|s| s.trim()).collect();

    // Direct match
    if scope_list.contains(&required) {
        return true;
    }

    // *:read wildcard
    if required.ends_with(":read") && scope_list.contains(&"*:read") {
        return true;
    }

    // Wildcard * matches everything
    if scope_list.contains(&"*") {
        return true;
    }

    false
}

// ─── Rate limiting ───────────────────────────────────────────────────────

fn check_rate_limit(
    rate_limits: &Mutex<HashMap<String, Vec<Instant>>>,
    token_name: &str,
    max_per_minute: u32,
) -> bool {
    let mut limits = rate_limits.lock().unwrap();
    let now = Instant::now();
    let window = std::time::Duration::from_secs(60);

    let timestamps = limits.entry(token_name.to_string()).or_default();
    timestamps.retain(|t| now.duration_since(*t) < window);

    if timestamps.len() >= max_per_minute as usize {
        return false;
    }

    timestamps.push(now);
    true
}

// ─── Audit logging ──────────────────────────────────────────────────────

fn log_audit(
    conn: &Connection,
    token_name: &str,
    tool_name: &str,
    params: &Value,
    result_size: usize,
    duration_ms: u64,
    source_ip: &str,
) {
    let params_str = serde_json::to_string(params).unwrap_or_default();
    let truncated = if params_str.len() > 500 { &params_str[..500] } else { &params_str };
    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    let _ = conn.execute(
        "INSERT INTO mcp_audit_log (token_name, tool_name, params_truncated, result_size_bytes, duration_ms, source_ip, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![token_name, tool_name, truncated, result_size as i64, duration_ms as i64, source_ip, now],
    );
}

fn prune_old_audit_logs(conn: &Connection, retention_days: u32) {
    let cutoff = jiff::Zoned::now()
        .checked_sub(jiff::SignedDuration::from_hours(retention_days as i64 * 24))
        .map(|t| t.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string());

    if let Ok(cutoff_str) = cutoff {
        let _ = conn.execute(
            "DELETE FROM mcp_audit_log WHERE created_at < ?1",
            [&cutoff_str],
        );
    }
}

// ─── Tool implementations ────────────────────────────────────────────────

fn exec_notes_search(conn: &Connection, notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let query = params.get("query").and_then(|v| v.as_str())
        .ok_or("query parameter required")?;
    let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(20);

    // Rebuild FTS index
    let _ = conn.execute("DELETE FROM notes_fts", []);
    if notes_dir.exists() {
        index_notes_fts_recursive(conn, notes_dir, notes_dir);
    }

    let mut stmt = conn.prepare(
        "SELECT path, title, snippet(notes_fts, 2, '[', ']', '...', 30) FROM notes_fts WHERE notes_fts MATCH ?1 ORDER BY rank LIMIT ?2"
    ).map_err(|e| e.to_string())?;

    let results: Vec<Value> = stmt.query_map(rusqlite::params![query, limit], |row| {
        let path: String = row.get(0)?;
        let title: String = row.get(1)?;
        let snippet: String = row.get(2)?;
        // Get modified time from file
        let full_path = notes_dir.join(&path);
        let modified = full_path.metadata()
            .and_then(|m| m.modified())
            .ok()
            .map(|t| {
                let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                jiff::Timestamp::from_second(d.as_secs() as i64)
                    .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
                    .strftime("%Y-%m-%dT%H:%M:%SZ")
                    .to_string()
            })
            .unwrap_or_default();
        Ok(json!({
            "path": path,
            "title": title,
            "snippet": snippet,
            "modified": modified,
        }))
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();

    Ok(json!(results))
}

fn exec_notes_read(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params.get("path").and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let full_path = notes_dir.join(path);

    // Prevent path traversal
    if !full_path.starts_with(notes_dir) {
        return Err("path traversal not allowed".into());
    }

    let content = std::fs::read_to_string(&full_path)
        .map_err(|_| format!("note not found: {}", path))?;

    let title = content.lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").to_string())
        .unwrap_or_else(|| {
            full_path.file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });

    let modified = full_path.metadata()
        .and_then(|m| m.modified())
        .ok()
        .map(|t| {
            let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            jiff::Timestamp::from_second(d.as_secs() as i64)
                .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
                .strftime("%Y-%m-%dT%H:%M:%SZ")
                .to_string()
        })
        .unwrap_or_default();

    Ok(json!({
        "content": content,
        "metadata": {
            "title": title,
            "path": path,
            "modified": modified,
        }
    }))
}

fn exec_notes_append(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params.get("path").and_then(|v| v.as_str())
        .ok_or("path parameter required")?;
    let content = params.get("content").and_then(|v| v.as_str())
        .ok_or("content parameter required")?;

    let full_path = notes_dir.join(path);
    if !full_path.starts_with(notes_dir) {
        return Err("path traversal not allowed".into());
    }

    if !full_path.exists() {
        return Err(format!("note not found: {}", path));
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&full_path)
        .map_err(|e| e.to_string())?;

    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.write_all(content.as_bytes()).map_err(|e| e.to_string())?;

    Ok(json!({"success": true}))
}

fn exec_files_list(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let rel_path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let recursive = params.get("recursive").and_then(|v| v.as_bool()).unwrap_or(false);

    let target = if rel_path.is_empty() { files_dir.to_path_buf() } else { files_dir.join(rel_path) };
    if !target.starts_with(files_dir) {
        return Err("path traversal not allowed".into());
    }
    if !target.exists() || !target.is_dir() {
        return Err(format!("directory not found: {}", rel_path));
    }

    let mut entries = Vec::new();
    list_dir_entries(&target, files_dir, recursive, &mut entries, 0);

    Ok(json!(entries))
}

fn list_dir_entries(dir: &Path, base: &Path, recursive: bool, entries: &mut Vec<Value>, depth: usize) {
    if depth > 10 { return; } // prevent infinite recursion
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') { continue; }

            let rel = path.strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let is_dir = path.is_dir();
            let meta = path.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta.and_then(|m| m.modified().ok())
                .map(|t| {
                    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    jiff::Timestamp::from_second(d.as_secs() as i64)
                        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
                        .strftime("%Y-%m-%dT%H:%M:%SZ")
                        .to_string()
                })
                .unwrap_or_default();

            entries.push(json!({
                "name": name,
                "path": rel,
                "size": size,
                "modified": modified,
                "type": if is_dir { "directory" } else { "file" },
            }));

            if is_dir && recursive {
                list_dir_entries(&path, base, true, entries, depth + 1);
            }
        }
    }
}

fn exec_files_read(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params.get("path").and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let full_path = files_dir.join(path);
    if !full_path.starts_with(files_dir) {
        return Err("path traversal not allowed".into());
    }
    if !full_path.exists() {
        return Err(format!("file not found: {}", path));
    }
    if full_path.is_dir() {
        return Err("cannot read directory".into());
    }

    let meta = full_path.metadata().map_err(|e| e.to_string())?;
    if meta.len() > 1_048_576 {
        return Err("file too large (max 1MB)".into());
    }

    let content = std::fs::read_to_string(&full_path)
        .map_err(|_| "file is not valid UTF-8 text".to_string())?;

    Ok(json!({"content": content}))
}

fn exec_files_search(conn: &Connection, notes_dir: &Path, params: &Value) -> Result<Value, String> {
    // Reuse notes FTS for now — searches note content
    let query = params.get("query").and_then(|v| v.as_str())
        .ok_or("query parameter required")?;

    let _ = conn.execute("DELETE FROM notes_fts", []);
    if notes_dir.exists() {
        index_notes_fts_recursive(conn, notes_dir, notes_dir);
    }

    let mut stmt = conn.prepare(
        "SELECT path, snippet(notes_fts, 2, '[', ']', '...', 30) FROM notes_fts WHERE notes_fts MATCH ?1 ORDER BY rank LIMIT 20"
    ).map_err(|e| e.to_string())?;

    let results: Vec<Value> = stmt.query_map([query], |row| {
        Ok(json!({
            "path": row.get::<_, String>(0)?,
            "snippet": row.get::<_, String>(1)?,
        }))
    }).map_err(|e| e.to_string())?
    .filter_map(|r| r.ok())
    .collect();

    Ok(json!(results))
}

fn exec_trackers_log(conn: &Connection, params: &Value) -> Result<Value, String> {
    let collection_name = params.get("collection").and_then(|v| v.as_str())
        .ok_or("collection parameter required")?;
    let data = params.get("data")
        .ok_or("data parameter required")?;

    let (collection_id, schema_json): (String, String) = conn.query_row(
        "SELECT id, schema_json FROM collections WHERE name = ?1",
        [collection_name],
        |row| Ok((row.get(0)?, row.get(1)?)),
    ).map_err(|_| format!("collection '{}' not found", collection_name))?;

    // Basic schema validation
    if let Ok(schema) = serde_json::from_str::<Value>(&schema_json) {
        basic_validate(data, &schema)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let data_str = serde_json::to_string(data).map_err(|e| e.to_string())?;
    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    conn.execute(
        "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, collection_id, data_str, now, now, now],
    ).map_err(|e| e.to_string())?;

    Ok(json!({"id": id}))
}

fn exec_trackers_query(conn: &Connection, params: &Value) -> Result<Value, String> {
    let collection_name = params.get("collection").and_then(|v| v.as_str())
        .ok_or("collection parameter required")?;
    let since = params.get("since").and_then(|v| v.as_str());
    let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50);

    let (collection_id,): (String,) = conn.query_row(
        "SELECT id FROM collections WHERE name = ?1",
        [collection_name],
        |row| Ok((row.get(0)?,)),
    ).map_err(|_| format!("collection '{}' not found", collection_name))?;

    let results: Vec<Value> = if let Some(since_val) = since {
        let mut stmt = conn.prepare(
            "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC LIMIT ?3"
        ).map_err(|e| e.to_string())?;
        stmt.query_map(rusqlite::params![collection_id, since_val, limit], |row| {
            let data_str: String = row.get(1)?;
            let data: Value = serde_json::from_str(&data_str).unwrap_or(json!(null));
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "data": data,
                "timestamp": row.get::<_, String>(2)?,
            }))
        }).map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect()
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
        ).map_err(|e| e.to_string())?;
        stmt.query_map(rusqlite::params![collection_id, limit], |row| {
            let data_str: String = row.get(1)?;
            let data: Value = serde_json::from_str(&data_str).unwrap_or(json!(null));
            Ok(json!({
                "id": row.get::<_, String>(0)?,
                "data": data,
                "timestamp": row.get::<_, String>(2)?,
            }))
        }).map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect()
    };

    Ok(json!(results))
}

// ─── Helpers ─────────────────────────────────────────────────────────────

fn index_notes_fts_recursive(conn: &Connection, dir: &Path, base: &Path) {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            index_notes_fts_recursive(conn, &path, base);
        } else if path.extension().is_some_and(|e| e == "md") {
            let rel_path = path.strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let content = std::fs::read_to_string(&path).unwrap_or_default();
            let title = content.lines()
                .find(|l| l.starts_with("# "))
                .map(|l| l.trim_start_matches("# ").to_string())
                .unwrap_or_else(|| {
                    path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default()
                });
            let _ = conn.execute(
                "INSERT INTO notes_fts (path, title, content) VALUES (?1, ?2, ?3)",
                rusqlite::params![rel_path, title, content],
            );
        }
    }
}

fn basic_validate(data: &Value, schema: &Value) -> Result<(), String> {
    if let Some(required) = schema.get("required").and_then(|r| r.as_array())
        && let Some(obj) = data.as_object()
    {
        for req in required {
            if let Some(field) = req.as_str()
                && !obj.contains_key(field)
            {
                return Err(format!("missing required field: '{}'", field));
            }
        }
    }
    Ok(())
}

// ─── Main handler ────────────────────────────────────────────────────────

/// Handle an MCP JSON-RPC request.
/// Returns (response, was_tool_call) — was_tool_call is used for audit logging.
pub fn handle_mcp_request(
    state: &McpState,
    request: &JsonRpcRequest,
    token_name: &str,
    token_scopes: &str,
    rate_limit: u32,
    source_ip: &str,
    audit_retention_days: u32,
) -> JsonRpcResponse {
    match request.method.as_str() {
        "initialize" => {
            JsonRpcResponse::success(request.id.clone(), json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "tilde",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }))
        }

        "notifications/initialized" => {
            // Client notification, no response needed for notifications
            // But if it has an id, respond
            if request.id.is_some() {
                JsonRpcResponse::success(request.id.clone(), json!({}))
            } else {
                // Notifications don't get responses
                JsonRpcResponse::success(None, json!({}))
            }
        }

        "tools/list" => {
            let tools = all_tools();
            JsonRpcResponse::success(request.id.clone(), json!({
                "tools": tools
            }))
        }

        "tools/call" => {
            // Rate limit check
            if !check_rate_limit(&state.rate_limits, token_name, rate_limit) {
                return JsonRpcResponse::error(
                    request.id.clone(), -32000,
                    "rate limit exceeded",
                );
            }

            let tool_name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = request.params.get("arguments")
                .cloned()
                .unwrap_or(json!({}));

            // Scope check
            let required_scope = tool_required_scope(tool_name);
            if !check_scope(token_scopes, required_scope) {
                return JsonRpcResponse::error(
                    request.id.clone(), -32600,
                    format!("insufficient scope: requires {}", required_scope),
                );
            }

            let start = Instant::now();

            let notes_dir = state.data_dir.join("files/notes");
            let files_dir = state.data_dir.join("files");

            let result = {
                let conn = state.db.lock().unwrap();
                match tool_name {
                    "notes.search" => exec_notes_search(&conn, &notes_dir, &arguments),
                    "notes.read" => exec_notes_read(&notes_dir, &arguments),
                    "notes.append" => exec_notes_append(&notes_dir, &arguments),
                    "files.list" => exec_files_list(&files_dir, &arguments),
                    "files.read" => exec_files_read(&files_dir, &arguments),
                    "files.search" => exec_files_search(&conn, &notes_dir, &arguments),
                    "trackers.log" => exec_trackers_log(&conn, &arguments),
                    "trackers.query" => exec_trackers_query(&conn, &arguments),
                    _ => Err(format!("unknown tool: {}", tool_name)),
                }
            };

            let duration_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(value) => {
                    let result_str = serde_json::to_string(&value).unwrap_or_default();
                    let result_size = result_str.len();

                    // Audit log
                    {
                        let conn = state.db.lock().unwrap();
                        log_audit(&conn, token_name, tool_name, &arguments, result_size, duration_ms, source_ip);
                        prune_old_audit_logs(&conn, audit_retention_days);
                    }

                    info!(tool = tool_name, token = token_name, duration_ms, "MCP tool call");

                    JsonRpcResponse::success(request.id.clone(), json!({
                        "content": [{
                            "type": "text",
                            "text": result_str
                        }]
                    }))
                }
                Err(e) => {
                    warn!(tool = tool_name, error = %e, "MCP tool call failed");

                    // Still audit failed calls
                    {
                        let conn = state.db.lock().unwrap();
                        log_audit(&conn, token_name, tool_name, &arguments, 0, duration_ms, source_ip);
                    }

                    JsonRpcResponse::error(request.id.clone(), -32603, e)
                }
            }
        }

        _ => {
            JsonRpcResponse::error(
                request.id.clone(), -32601,
                format!("method not found: {}", request.method),
            )
        }
    }
}
