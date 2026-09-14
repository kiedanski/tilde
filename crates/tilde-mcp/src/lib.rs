//! tilde-mcp: Model Context Protocol (MCP) Streamable HTTP endpoint
//!
//! Implements JSON-RPC 2.0 over HTTP with MCP protocol methods:
//! - initialize, tools/list, tools/call
//!
//! Bearer token auth with scope enforcement, rate limiting, and audit logging.

pub mod tools_files;
pub mod tools_notes;
pub mod tools_photos;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tilde_core::db::DbPool;
use tracing::{info, warn};

/// MCP server state
pub struct McpState {
    pub db: DbPool,
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
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }
    fn error(id: Option<Value>, code: i64, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

// ─── Tool definitions ────────────────────────────────────────────────────

#[derive(Serialize)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
}

fn all_tools() -> Vec<ToolDef> {
    let mut tools = vec![
        ToolDef {
            name: "notes.search".into(),
            description: "Full-text search across the NOTES tree (`<data_dir>/notes`, the tree \
                 served at /dav/notes). This is a different directory tree from the one \
                 files.search covers: a note never appears in files.search results and a file \
                 never appears here, so pick the tool by which tree the content lives in. Only \
                 *.md and *.txt files are searched — any other extension is invisible. The query \
                 is handed to grep as a case-sensitive POSIX basic regular expression, not a \
                 fuzzy or stemmed search, so 'Widget' does not match 'widget'. Returns a JSON \
                 array with one entry per matching FILE (not per matching line): [{path, title, \
                 modified}], where path is relative to the notes root, title is the filename stem \
                 (NOT the note's heading), and modified is an ISO 8601 UTC timestamp. No snippet \
                 is returned — call notes.read for the content. An empty array means nothing \
                 matched, not an error. `limit` (default 20, no maximum) silently drops matches \
                 beyond it and results are in grep's traversal order, so a truncated result is an \
                 arbitrary subset. Requires notes:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text to find, treated as a case-sensitive POSIX basic regex. Plain substrings work; . * [ ] ^ $ \\ are metacharacters."},
                    "limit": {"type": "integer", "description": "Max matching files returned (default 20, no maximum). Excess matches are dropped silently."}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "notes.read".into(),
            description: "Read one note's full text and metadata from the NOTES tree \
                 (`<data_dir>/notes`) — not the files tree; use files.read for that. The note \
                 must already exist: a missing path, a directory, or a non-UTF-8 file all fail \
                 with \"note not found: <path>\". Paths are relative to the notes root (e.g. \
                 'projects/ideas.md'); absolute paths and any '..' segment are rejected with \
                 \"path traversal not allowed\". Returns {content: <the entire file as a string>, \
                 metadata: {title, path, modified}}, where title is the first '# ' heading in the \
                 file and falls back to the filename stem, and modified is an ISO 8601 UTC \
                 timestamp. There is no size cap and no truncation here (unlike files.read's 1MB \
                 limit), so a huge note comes back whole. Requires notes:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'projects/ideas.md'). Must already exist."}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "notes.append".into(),
            description: "Append text to the end of an EXISTING note in the notes tree, after a \
                 newline so the appended block starts on its own line. The note must already \
                 exist — a missing path fails with \"note not found: <path>\" and creates \
                 nothing; use notes.create for a new note, or notes.write to replace one \
                 wholesale. Existing content is never read or rewritten, only added to, so unlike \
                 notes.write there is no version-store archive of the pre-append state and no \
                 archived_sha256 in the result. Paths are relative to the notes root (e.g. \
                 'journal/2026-03.md'); absolute paths and '..' are rejected. No size cap. \
                 Returns {\"success\": true} and nothing else — no path, no byte count, no \
                 resulting length. Requires notes:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'journal/2026-03.md'). Must already exist — use notes.create otherwise."},
                    "content": {"type": "string", "description": "Text to add at the end of the note. A newline is inserted before it."}
                },
                "required": ["path", "content"]
            }),
        },
        ToolDef {
            name: "files.list".into(),
            description: "List the entries of one directory in the FILES tree \
                 (`<data_dir>/files`, the tree served at /dav/files) — a different tree from \
                 notes, which files.* tools cannot see at all. Paths are relative to the files \
                 root (e.g. 'docs/2026'); omit `path` or pass \"\" for the root. The directory \
                 must exist and be a directory or the call fails with \"directory not found: \
                 <path>\"; absolute paths and '..' are rejected with \"path traversal not \
                 allowed\". Dotfiles and dot-directories are skipped silently, so a hidden entry \
                 that exists simply will not appear. Returns a JSON array (empty for an empty \
                 directory) of {name, path, size, modified, type}, where path is relative to the \
                 files root, type is \"file\" or \"directory\", size is bytes, and modified is \
                 ISO 8601 UTC. There is no limit and no pagination — every entry is returned — \
                 and `recursive: true` walks the whole subtree, silently stopping at 10 levels \
                 deep. Requires files:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path relative to files root, e.g. 'docs/2026'. Default: the files root."},
                    "recursive": {"type": "boolean", "description": "Walk subdirectories too (default false). Stops silently below 10 levels deep."}
                }
            }),
        },
        ToolDef {
            name: "files.read".into(),
            description: "Read one UTF-8 text file from the FILES tree (`<data_dir>/files`) — not \
                 the notes tree; use notes.read for notes. Paths are relative to the files root \
                 (e.g. 'docs/notes/todo.md'); absolute paths and '..' are rejected with \"path \
                 traversal not allowed\". Fails with \"file not found: <path>\" when nothing is \
                 there, \"cannot read directory\" for a directory, \"file too large (max 1MB)\" \
                 above 1,048,576 bytes, and \"file is not valid UTF-8 text\" for binary content — \
                 binary and oversized files cannot be read through MCP at all. Returns {content: \
                 <the whole file as a string>}; content is never truncated, so a successful call \
                 gives you the entire file. Requires files:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to files root, e.g. 'docs/notes/todo.md'. Must exist, be UTF-8 text and be under 1MB."}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "files.search".into(),
            description: "Search file CONTENTS in the FILES tree (`<data_dir>/files`). This is a \
                 different directory tree from the one notes.search covers: notes are never \
                 found here and files are never found there, so choose by which tree the content \
                 lives in. Only *.md and *.txt files are searched — every other extension \
                 (including .json and binaries) is invisible. The query is a case-sensitive POSIX \
                 basic regular expression, handed to grep. Optional `path` narrows the search to \
                 a subdirectory relative to the files root (e.g. 'docs'); a subdirectory that \
                 does not exist yields an empty array rather than an error. Returns a JSON array \
                 with one entry per matching LINE: [{path, snippet}], where snippet is the \
                 trimmed matching line and path is relative to the directory actually searched — \
                 i.e. relative to `path` when you pass one, and to the files root otherwise. \
                 Hard-capped at 20 results, not configurable (there is no limit parameter), and \
                 nothing in the response says whether more matches existed — narrow the query or \
                 the path when you might be at the cap. Requires files:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Text to find, treated as a case-sensitive POSIX basic regex."},
                    "path": {"type": "string", "description": "Restrict to a subdirectory, relative to files root (e.g. 'docs'). Default: search the whole files tree."}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "trackers.log".into(),
            description: "Append one record to an EXISTING tracker collection (a named, schema'd \
                 log kept in SQLite — habits, weights, expenses, and so on). The collection must \
                 already exist or the call fails with \"collection '<name>' not found\", and no \
                 MCP tool can create one: collections are created out of band with the CLI \
                 `tilde collection create <name> --schema '<json-schema>'`. Names match exactly \
                 and case-sensitively; confirm one with trackers.query before logging into it. \
                 `data` is validated ONLY against the collection schema's top-level `required` \
                 list — a missing required field fails with \"missing required field: \
                 '<field>'\" — while field types, formats and unexpected extra fields are not \
                 checked and are stored exactly as given. The record's timestamp is set \
                 server-side; there is no way to backdate one, and no way to update or delete a \
                 record over MCP. Returns {\"id\": \"<uuid of the new record>\"}. Requires \
                 trackers:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Exact name of an existing collection, e.g. 'weight'. Must already exist — create it with the CLI `tilde collection create`."},
                    "data": {"type": "object", "description": "Record fields as a JSON object. Must contain the schema's required fields; anything else is stored unvalidated."}
                },
                "required": ["collection", "data"]
            }),
        },
        ToolDef {
            name: "trackers.query".into(),
            description: "Read records back from an EXISTING tracker collection, newest first. \
                 The collection must already exist or the call fails with \"collection '<name>' \
                 not found\" (names match exactly); no MCP tool creates or lists collections — \
                 the CLI `tilde collection list` shows them and `tilde collection create` makes \
                 one. Returns a JSON array of {id, data, timestamp} ordered by creation time \
                 descending, where `data` is the record object exactly as it was logged and \
                 `timestamp` is the ISO 8601 creation time with UTC offset. `limit` defaults to \
                 50 and has no maximum; results are truncated at it with no more-results flag, so \
                 a result of exactly `limit` entries may well be hiding older records. `since` \
                 filters on that same creation timestamp by plain string comparison — pass the \
                 same shape the timestamps use (e.g. '2026-01-01T00:00:00+00:00'); a bare \
                 '2026-01-01' works as a prefix bound, but a differently formatted value filters \
                 wrongly instead of erroring. An empty array means no records matched. Requires \
                 trackers:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "collection": {"type": "string", "description": "Exact name of an existing collection, e.g. 'weight'."},
                    "since": {"type": "string", "description": "Only records created at or after this. Compared as text against ISO 8601 timestamps with offset, e.g. '2026-01-01T00:00:00+00:00'."},
                    "limit": {"type": "integer", "description": "Max records returned, newest first (default 50, no maximum). Truncation is silent."}
                },
                "required": ["collection"]
            }),
        },
        ToolDef {
            name: "calendar.list_events".into(),
            description: "List calendar objects, optionally within a date window. NOTE: this \
                 returns every non-deleted object in the calendar, TASKS INCLUDED — each entry \
                 carries `type`, \"VEVENT\" for an appointment and \"VTODO\" for a task, so \
                 filter on it if you want events only (tasks.list returns tasks alone). \
                 Soft-deleted objects never appear. With no arguments it returns the entire \
                 calendar history: there is no limit and no pagination, so pass `from`/`to` \
                 unless you truly want everything. The window is inclusive and catches overlaps: \
                 `from` keeps objects ending at or after it, `to` keeps objects starting at or \
                 before it. Both bounds are compared as TEXT against the stored values, so use \
                 the same format the events were created with (ISO 8601 like \
                 '2026-03-01T00:00:00Z', or an iCalendar stamp like '20260301T000000Z'); a \
                 mismatched format filters wrongly and silently rather than erroring. `calendar` \
                 matches a calendar name exactly (see calendar.list_calendars); an unknown name \
                 returns an empty array, not an error. Returns a JSON array of {uid, type, \
                 summary, start, end, location, status} sorted by start ascending; every field \
                 except uid and type may be null. Requires calendar:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Window start, inclusive: keeps objects ending at or after this. ISO 8601 or iCalendar stamp, compared as text."},
                    "to": {"type": "string", "description": "Window end, inclusive: keeps objects starting at or before this. Same formats as 'from'."},
                    "calendar": {"type": "string", "description": "Exact calendar name (default: all calendars). An unknown name returns an empty list."}
                }
            }),
        },
        ToolDef {
            name: "calendar.create_event".into(),
            description: "Create a calendar event (an iCalendar VEVENT). The named calendar must \
                 already exist or the call fails with \"calendar '<name>' not found\"; the \
                 built-in 'default' calendar is auto-created on first use, so omitting `calendar` \
                 always works, while any other name must have been created beforehand (see \
                 calendar.list_calendars). `start` and `end` are stored VERBATIM — not parsed, \
                 not validated, not timezone-converted — so pass the format you want back out of \
                 calendar.list_events (ISO 8601 '2026-03-01T09:00:00Z' or iCalendar \
                 '20260301T090000Z') and stay consistent, because date filtering elsewhere is a \
                 text comparison. There is no conflict or duplicate detection: calling twice \
                 creates two events. Only these fields can be set — no attendees, reminders or \
                 recurrence over MCP. Returns {uid, status: \"created\"}; keep the uid to update \
                 or delete the event later. Requires calendar:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "calendar": {"type": "string", "description": "Exact name of an existing calendar (default: 'default', which is created automatically)."},
                    "summary": {"type": "string", "description": "Event title."},
                    "start": {"type": "string", "description": "Start datetime, stored verbatim and unvalidated. ISO 8601 ('2026-03-01T09:00:00Z') or iCalendar ('20260301T090000Z')."},
                    "end": {"type": "string", "description": "End datetime, same format as 'start'. Not checked against it."},
                    "location": {"type": "string", "description": "Free-text location. Optional."},
                    "description": {"type": "string", "description": "Free-text notes for the event. Optional."}
                },
                "required": ["summary", "start", "end"]
            }),
        },
        ToolDef {
            name: "contacts.search".into(),
            description: "Find contacts whose formatted name, email, phone or organisation \
                 contains the query. The match is a case-insensitive (ASCII) SUBSTRING match, not \
                 fuzzy and not prefix-anchored: 'jon' will not find 'John', and '%' or '_' in the \
                 query act as SQL LIKE wildcards. Soft-deleted contacts are excluded. A query \
                 matching nothing returns an empty array, not an error. Returns a JSON array of \
                 {uid, name, email, phone, org} in unspecified order; every field but uid may be \
                 null, and only the single stored email/phone comes back, not every address on \
                 the underlying vCard. WARNING: `limit` is accepted but currently has NO effect — \
                 every match is returned, so a broad query on a large address book returns \
                 everything. Requires contacts:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Substring to look for in name, email, phone or organisation. Case-insensitive, not fuzzy; % and _ are wildcards."},
                    "limit": {"type": "integer", "description": "Currently IGNORED — all matches are returned regardless of this value."}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "tasks.list".into(),
            description: "List to-dos — reach for this rather than calendar.list_events when you \
                 want the task list (they are stored as iCalendar VTODO objects in the same \
                 calendars). Soft-deleted tasks are excluded; everything else comes back with no \
                 limit, no pagination and no date filtering, so a long-lived list returns in \
                 full. COMPLETED tasks are included unless you filter them out: `status` matches \
                 an exact, case-sensitive status string — 'NEEDS-ACTION', 'IN-PROCESS', \
                 'COMPLETED' or 'CANCELLED'. `calendar` matches a calendar name exactly; an \
                 unknown name returns an empty array rather than an error. Returns a JSON array \
                 of {uid, summary, due, priority, status} in unspecified order — it is NOT sorted \
                 by due date — where due, priority and status may be null and priority runs 1 \
                 (highest) to 9 (lowest). Requires tasks:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "calendar": {"type": "string", "description": "Exact calendar name (default: all calendars). An unknown name returns an empty list."},
                    "status": {"type": "string", "description": "Exact, case-sensitive status filter: NEEDS-ACTION, IN-PROCESS, COMPLETED or CANCELLED. Default: every status, completed included."}
                }
            }),
        },
        ToolDef {
            name: "tasks.add".into(),
            description: "Create a to-do (an iCalendar VTODO) with status NEEDS-ACTION. The named \
                 calendar must already exist or the call fails with \"calendar '<name>' not \
                 found\"; the 'default' calendar is created automatically, so omitting `calendar` \
                 always works. `due` is stored VERBATIM without parsing or validation — pass ISO \
                 8601 ('2026-03-01T17:00:00Z') and stay consistent, since task dates are compared \
                 as text elsewhere. No duplicate detection: calling twice creates two tasks. \
                 There is no description/notes field for tasks over MCP. Returns {uid, status: \
                 \"created\"}; keep the uid for tasks.update, tasks.complete or tasks.delete. \
                 Requires tasks:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "summary": {"type": "string", "description": "Task title."},
                    "due": {"type": "string", "description": "Due date, stored verbatim and unvalidated. ISO 8601, e.g. '2026-03-01T17:00:00Z'. Optional."},
                    "priority": {"type": "integer", "description": "iCalendar priority, 1 (highest) to 9 (lowest). Optional."},
                    "calendar": {"type": "string", "description": "Exact name of an existing calendar (default: 'default', created automatically)."}
                },
                "required": ["summary"]
            }),
        },
        ToolDef {
            name: "email.search".into(),
            description: "Find indexed mail by SUBJECT, sender address or sender name only — the \
                 message BODY is not searched. Despite the name there is no full-text index: this \
                 is a case-insensitive SQL LIKE substring match, and '%' or '_' in the query act \
                 as wildcards. To get at content, match on subject or sender and read the \
                 returned snippet, or follow up with email.thread; full bodies are not exposed \
                 over MCP. Results span every indexed account and folder — there is no folder or \
                 account filter here (email.recent has one). Returns a JSON array of \
                 {message_id, from, subject, date, snippet} ordered by date descending, where \
                 `from` is the bare address and `snippet` is a short stored preview that may be \
                 null. `limit` defaults to 20 with no maximum and truncation is silent. An empty \
                 array means nothing matched — or that no mail has been indexed yet. Requires \
                 email:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {"type": "string", "description": "Substring matched against subject, sender address and sender name. Not the body. Case-insensitive; % and _ are wildcards."},
                    "limit": {"type": "integer", "description": "Max messages returned, newest first (default 20, no maximum)."}
                },
                "required": ["query"]
            }),
        },
        ToolDef {
            name: "email.thread".into(),
            description: "Fetch one message plus its DIRECT replies — one level deep, not a whole \
                 conversation. It returns the message with the given Message-ID and every message \
                 whose In-Reply-To is that id; replies to those replies, and the message's own \
                 ancestors, are NOT included, so walk the tree yourself by calling this again \
                 with each reply's message_id. `message_id` must be the exact Message-ID header \
                 value as indexed (usually angle-bracketed, e.g. '<abc123@example.com>', as \
                 returned by email.search or email.recent); an unknown or mistyped id returns an \
                 empty array rather than an error. Returns a JSON array of {message_id, from, to, \
                 subject, date, body_snippet} ordered by date ascending, where body_snippet is \
                 the short stored preview — full message bodies are not available over MCP. \
                 Requires email:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "message_id": {"type": "string", "description": "Exact Message-ID header value, usually angle-bracketed, e.g. '<abc123@example.com>'. Take it from email.search or email.recent."}
                },
                "required": ["message_id"]
            }),
        },
        ToolDef {
            name: "email.recent".into(),
            description: "List the most recent indexed messages, newest first — ordered by the \
                 message Date header, not by when it was fetched, so a newly synced old message \
                 does not jump to the top. `folder` matches a folder name exactly and \
                 case-sensitively (e.g. 'INBOX'); an unknown folder returns an empty array rather \
                 than an error, and omitting it spans every folder and account. Returns a JSON \
                 array of {message_id, from, subject, date, snippet}, where snippet is a short \
                 stored preview and may be null; full bodies are not available over MCP. `count` \
                 defaults to 10 and has no maximum. An empty array means no mail is indexed. \
                 Requires email:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "count": {"type": "integer", "description": "Max messages returned, newest first (default 10, no maximum)."},
                    "folder": {"type": "string", "description": "Exact, case-sensitive folder name, e.g. 'INBOX' (default: all folders and accounts)."}
                }
            }),
        },
        ToolDef {
            name: "calendar.list_calendars".into(),
            description: "List every calendar on the server, so you can pick a valid name for the \
                 `calendar` argument of calendar.list_events, calendar.create_event, tasks.list \
                 or tasks.add — those take the `name` value and match it exactly. Takes no \
                 arguments and no filters. Returns a JSON array of {name, display_name, ctag, \
                 description}; description may be null and ctag is a DAV sync token you can \
                 ignore. The array can be empty on a fresh server until something creates the \
                 'default' calendar, which creating an event or a task does automatically. \
                 Requires calendar:read scope."
                .into(),
            input_schema: json!({"type": "object", "properties": {}}),
        },
        ToolDef {
            name: "calendar.update_event".into(),
            description: "Change fields on an existing event, addressed by uid (from \
                 calendar.create_event or calendar.list_events). Only the fields you pass change; \
                 omitted fields keep their current values, and there is NO way to clear a field \
                 back to empty — passing \"\" sets it to an empty string. The target must be a \
                 live VEVENT: an unknown uid, an already-deleted event, or a task's uid all fail \
                 with \"event '<uid>' not found\" (use tasks.update for tasks). `start` and `end` \
                 are stored verbatim and unvalidated, so match the format the event already uses. \
                 CAUTION: the stored iCalendar object is REBUILT from summary/start/end/location/ \
                 description alone, so any other properties a CalDAV client had put on the event \
                 (recurrence rules, attendees, alarms, categories) are dropped by this call. The \
                 calendar's sync token is bumped so DAV clients see the change. Returns {uid, \
                 status: \"updated\"}. Requires calendar:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) event, from calendar.create_event or calendar.list_events."},
                    "summary": {"type": "string", "description": "New title. Omit to leave unchanged; cannot be cleared."},
                    "start": {"type": "string", "description": "New start datetime (ISO 8601 or iCalendar stamp), stored verbatim. Omit to leave unchanged."},
                    "end": {"type": "string", "description": "New end datetime, same format as 'start'. Omit to leave unchanged."},
                    "location": {"type": "string", "description": "New location. Omit to leave unchanged; cannot be cleared."},
                    "description": {"type": "string", "description": "New description. Omit to leave unchanged; cannot be cleared."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "calendar.delete_event".into(),
            description: "Delete an event by uid. The delete is a SOFT delete, and what that \
                 means for you is: the event disappears immediately from calendar.list_events, \
                 can no longer be read, updated or deleted again, and is published to DAV clients \
                 as a deletion — a second call, an unknown uid, or a task's uid all fail with \
                 \"event '<uid>' not found\" (use tasks.delete for tasks). The row survives in \
                 the database only as a tombstone for sync; NO MCP tool can restore it, so treat \
                 this as permanent and recreate the event with calendar.create_event (under a new \
                 uid) if it was a mistake. Returns {uid, status: \"deleted\"}. Requires \
                 calendar:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) event. Deleting twice is an error, not a no-op."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "tasks.update".into(),
            description: "Change fields on an existing task, addressed by uid (from tasks.add or \
                 tasks.list). Only the fields you pass change; omitted fields keep their current \
                 values and cannot be cleared back to empty. The target must be a live VTODO: an \
                 unknown uid, an already-deleted task, or an event's uid all fail with \"task \
                 '<uid>' not found\" (use calendar.update_event for events). `status` is stored \
                 verbatim and is NOT validated, so a typo like 'DONE' is accepted and will then \
                 never match tasks.list's status filter — stick to NEEDS-ACTION, IN-PROCESS, \
                 COMPLETED or CANCELLED, or call tasks.complete. `due` is likewise stored without \
                 parsing. The task's iCalendar object is rebuilt from these fields and the \
                 calendar's sync token bumped for DAV clients. Returns {uid, status: \
                 \"updated\"} — that \"updated\" reports the outcome of the call, it is not the \
                 task's own status field. Requires tasks:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) task, from tasks.add or tasks.list."},
                    "summary": {"type": "string", "description": "New title. Omit to leave unchanged; cannot be cleared."},
                    "due": {"type": "string", "description": "New due date (ISO 8601), stored verbatim and unvalidated. Omit to leave unchanged."},
                    "priority": {"type": "integer", "description": "New priority, 1 (highest) to 9 (lowest). Omit to leave unchanged."},
                    "status": {"type": "string", "description": "NEEDS-ACTION, IN-PROCESS, COMPLETED or CANCELLED. Stored verbatim and unvalidated — other values break status filtering."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "tasks.complete".into(),
            description:
                "Mark an existing task COMPLETED. Exactly equivalent to tasks.update with \
                 status 'COMPLETED': it changes nothing else and records no completion timestamp. \
                 The task must be live — an unknown uid, an already-deleted task, or an event's \
                 uid fail with \"task '<uid>' not found\". Completing an already-completed task \
                 succeeds and is a no-op. Completed tasks are NOT hidden: they keep appearing in \
                 tasks.list unless you filter with status, and this is not a delete — use \
                 tasks.delete for that. Returns {uid, status: \"completed\"}. Requires \
                 tasks:write scope."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) task, from tasks.add or tasks.list."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "tasks.delete".into(),
            description: "Delete a task by uid. The delete is a SOFT delete, and what that means \
                 for you is: the task vanishes at once from tasks.list, can no longer be read, \
                 updated or completed, and is published to DAV clients as a deletion — a second \
                 call, an unknown uid, or an event's uid all fail with \"task '<uid>' not found\" \
                 (use calendar.delete_event for events). The row survives only as a sync \
                 tombstone and NO MCP tool can undo it, so prefer tasks.complete when the work is \
                 simply finished, and re-create the task if you delete one by mistake. Returns \
                 {uid, status: \"deleted\"}. Requires tasks:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) task. Deleting twice is an error, not a no-op."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "contacts.list_addressbooks".into(),
            description: "List every address book on the server, so you can pick a valid name for \
                 the `addressbook` argument of contacts.create — it takes the `name` value and \
                 matches it exactly. Takes no arguments and no filters. Returns a JSON array of \
                 {name, display_name, description}; description may be null. The array can be \
                 empty on a fresh server until the 'default' address book exists, which \
                 contacts.create creates automatically. Requires contacts:read scope."
                .into(),
            input_schema: json!({"type": "object", "properties": {}}),
        },
        ToolDef {
            name: "contacts.create".into(),
            description: "Create a contact (a vCard) in an address book. The named address book \
                 must already exist or the call fails with \"addressbook '<name>' not found\"; \
                 the 'default' book is created automatically, so omitting `addressbook` always \
                 works (see contacts.list_addressbooks for the others). Only these four fields \
                 are stored — one formatted name, one email, one phone, one organisation; there \
                 is no way to record a second address, a birthday, a postal address or any other \
                 vCard property over MCP. There is NO duplicate detection: creating the same \
                 person twice yields two contacts, so search with contacts.search first. Returns \
                 {uid, status: \"created\"}; keep the uid for contacts.update or contacts.delete. \
                 Requires contacts:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "addressbook": {"type": "string", "description": "Exact name of an existing address book (default: 'default', created automatically)."},
                    "fn_name": {"type": "string", "description": "Formatted display name, e.g. 'Ada Lovelace'."},
                    "email": {"type": "string", "description": "A single email address. Optional; only one is stored."},
                    "phone": {"type": "string", "description": "A single phone number. Optional; only one is stored."},
                    "org": {"type": "string", "description": "Organisation name. Optional."}
                },
                "required": ["fn_name"]
            }),
        },
        ToolDef {
            name: "contacts.update".into(),
            description: "Change fields on an existing contact, addressed by uid (from \
                 contacts.create or contacts.search). Only the fields you pass change; omitted \
                 fields keep their current values and cannot be cleared back to empty. The \
                 contact must exist and not be deleted, or the call fails with \"contact '<uid>' \
                 not found\". Each field holds a single value, so passing `email` REPLACES the \
                 stored address rather than adding another. CAUTION: the vCard is REBUILT from \
                 just these four fields, so any other properties a CardDAV client stored on the \
                 contact (extra emails, postal address, birthday, notes) are dropped by this \
                 call. The address book's sync token is bumped so DAV clients see the change. \
                 Returns {uid, status: \"updated\"}. Requires contacts:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) contact, from contacts.create or contacts.search."},
                    "fn_name": {"type": "string", "description": "New formatted name. Omit to leave unchanged; cannot be cleared."},
                    "email": {"type": "string", "description": "New email address — replaces the stored one. Omit to leave unchanged."},
                    "phone": {"type": "string", "description": "New phone number — replaces the stored one. Omit to leave unchanged."},
                    "org": {"type": "string", "description": "New organisation. Omit to leave unchanged; cannot be cleared."}
                },
                "required": ["uid"]
            }),
        },
        ToolDef {
            name: "contacts.delete".into(),
            description: "Delete a contact by uid. The delete is a SOFT delete, and what that \
                 means for you is: the contact disappears immediately from contacts.search, can \
                 no longer be updated or deleted again, and is published to DAV clients as a \
                 deletion — a second call or an unknown uid fails with \"contact '<uid>' not \
                 found\". The row survives only as a sync tombstone and NO MCP tool can restore \
                 it, so confirm you have the right uid with contacts.search first; recovering \
                 means creating the contact again under a new uid. Returns {uid, status: \
                 \"deleted\"}. Requires contacts:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "uid": {"type": "string", "description": "UID of a live (non-deleted) contact, from contacts.search. Deleting twice is an error, not a no-op."}
                },
                "required": ["uid"]
            }),
        },
    ];
    // Domain modules own their own definitions so the surface can grow without
    // every addition colliding here.
    tools.extend(tools_notes::defs());
    tools.extend(tools_files::defs());
    tools.extend(tools_photos::defs());
    tools
}

// ─── Scope checking ──────────────────────────────────────────────────────

fn tool_required_scope(tool_name: &str) -> &'static str {
    match tool_name {
        "notes.search" | "notes.read" => "notes:read",
        "notes.append" => "notes:write",
        "files.list" | "files.read" | "files.search" => "files:read",
        "trackers.query" => "trackers:read",
        "trackers.log" => "trackers:write",
        "calendar.list_events" | "calendar.list_calendars" => "calendar:read",
        "calendar.create_event" | "calendar.update_event" | "calendar.delete_event" => {
            "calendar:write"
        }
        "contacts.search" | "contacts.list_addressbooks" => "contacts:read",
        "contacts.create" | "contacts.update" | "contacts.delete" => "contacts:write",
        "tasks.list" => "tasks:read",
        "tasks.add" | "tasks.update" | "tasks.complete" | "tasks.delete" => "tasks:write",
        "email.search" | "email.thread" | "email.recent" => "email:read",
        _ => {
            // Domain modules declare their own scopes.
            if let Some(scope) = tools_notes::required_scope(tool_name)
                .or_else(|| tools_files::required_scope(tool_name))
                .or_else(|| tools_photos::required_scope(tool_name))
            {
                return scope;
            }
            "unknown"
        }
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

/// Truncate to at most `max_bytes`, never splitting a UTF-8 character.
///
/// `&s[..n]` panics when `n` lands inside a multibyte character. The audit log
/// sliced tool parameters at a fixed byte offset, so any call whose serialized
/// params crossed that offset mid-character panicked — and it fired *after* the
/// write had already been applied, killing the connection with the client unable
/// to tell whether its write succeeded. Ordinary input reaches this: an accented
/// character or an emoji in a note or task title.
pub(crate) fn truncate_on_char_boundary(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

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
    let truncated = truncate_on_char_boundary(&params_str, 500);
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

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

/// Resolve a user-supplied relative path inside `root`, refusing anything that
/// escapes it.
///
/// `Path::starts_with` is **component-wise and does not normalise**, so the
/// obvious check `root.join(rel).starts_with(root)` returns true for
/// `root/../etc/passwd` and lets the read escape. That was a live traversal hole
/// in every MCP path tool: a `notes:read` token could read any file the server
/// process could open, including the database. Lexical rejection of `..` is the
/// actual fix; the prefix check and the symlink check below are defence in depth.
pub(crate) fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.is_empty() {
        return Ok(root.to_path_buf());
    }

    let mut full = root.to_path_buf();
    for component in Path::new(rel).components() {
        match component {
            std::path::Component::Normal(part) => full.push(part),
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir
            | std::path::Component::RootDir
            | std::path::Component::Prefix(_) => {
                return Err("path traversal not allowed".into());
            }
        }
    }

    if !full.starts_with(root) {
        return Err("path traversal not allowed".into());
    }

    // A lexically clean path can still escape through a symlink. Probe from the
    // target itself, not its parent: `skip(1)` missed a symlink *at* the
    // requested path, and `notes.write` uses `fs::write`, which follows it.
    if let Some(existing) = full.ancestors().find(|a| a.exists())
        && let (Ok(real), Ok(real_root)) = (existing.canonicalize(), root.canonicalize())
        && !real.starts_with(&real_root)
    {
        return Err("path traversal not allowed".into());
    }

    Ok(full)
}

fn exec_notes_search(
    _conn: &Connection,
    notes_dir: &Path,
    params: &Value,
) -> Result<Value, String> {
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or("query parameter required")?;
    let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(20);

    if !notes_dir.exists() {
        return Ok(json!([]));
    }

    // Use grep for search — notes are plain files on disk
    let output = std::process::Command::new("grep")
        .args([
            "-rn",
            "--include=*.md",
            "--include=*.txt",
            "--color=never",
            "-l",
            // `--` stops grep parsing the query as an option (see notes.rs).
            "--",
            query,
        ])
        .arg(notes_dir)
        .output()
        .map_err(|e| format!("grep failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results: Vec<Value> = Vec::new();
    for line in stdout.lines().take(limit as usize) {
        let full_path = std::path::Path::new(line.trim());
        let rel_path = full_path
            .strip_prefix(notes_dir)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| line.trim().to_string());
        let title = full_path
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let modified = full_path
            .metadata()
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
        results.push(json!({
            "path": rel_path,
            "title": title,
            "modified": modified,
        }));
    }

    Ok(json!(results))
}

fn exec_notes_read(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let full_path = safe_join(notes_dir, path)?;

    let content =
        std::fs::read_to_string(&full_path).map_err(|_| format!("note not found: {}", path))?;

    let title = content
        .lines()
        .find(|l| l.starts_with("# "))
        .map(|l| l.trim_start_matches("# ").to_string())
        .unwrap_or_else(|| {
            full_path
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default()
        });

    let modified = full_path
        .metadata()
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
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;
    let content = params
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or("content parameter required")?;

    let full_path = safe_join(notes_dir, path)?;

    if !full_path.exists() {
        return Err(format!("note not found: {}", path));
    }

    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&full_path)
        .map_err(|e| e.to_string())?;

    file.write_all(b"\n").map_err(|e| e.to_string())?;
    file.write_all(content.as_bytes())
        .map_err(|e| e.to_string())?;

    Ok(json!({"success": true}))
}

fn exec_files_list(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let rel_path = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let recursive = params
        .get("recursive")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let target = safe_join(files_dir, rel_path)?;
    if !target.exists() || !target.is_dir() {
        return Err(format!("directory not found: {}", rel_path));
    }

    let mut entries = Vec::new();
    list_dir_entries(&target, files_dir, recursive, &mut entries, 0);

    Ok(json!(entries))
}

fn list_dir_entries(
    dir: &Path,
    base: &Path,
    recursive: bool,
    entries: &mut Vec<Value>,
    depth: usize,
) {
    if depth > 10 {
        return;
    } // prevent infinite recursion
    if let Ok(read_dir) = std::fs::read_dir(dir) {
        for entry in read_dir.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }

            let rel = path
                .strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            let is_dir = path.is_dir();
            let meta = path.metadata().ok();
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let modified = meta
                .and_then(|m| m.modified().ok())
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
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let full_path = safe_join(files_dir, path)?;
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

fn exec_files_search(
    _conn: &Connection,
    files_dir: &Path,
    params: &Value,
) -> Result<Value, String> {
    let query = params
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or("query parameter required")?;

    // Honour the declared `path` parameter ("Restrict to subdirectory"), which
    // was previously accepted and ignored.
    let rel = params.get("path").and_then(|v| v.as_str()).unwrap_or("");
    let search_root = safe_join(files_dir, rel)?;

    let notes_dir = &search_root; // grep target below
    if !notes_dir.exists() {
        return Ok(json!([]));
    }

    // Use grep for file content search
    let output = std::process::Command::new("grep")
        .args([
            "-rn",
            "--include=*.md",
            "--include=*.txt",
            "--color=never",
            // `--` stops grep parsing the query as an option (see notes.rs).
            "--",
            query,
        ])
        .arg(notes_dir)
        .output()
        .map_err(|e| format!("grep failed: {}", e))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut results: Vec<Value> = Vec::new();
    for line in stdout.lines().take(20) {
        let rel = line
            .strip_prefix(notes_dir.to_str().unwrap_or(""))
            .map(|s| s.trim_start_matches('/'))
            .unwrap_or(line);
        // Split "path:line:content" into path and snippet
        let (path, snippet) = rel
            .split_once(':')
            .and_then(|(p, rest)| rest.split_once(':').map(|(_, s)| (p, s)))
            .unwrap_or((rel, ""));
        results.push(json!({
            "path": path,
            "snippet": snippet.trim(),
        }));
    }

    Ok(json!(results))
}

fn exec_trackers_log(conn: &Connection, params: &Value) -> Result<Value, String> {
    let collection_name = params
        .get("collection")
        .and_then(|v| v.as_str())
        .ok_or("collection parameter required")?;
    let data = params.get("data").ok_or("data parameter required")?;

    let (collection_id, schema_json): (String, String) = conn
        .query_row(
            "SELECT id, schema_json FROM collections WHERE name = ?1",
            [collection_name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|_| format!("collection '{}' not found", collection_name))?;

    // Basic schema validation
    if let Ok(schema) = serde_json::from_str::<Value>(&schema_json) {
        basic_validate(data, &schema)?;
    }

    let id = uuid::Uuid::new_v4().to_string();
    let data_str = serde_json::to_string(data).map_err(|e| e.to_string())?;
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    conn.execute(
        "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        rusqlite::params![id, collection_id, data_str, now, now, now],
    ).map_err(|e| e.to_string())?;

    Ok(json!({"id": id}))
}

fn exec_trackers_query(conn: &Connection, params: &Value) -> Result<Value, String> {
    let collection_name = params
        .get("collection")
        .and_then(|v| v.as_str())
        .ok_or("collection parameter required")?;
    let since = params.get("since").and_then(|v| v.as_str());
    let limit = params.get("limit").and_then(|v| v.as_i64()).unwrap_or(50);

    let (collection_id,): (String,) = conn
        .query_row(
            "SELECT id FROM collections WHERE name = ?1",
            [collection_name],
            |row| Ok((row.get(0)?,)),
        )
        .map_err(|_| format!("collection '{}' not found", collection_name))?;

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
        })
        .map_err(|e| e.to_string())?
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
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect()
    };

    Ok(json!(results))
}

// ─── Helpers ─────────────────────────────────────────────────────────────

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
        "initialize" => JsonRpcResponse::success(
            request.id.clone(),
            json!({
                "protocolVersion": "2025-03-26",
                "capabilities": {
                    "tools": {}
                },
                "serverInfo": {
                    "name": "tilde",
                    "version": env!("CARGO_PKG_VERSION")
                }
            }),
        ),

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
            JsonRpcResponse::success(
                request.id.clone(),
                json!({
                    "tools": tools
                }),
            )
        }

        "tools/call" => {
            // Rate limit check
            if !check_rate_limit(&state.rate_limits, token_name, rate_limit) {
                return JsonRpcResponse::error(request.id.clone(), -32000, "rate limit exceeded");
            }

            let tool_name = request
                .params
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = request
                .params
                .get("arguments")
                .cloned()
                .unwrap_or(json!({}));

            // Scope check
            let required_scope = tool_required_scope(tool_name);
            if !check_scope(token_scopes, required_scope) {
                return JsonRpcResponse::error(
                    request.id.clone(),
                    -32600,
                    format!("insufficient scope: requires {}", required_scope),
                );
            }

            let start = Instant::now();

            let notes_dir = state.data_dir.join("notes");
            let files_dir = state.data_dir.join("files");

            let result = {
                let conn = state.db.get().unwrap();
                match tool_name {
                    "notes.search" => exec_notes_search(&conn, &notes_dir, &arguments),
                    "notes.read" => exec_notes_read(&notes_dir, &arguments),
                    "notes.append" => exec_notes_append(&notes_dir, &arguments),
                    "files.list" => exec_files_list(&files_dir, &arguments),
                    "files.read" => exec_files_read(&files_dir, &arguments),
                    // files.search searches the FILES tree — it was previously
                    // handed notes_dir and so searched the wrong tree entirely.
                    "files.search" => exec_files_search(&conn, &files_dir, &arguments),
                    "trackers.log" => exec_trackers_log(&conn, &arguments),
                    "trackers.query" => exec_trackers_query(&conn, &arguments),
                    "calendar.list_events" => exec_calendar_list_events(&conn, &arguments),
                    "calendar.create_event" => exec_calendar_create_event(&conn, &arguments),
                    "calendar.list_calendars" => exec_calendar_list_calendars(&conn),
                    "calendar.update_event" => exec_calendar_update_event(&conn, &arguments),
                    "calendar.delete_event" => exec_calendar_delete_event(&conn, &arguments),
                    "contacts.search" => exec_contacts_search(&conn, &arguments),
                    "contacts.list_addressbooks" => exec_contacts_list_addressbooks(&conn),
                    "contacts.create" => exec_contacts_create(&conn, &arguments),
                    "contacts.update" => exec_contacts_update(&conn, &arguments),
                    "contacts.delete" => exec_contacts_delete(&conn, &arguments),
                    "tasks.list" => exec_tasks_list(&conn, &arguments),
                    "tasks.add" => exec_tasks_add(&conn, &arguments),
                    "tasks.update" => exec_tasks_update(&conn, &arguments),
                    "tasks.complete" => exec_tasks_complete(&conn, &arguments),
                    "tasks.delete" => exec_tasks_delete(&conn, &arguments),
                    "email.search" => exec_email_search(&conn, &arguments),
                    "email.thread" => exec_email_thread(&conn, &arguments),
                    "email.recent" => exec_email_recent(&conn, &arguments),
                    _ => tools_notes::exec(tool_name, &notes_dir, &arguments)
                        .or_else(|| tools_files::exec(tool_name, &files_dir, &arguments))
                        .or_else(|| tools_photos::exec(tool_name, &conn, &arguments))
                        .unwrap_or_else(|| Err(format!("unknown tool: {}", tool_name))),
                }
            };

            let duration_ms = start.elapsed().as_millis() as u64;

            match result {
                Ok(value) => {
                    let result_str = serde_json::to_string(&value).unwrap_or_default();
                    let result_size = result_str.len();

                    // Audit log
                    {
                        let conn = state.db.get().unwrap();
                        log_audit(
                            &conn,
                            token_name,
                            tool_name,
                            &arguments,
                            result_size,
                            duration_ms,
                            source_ip,
                        );
                        prune_old_audit_logs(&conn, audit_retention_days);
                    }

                    info!(
                        tool = tool_name,
                        token = token_name,
                        duration_ms,
                        "MCP tool call"
                    );

                    JsonRpcResponse::success(
                        request.id.clone(),
                        json!({
                            "content": [{
                                "type": "text",
                                "text": result_str
                            }]
                        }),
                    )
                }
                Err(e) => {
                    warn!(tool = tool_name, error = %e, "MCP tool call failed");

                    // Still audit failed calls
                    {
                        let conn = state.db.get().unwrap();
                        log_audit(
                            &conn,
                            token_name,
                            tool_name,
                            &arguments,
                            0,
                            duration_ms,
                            source_ip,
                        );
                    }

                    JsonRpcResponse::error(request.id.clone(), -32603, e)
                }
            }
        }

        _ => JsonRpcResponse::error(
            request.id.clone(),
            -32601,
            format!("method not found: {}", request.method),
        ),
    }
}

// ─── Calendar/Contacts/Tasks/Email tool implementations ───────────��─────

fn exec_calendar_list_events(conn: &Connection, args: &Value) -> Result<Value, String> {
    let calendar = args.get("calendar").and_then(|v| v.as_str());
    let from = args.get("from").and_then(|v| v.as_str());
    let to = args.get("to").and_then(|v| v.as_str());

    let events = tilde_cal::list_events(conn, calendar, from, to);
    let results: Vec<Value> = events
        .iter()
        .map(
            |(uid, comp_type, summary, dtstart, dtend, location, status)| {
                json!({
                    "uid": uid,
                    "type": comp_type,
                    "summary": summary,
                    "start": dtstart,
                    "end": dtend,
                    "location": location,
                    "status": status,
                })
            },
        )
        .collect();
    Ok(json!(results))
}

fn exec_calendar_create_event(conn: &Connection, args: &Value) -> Result<Value, String> {
    let calendar = args
        .get("calendar")
        .and_then(|v| v.as_str())
        .unwrap_or("default");
    let summary = args
        .get("summary")
        .and_then(|v| v.as_str())
        .ok_or("summary is required")?;
    let start = args
        .get("start")
        .and_then(|v| v.as_str())
        .ok_or("start is required")?;
    let end = args
        .get("end")
        .and_then(|v| v.as_str())
        .ok_or("end is required")?;
    let location = args.get("location").and_then(|v| v.as_str());
    let description = args.get("description").and_then(|v| v.as_str());

    tilde_cal::ensure_default_calendar(conn);
    match tilde_cal::create_event(conn, calendar, summary, start, end, location, description) {
        Ok(uid) => Ok(json!({"uid": uid, "status": "created"})),
        Err(e) => Err(e.to_string()),
    }
}

fn exec_contacts_search(conn: &Connection, args: &Value) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or("query is required")?;
    let contacts = tilde_card::search_contacts(conn, query);
    let results: Vec<Value> = contacts
        .iter()
        .map(|(uid, name, email, phone, org)| {
            json!({
                "uid": uid,
                "name": name,
                "email": email,
                "phone": phone,
                "org": org,
            })
        })
        .collect();
    Ok(json!(results))
}

fn exec_tasks_list(conn: &Connection, args: &Value) -> Result<Value, String> {
    let calendar = args.get("calendar").and_then(|v| v.as_str());
    let status = args.get("status").and_then(|v| v.as_str());

    let tasks = tilde_cal::list_tasks(conn, calendar, status);
    let results: Vec<Value> = tasks
        .iter()
        .map(|(uid, summary, due, priority, status)| {
            json!({
                "uid": uid,
                "summary": summary,
                "due": due,
                "priority": priority,
                "status": status,
            })
        })
        .collect();
    Ok(json!(results))
}

fn exec_tasks_add(conn: &Connection, args: &Value) -> Result<Value, String> {
    let summary = args
        .get("summary")
        .and_then(|v| v.as_str())
        .ok_or("summary is required")?;
    let due = args.get("due").and_then(|v| v.as_str());
    let priority = args
        .get("priority")
        .and_then(|v| v.as_i64())
        .map(|p| p as i32);
    let calendar = args.get("calendar").and_then(|v| v.as_str());

    match tilde_cal::create_task(conn, calendar, summary, due, priority) {
        Ok(uid) => Ok(json!({"uid": uid, "status": "created"})),
        Err(e) => Err(e.to_string()),
    }
}

fn exec_email_search(conn: &Connection, args: &Value) -> Result<Value, String> {
    let query = args
        .get("query")
        .and_then(|v| v.as_str())
        .ok_or("query is required")?;
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(20) as u32;

    // Try FTS5 search first, fall back to LIKE
    let mut stmt = conn
        .prepare(
            "SELECT message_id, from_address, subject, date, snippet FROM email_messages
         WHERE subject LIKE ?1 OR from_address LIKE ?1 OR from_name LIKE ?1
         ORDER BY date DESC LIMIT ?2",
        )
        .map_err(|e| e.to_string())?;

    let pattern = format!("%{}%", query);
    let results: Vec<Value> = stmt
        .query_map(rusqlite::params![pattern, limit], |row| {
            Ok(json!({
                "message_id": row.get::<_, String>(0)?,
                "from": row.get::<_, String>(1)?,
                "subject": row.get::<_, String>(2)?,
                "date": row.get::<_, String>(3)?,
                "snippet": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(json!(results))
}

fn exec_email_thread(conn: &Connection, args: &Value) -> Result<Value, String> {
    let message_id = args
        .get("message_id")
        .and_then(|v| v.as_str())
        .ok_or("message_id is required")?;

    let mut stmt = conn
        .prepare(
            "SELECT message_id, from_address, to_addresses, subject, date, snippet
         FROM email_messages WHERE message_id = ?1 OR in_reply_to = ?1
         ORDER BY date",
        )
        .map_err(|e| e.to_string())?;

    let results: Vec<Value> = stmt
        .query_map([message_id], |row| {
            Ok(json!({
                "message_id": row.get::<_, String>(0)?,
                "from": row.get::<_, String>(1)?,
                "to": row.get::<_, String>(2)?,
                "subject": row.get::<_, String>(3)?,
                "date": row.get::<_, String>(4)?,
                "body_snippet": row.get::<_, Option<String>>(5)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(json!(results))
}

fn exec_email_recent(conn: &Connection, args: &Value) -> Result<Value, String> {
    let count = args.get("count").and_then(|v| v.as_i64()).unwrap_or(10) as u32;
    let folder = args.get("folder").and_then(|v| v.as_str());

    let (query, params): (String, Vec<Box<dyn rusqlite::types::ToSql>>) = match folder {
        Some(f) => (
            "SELECT message_id, from_address, subject, date, snippet FROM email_messages WHERE folder = ?1 ORDER BY date DESC LIMIT ?2".into(),
            vec![Box::new(f.to_string()), Box::new(count)],
        ),
        None => (
            "SELECT message_id, from_address, subject, date, snippet FROM email_messages ORDER BY date DESC LIMIT ?1".into(),
            vec![Box::new(count)],
        ),
    };

    let mut stmt = conn.prepare(&query).map_err(|e| e.to_string())?;
    let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let results: Vec<Value> = stmt
        .query_map(refs.as_slice(), |row| {
            Ok(json!({
                "message_id": row.get::<_, String>(0)?,
                "from": row.get::<_, String>(1)?,
                "subject": row.get::<_, String>(2)?,
                "date": row.get::<_, String>(3)?,
                "snippet": row.get::<_, Option<String>>(4)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(json!(results))
}

fn exec_calendar_list_calendars(conn: &Connection) -> Result<Value, String> {
    let calendars = tilde_cal::list_calendars(conn);
    let results: Vec<Value> = calendars
        .iter()
        .map(|(name, display_name, ctag, description)| {
            json!({
                "name": name,
                "display_name": display_name,
                "ctag": ctag,
                "description": description,
            })
        })
        .collect();
    Ok(json!(results))
}

fn exec_calendar_update_event(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    let summary = args.get("summary").and_then(|v| v.as_str());
    let start = args.get("start").and_then(|v| v.as_str());
    let end = args.get("end").and_then(|v| v.as_str());
    let location = args.get("location").and_then(|v| v.as_str());
    let description = args.get("description").and_then(|v| v.as_str());
    tilde_cal::update_event(conn, uid, summary, start, end, location, description)
        .map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "updated"}))
}

fn exec_calendar_delete_event(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    tilde_cal::delete_event(conn, uid).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "deleted"}))
}

fn exec_tasks_update(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    let summary = args.get("summary").and_then(|v| v.as_str());
    let due = args.get("due").and_then(|v| v.as_str());
    let priority = args
        .get("priority")
        .and_then(|v| v.as_i64())
        .map(|p| p as i32);
    let status = args.get("status").and_then(|v| v.as_str());
    tilde_cal::update_task(conn, uid, summary, due, priority, status).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "updated"}))
}

fn exec_tasks_complete(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    tilde_cal::complete_task(conn, uid).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "completed"}))
}

fn exec_tasks_delete(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    tilde_cal::delete_task(conn, uid).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "deleted"}))
}

fn exec_contacts_list_addressbooks(conn: &Connection) -> Result<Value, String> {
    let books = tilde_card::list_addressbooks(conn);
    let results: Vec<Value> = books
        .iter()
        .map(|(name, display_name, description)| {
            json!({
                "name": name,
                "display_name": display_name,
                "description": description,
            })
        })
        .collect();
    Ok(json!(results))
}

fn exec_contacts_create(conn: &Connection, args: &Value) -> Result<Value, String> {
    let fn_name = args
        .get("fn_name")
        .and_then(|v| v.as_str())
        .ok_or("fn_name is required")?;
    let addressbook = args.get("addressbook").and_then(|v| v.as_str());
    let email = args.get("email").and_then(|v| v.as_str());
    let phone = args.get("phone").and_then(|v| v.as_str());
    let org = args.get("org").and_then(|v| v.as_str());
    let uid = tilde_card::create_contact(conn, addressbook, fn_name, email, phone, org)
        .map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "created"}))
}

fn exec_contacts_update(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    let fn_name = args.get("fn_name").and_then(|v| v.as_str());
    let email = args.get("email").and_then(|v| v.as_str());
    let phone = args.get("phone").and_then(|v| v.as_str());
    let org = args.get("org").and_then(|v| v.as_str());
    tilde_card::update_contact(conn, uid, fn_name, email, phone, org).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "updated"}))
}

fn exec_contacts_delete(conn: &Connection, args: &Value) -> Result<Value, String> {
    let uid = args
        .get("uid")
        .and_then(|v| v.as_str())
        .ok_or("uid is required")?;
    tilde_card::delete_contact(conn, uid).map_err(|e| e.to_string())?;
    Ok(json!({"uid": uid, "status": "deleted"}))
}

#[cfg(test)]
mod audit_truncation_tests {
    use super::*;

    /// `&s[..500]` panics when byte 500 lands inside a multibyte character.
    /// Without the fix this test panics rather than failing.
    #[test]
    fn truncation_never_splits_a_multibyte_character() {
        let mut s = "x".repeat(499);
        s.push('\u{e9}'); // 2 bytes, straddling byte 500
        s.push_str(&"y".repeat(50));
        assert!(
            !s.is_char_boundary(500),
            "test fixture must straddle the cut"
        );

        let out = truncate_on_char_boundary(&s, 500);
        assert_eq!(out.len(), 499, "must cut back to the boundary");
        assert!(out.is_char_boundary(out.len()));
    }

    #[test]
    fn truncation_handles_emoji_and_wide_chars() {
        for ch in ['\u{1f600}', '\u{4e16}', '\u{e9}'] {
            for pad in 495..505usize {
                let mut s = "x".repeat(pad);
                s.push(ch);
                s.push_str(&"y".repeat(20));
                let out = truncate_on_char_boundary(&s, 500);
                assert!(out.len() <= 500);
                assert!(s.starts_with(out), "truncation must be a prefix");
            }
        }
    }

    #[test]
    fn truncation_passes_short_input_through() {
        assert_eq!(truncate_on_char_boundary("hello", 500), "hello");
        assert_eq!(truncate_on_char_boundary("", 500), "");
    }

    #[test]
    fn truncation_survives_all_multibyte_input() {
        // Every byte position is inside a character; must not panic or overrun.
        let s = "\u{1f600}".repeat(400);
        let out = truncate_on_char_boundary(&s, 500);
        assert!(out.len() <= 500);
        assert_eq!(out.len() % 4, 0, "emoji are 4 bytes each");
    }
}
