-- Migration 001: Initial schema
-- Creates core tables for tilde personal cloud server

CREATE TABLE IF NOT EXISTS migrations (
    version INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    applied_at TEXT NOT NULL,
    checksum TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    id TEXT PRIMARY KEY,
    token_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    user_agent TEXT,
    source_ip TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS app_passwords (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    scope_prefix TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    rate_limit INTEGER NOT NULL DEFAULT 60,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mcp_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token_name TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    params_truncated TEXT,
    result_size_bytes INTEGER,
    duration_ms INTEGER NOT NULL,
    source_ip TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    path TEXT NOT NULL UNIQUE,
    parent_path TEXT NOT NULL,
    name TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    content_type TEXT NOT NULL,
    etag TEXT NOT NULL,
    sha256 TEXT,
    is_directory INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    modified_at TEXT NOT NULL,
    hlc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_path);

CREATE TABLE IF NOT EXISTS photos (
    id TEXT PRIMARY KEY,
    file_id TEXT NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    original_sha256 TEXT NOT NULL,
    current_sha256 TEXT NOT NULL,
    width INTEGER,
    height INTEGER,
    taken_at TEXT,
    camera_make TEXT,
    camera_model TEXT,
    lens TEXT,
    focal_length_mm REAL,
    aperture REAL,
    iso INTEGER,
    exposure_time TEXT,
    gps_latitude REAL,
    gps_longitude REAL,
    gps_altitude REAL,
    orientation INTEGER,
    content_readable INTEGER NOT NULL DEFAULT 1,
    manually_placed INTEGER NOT NULL DEFAULT 0,
    blurhash TEXT,
    thumbnail_256_generated INTEGER NOT NULL DEFAULT 0,
    thumbnail_1920_generated INTEGER NOT NULL DEFAULT 0,
    tags_json TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    hlc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS photo_tags (
    photo_id TEXT NOT NULL REFERENCES photos(id) ON DELETE CASCADE,
    tag TEXT NOT NULL,
    prefix TEXT,
    PRIMARY KEY (photo_id, tag)
);

CREATE INDEX IF NOT EXISTS idx_photo_tags_tag ON photo_tags(tag);

CREATE TABLE IF NOT EXISTS collections (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    schema_json TEXT NOT NULL,
    display_config TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS records (
    id TEXT PRIMARY KEY,
    collection_id TEXT NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    data_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    hlc TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_records_collection ON records(collection_id, created_at);

CREATE TABLE IF NOT EXISTS email_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    account TEXT NOT NULL,
    message_id TEXT NOT NULL,
    folder TEXT NOT NULL,
    uid INTEGER NOT NULL,
    from_address TEXT NOT NULL,
    from_name TEXT,
    to_addresses TEXT NOT NULL,
    cc_addresses TEXT,
    subject TEXT NOT NULL,
    date TEXT NOT NULL,
    in_reply_to TEXT,
    references_list TEXT,
    snippet TEXT,
    has_attachment INTEGER NOT NULL DEFAULT 0,
    size_bytes INTEGER NOT NULL,
    flags TEXT,
    maildir_path TEXT NOT NULL,
    tags_json TEXT,
    created_at TEXT NOT NULL,
    UNIQUE(account, message_id)
);

CREATE INDEX IF NOT EXISTS idx_email_date ON email_messages(account, date DESC);
CREATE INDEX IF NOT EXISTS idx_email_folder ON email_messages(account, folder);
CREATE INDEX IF NOT EXISTS idx_email_thread ON email_messages(in_reply_to);

CREATE TABLE IF NOT EXISTS chunked_uploads (
    session_id TEXT PRIMARY KEY,
    destination_path TEXT NOT NULL,
    total_size INTEGER,
    bytes_received INTEGER NOT NULL DEFAULT 0,
    chunk_count INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    staging_dir TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    target_uri TEXT NOT NULL,
    context TEXT
);

CREATE INDEX IF NOT EXISTS idx_links_source ON links(source_type, source_id);
CREATE INDEX IF NOT EXISTS idx_links_target ON links(target_uri);

CREATE TABLE IF NOT EXISTS jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 3,
    error_message TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    completed_at TEXT
);

CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    priority TEXT NOT NULL,
    message TEXT NOT NULL,
    sinks_notified TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id TEXT PRIMARY KEY,
    public_key BLOB NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
);

CREATE TABLE IF NOT EXISTS webhook_tokens (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    token_prefix TEXT NOT NULL,
    scopes TEXT NOT NULL,
    rate_limit INTEGER NOT NULL DEFAULT 30,
    hmac_secret TEXT,
    created_at TEXT NOT NULL,
    last_used_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- FTS5 virtual tables
CREATE VIRTUAL TABLE IF NOT EXISTS notes_fts USING fts5(path, title, content);
CREATE VIRTUAL TABLE IF NOT EXISTS email_fts USING fts5(subject, from_address, from_name, body_text);
