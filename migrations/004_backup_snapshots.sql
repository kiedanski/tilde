-- Migration 004: Backup snapshots tracking
-- Stores metadata for local backup snapshots

CREATE TABLE IF NOT EXISTS backup_snapshots (
    id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    archive_path TEXT NOT NULL,
    checksum TEXT NOT NULL,
    pinned INTEGER NOT NULL DEFAULT 0,
    pin_reason TEXT,
    retention_class TEXT
);

CREATE INDEX IF NOT EXISTS idx_backup_snapshots_created ON backup_snapshots(created_at DESC);
