-- Migration 002: Custom WebDAV properties for files
-- Stores PROPPATCH-set properties per file

CREATE TABLE IF NOT EXISTS file_properties (
    file_path TEXT NOT NULL,
    namespace TEXT NOT NULL,
    name TEXT NOT NULL,
    value TEXT,
    PRIMARY KEY (file_path, namespace, name)
);

CREATE INDEX IF NOT EXISTS idx_file_properties_path ON file_properties(file_path);
