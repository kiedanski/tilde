-- Full-text index of the LiveSync CouchDB vault, fed from its _changes feed.
-- CouchDB stays the source of truth; this is a rebuildable cache for search.
CREATE TABLE IF NOT EXISTS livesync_notes (
    id INTEGER PRIMARY KEY,
    doc_id TEXT NOT NULL UNIQUE,
    path TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    modified_ms INTEGER NOT NULL
);

-- remove_diacritics 2 makes "nutricion" match "nutrición".
CREATE VIRTUAL TABLE IF NOT EXISTS livesync_notes_fts USING fts5(
    path, title, content,
    content = 'livesync_notes', content_rowid = 'id',
    tokenize = 'unicode61 remove_diacritics 2'
);

CREATE TRIGGER IF NOT EXISTS livesync_notes_ai AFTER INSERT ON livesync_notes BEGIN
    INSERT INTO livesync_notes_fts (rowid, path, title, content)
    VALUES (new.id, new.path, new.title, new.content);
END;

CREATE TRIGGER IF NOT EXISTS livesync_notes_ad AFTER DELETE ON livesync_notes BEGIN
    INSERT INTO livesync_notes_fts (livesync_notes_fts, rowid, path, title, content)
    VALUES ('delete', old.id, old.path, old.title, old.content);
END;

CREATE TRIGGER IF NOT EXISTS livesync_notes_au AFTER UPDATE ON livesync_notes BEGIN
    INSERT INTO livesync_notes_fts (livesync_notes_fts, rowid, path, title, content)
    VALUES ('delete', old.id, old.path, old.title, old.content);
    INSERT INTO livesync_notes_fts (rowid, path, title, content)
    VALUES (new.id, new.path, new.title, new.content);
END;

-- Feed checkpoint per CouchDB database. built_at is set once the initial
-- pass has caught up; until then search reports the index as building.
CREATE TABLE IF NOT EXISTS livesync_index_state (
    database TEXT PRIMARY KEY,
    since TEXT,
    built_at TEXT
);
