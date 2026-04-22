-- Migration 003: CalDAV and CardDAV tables

CREATE TABLE IF NOT EXISTS calendars (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    color TEXT,
    description TEXT,
    timezone TEXT,
    ctag TEXT NOT NULL DEFAULT '0',
    sync_token INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS calendar_objects (
    id TEXT PRIMARY KEY,
    calendar_id TEXT NOT NULL REFERENCES calendars(id) ON DELETE CASCADE,
    uid TEXT NOT NULL,
    ics_data TEXT NOT NULL,
    etag TEXT NOT NULL,
    component_type TEXT NOT NULL DEFAULT 'VEVENT',
    summary TEXT,
    dtstart TEXT,
    dtend TEXT,
    location TEXT,
    description TEXT,
    priority INTEGER,
    status TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    UNIQUE(calendar_id, uid)
);

CREATE INDEX IF NOT EXISTS idx_calendar_objects_calendar ON calendar_objects(calendar_id);
CREATE INDEX IF NOT EXISTS idx_calendar_objects_uid ON calendar_objects(uid);
CREATE INDEX IF NOT EXISTS idx_calendar_objects_dtstart ON calendar_objects(dtstart);

CREATE TABLE IF NOT EXISTS addressbooks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    description TEXT,
    ctag TEXT NOT NULL DEFAULT '0',
    sync_token INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    addressbook_id TEXT NOT NULL REFERENCES addressbooks(id) ON DELETE CASCADE,
    uid TEXT NOT NULL,
    vcard_data TEXT NOT NULL,
    etag TEXT NOT NULL,
    fn_name TEXT,
    email TEXT,
    phone TEXT,
    org TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    deleted INTEGER NOT NULL DEFAULT 0,
    UNIQUE(addressbook_id, uid)
);

CREATE INDEX IF NOT EXISTS idx_contacts_addressbook ON contacts(addressbook_id);
CREATE INDEX IF NOT EXISTS idx_contacts_uid ON contacts(uid);

CREATE TABLE IF NOT EXISTS sync_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    collection_type TEXT NOT NULL,
    collection_id TEXT NOT NULL,
    object_uri TEXT NOT NULL,
    change_type TEXT NOT NULL,
    sync_token INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sync_changes_collection ON sync_changes(collection_type, collection_id, sync_token);
