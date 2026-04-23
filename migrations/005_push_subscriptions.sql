-- Migration 005: Push subscriptions for CalDAV/CardDAV change notifications

CREATE TABLE IF NOT EXISTS push_subscriptions (
    id TEXT PRIMARY KEY,
    collection_type TEXT NOT NULL,  -- 'calendar' or 'addressbook'
    collection_id TEXT NOT NULL,    -- calendar or addressbook ID
    callback_url TEXT NOT NULL,     -- URL to POST notifications to
    expiry TEXT NOT NULL,           -- ISO 8601 expiry timestamp
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_push_subs_collection ON push_subscriptions(collection_type, collection_id);
