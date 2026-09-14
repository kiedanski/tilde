-- Per-client record of the last content version served.
--
-- Three-way merge (plan.md §5) needs the *base* version a writing client was
-- working from. The ETag identifies it; this table remembers which one each
-- credential last received, so a stale PUT can be merged against the right
-- ancestor instead of silently overwriting.
--
-- Keyed by credential, so each device must have its own app password — a shared
-- password collapses the tracking and picks wrong bases.
CREATE TABLE IF NOT EXISTS client_base_versions (
    credential_id TEXT NOT NULL,
    path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    served_at TEXT NOT NULL,
    PRIMARY KEY (credential_id, path)
);
