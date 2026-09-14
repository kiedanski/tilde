//! Upgrade path: migrating a **populated** pre-009 database.
//!
//! Every other test starts from an empty database created by the current binary,
//! so migrations 009 and 010 have only ever run against a fresh schema. A real
//! deployment upgrades a database with months of rows in it, where `files` rows
//! predate `mtime_nanos`/`inode` and may carry a **stale** `etag` — that stale
//! value is the very bug this work fixes, so it is what production data actually
//! looks like.
//!
//! This test builds that database from the historical migration files, then runs
//! the current binary against it.

mod common;

use common::e2e::{Client, start_server_prepared};

fn migrations_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("migrations")
}

fn checksum(sql: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(sql.as_bytes());
    format!("{:x}", h.finalize())
}

/// Build a database at the 001–008 schema, with the tracking rows a real
/// deployment would have, then hand it some rows to carry across the upgrade.
fn build_legacy_db(data_dir: &std::path::Path, _config: &str) {
    let conn = rusqlite::Connection::open(data_dir.join("tilde.db")).unwrap();
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );",
    )
    .unwrap();

    let mut files: Vec<_> = std::fs::read_dir(migrations_dir())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| n.ends_with(".sql"))
        .collect();
    files.sort();

    for name in files {
        let version: i64 = name.split('_').next().unwrap().parse().unwrap();
        if version > 8 {
            continue; // this is the *pre*-009 world
        }
        let sql = std::fs::read_to_string(migrations_dir().join(&name)).unwrap();
        conn.execute_batch(&sql).unwrap();
        conn.execute(
            "INSERT INTO migrations (version, name, applied_at, checksum)
             VALUES (?1, ?2, '2026-05-01T00:00:00+00:00', ?3)",
            rusqlite::params![version, name.trim_end_matches(".sql"), checksum(&sql)],
        )
        .unwrap();
    }

    // Months-old content, on disk and indexed — with a deliberately WRONG etag,
    // which is exactly what the pre-fix server left behind whenever anything
    // wrote to a file without going through DAV.
    std::fs::create_dir_all(data_dir.join("notes")).unwrap();
    std::fs::write(data_dir.join("notes/old.md"), "real content on disk\n").unwrap();

    conn.execute(
        "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type,
                            etag, sha256, is_directory, created_at, modified_at, hlc)
         VALUES ('legacy-id-1', 'notes/old.md', 'notes', 'old.md', 999, 'text/markdown',
                 'staleetag0000000', 'deadbeef', 0,
                 '2026-05-01T00:00:00+00:00', '2026-05-01T00:00:00+00:00',
                 '2026-05-01T00:00:00+00:00')",
        [],
    )
    .unwrap();

    // A collection record, to prove unrelated data survives.
    conn.execute(
        "INSERT INTO collections (id, name, schema_json, created_at, updated_at)
         VALUES ('c1', 'weight', '{}', '2026-05-01T00:00:00+00:00', '2026-05-01T00:00:00+00:00')",
        [],
    )
    .unwrap();
    conn.execute(
        "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc)
         VALUES ('r1', 'c1', '{\"kg\":80}', '2026-05-01T00:00:00+00:00',
                 '2026-05-01T00:00:00+00:00', '2026-05-01T00:00:00+00:00')",
        [],
    )
    .unwrap();
}

fn query_one<T: rusqlite::types::FromSql>(db: &std::path::Path, sql: &str) -> T {
    let conn = rusqlite::Connection::open(db).unwrap();
    conn.query_row(sql, [], |r| r.get(0)).unwrap()
}

#[test]
fn e2e_upgrade_applies_new_migrations_to_a_populated_database() {
    let (server, _pws) = start_server_prepared(&["phone"], build_legacy_db);
    let db = server.data_dir.join("tilde.db");

    let max: i64 = query_one(&db, "SELECT MAX(version) FROM migrations");
    assert_eq!(
        max, 10,
        "009 and 010 must apply on top of an existing database"
    );

    let has_cols: i64 = query_one(
        &db,
        "SELECT COUNT(*) FROM pragma_table_info('files')
         WHERE name IN ('mtime_nanos', 'inode')",
    );
    assert_eq!(has_cols, 2, "stat-cache columns must exist after upgrade");

    let has_table: i64 = query_one(
        &db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='client_base_versions'",
    );
    assert_eq!(has_table, 1);
}

#[test]
fn e2e_upgrade_preserves_existing_rows() {
    let (server, _pws) = start_server_prepared(&["phone"], build_legacy_db);
    let db = server.data_dir.join("tilde.db");

    let id: String = query_one(&db, "SELECT id FROM files WHERE path = 'notes/old.md'");
    assert_eq!(
        id, "legacy-id-1",
        "oc:id must survive the upgrade — clients key file identity on it"
    );

    let kg: String = query_one(&db, "SELECT data_json FROM records WHERE id = 'r1'");
    assert!(
        kg.contains("80"),
        "unrelated data must be untouched: {}",
        kg
    );
}

/// The upgrade must *heal* stale ETags, not preserve them. A pre-009 database is
/// full of rows whose etag no longer matches the file on disk; if the new server
/// trusted them, sync clients would still not see those files' real content.
#[test]
fn e2e_upgrade_heals_a_stale_etag_on_first_read() {
    let (server, pws) = start_server_prepared(&["phone"], build_legacy_db);
    let c = Client::new(&server, &pws[0]);

    let (status, body) = c.get("/dav/notes/old.md");
    assert_eq!(status, 200);
    assert_eq!(body, "real content on disk\n");

    let db = server.data_dir.join("tilde.db");
    let etag: String = query_one(&db, "SELECT etag FROM files WHERE path = 'notes/old.md'");

    assert_ne!(
        etag, "staleetag0000000",
        "the stale legacy etag must be replaced by one derived from disk"
    );
    let expected = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(b"real content on disk\n");
        format!("{:x}", h.finalize())[..16].to_string()
    };
    assert_eq!(etag, expected, "etag must match the real content");
}

/// The merge machinery must work for files that predate it.
#[test]
fn e2e_upgrade_enables_merge_on_a_legacy_file() {
    let (server, pws) = start_server_prepared(&["phone"], build_legacy_db);
    let c = Client::new(&server, &pws[0]);

    // Client syncs down the legacy note, establishing a base.
    assert_eq!(c.get("/dav/notes/old.md").0, 200);

    // An agent appends while the client holds the older version.
    std::fs::write(
        server.data_dir.join("notes/old.md"),
        "real content on disk\nagent line\n",
    )
    .unwrap();

    // Client writes from what it read, unaware of the agent.
    c.put("/dav/notes/old.md", "client line\nreal content on disk\n");

    let (_, merged) = c.get("/dav/notes/old.md");
    assert!(
        merged.contains("agent line") && merged.contains("client line"),
        "a file created before the upgrade must still merge:\n{}",
        merged
    );
}

/// Guards the other tests in this file: if `build_legacy_db` ever stopped
/// producing a genuine pre-009 database, they would silently degrade into
/// testing a fresh install and would keep passing while proving nothing.
#[test]
fn legacy_fixture_really_is_pre_009() {
    let dir = tempfile::tempdir().unwrap();
    build_legacy_db(dir.path(), "");
    let db = dir.path().join("tilde.db");

    let max: i64 = query_one(&db, "SELECT MAX(version) FROM migrations");
    assert_eq!(max, 8, "fixture must stop at 008");

    let stat_cols: i64 = query_one(
        &db,
        "SELECT COUNT(*) FROM pragma_table_info('files')
         WHERE name IN ('mtime_nanos', 'inode')",
    );
    assert_eq!(
        stat_cols, 0,
        "fixture must not already have the 009 columns"
    );

    let base_table: i64 = query_one(
        &db,
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='client_base_versions'",
    );
    assert_eq!(base_table, 0, "fixture must not already have the 010 table");
}
