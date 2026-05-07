//! SQLite database initialization and migration runner

use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::info;

/// Connection pool type for the application.
/// Each pooled connection is configured with the same PRAGMAs as `init_db`.
pub type DbPool = r2d2::Pool<SqliteConnectionManager>;

/// Initialize SQLite database with required PRAGMAs (single connection).
/// Kept for `:memory:` databases in tests and one-shot CLI commands.
pub fn init_db(path: &str) -> anyhow::Result<Connection> {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)?;

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA foreign_keys=ON;
         PRAGMA mmap_size=33554432;",
    )?;

    info!(path = path, "Database initialized with WAL mode");
    Ok(conn)
}

/// Create a connection pool with ~4 connections, each configured with
/// the same PRAGMAs as `init_db`. WAL mode supports concurrent readers
/// while writes serialize on SQLite's internal lock.
pub fn init_pool(path: &str) -> anyhow::Result<DbPool> {
    // Ensure parent directory exists
    if let Some(parent) = Path::new(path).parent() {
        std::fs::create_dir_all(parent)?;
    }

    let manager = SqliteConnectionManager::file(path).with_init(|conn| {
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA busy_timeout=5000;
             PRAGMA foreign_keys=ON;
             PRAGMA mmap_size=33554432;",
        )
    });

    let pool = r2d2::Pool::builder().max_size(4).build(manager)?;

    info!(
        path = path,
        pool_size = 4,
        "Database pool initialized with WAL mode"
    );
    Ok(pool)
}

/// A single migration with version, name, and SQL content
struct Migration {
    version: i64,
    name: String,
    sql: String,
    checksum: String,
}

/// Compute SHA-256 checksum of SQL content
fn compute_checksum(sql: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(sql.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Migrations embedded at compile time so they're always available,
/// regardless of the working directory at runtime.
const EMBEDDED_MIGRATIONS: &[(&str, &str)] = &[
    ("001_initial", include_str!("../../../migrations/001_initial.sql")),
    ("002_file_properties", include_str!("../../../migrations/002_file_properties.sql")),
    ("003_caldav_carddav", include_str!("../../../migrations/003_caldav_carddav.sql")),
    ("004_backup_snapshots", include_str!("../../../migrations/004_backup_snapshots.sql")),
    ("005_push_subscriptions", include_str!("../../../migrations/005_push_subscriptions.sql")),
    ("006_app_password_lookup", include_str!("../../../migrations/006_app_password_lookup.sql")),
    ("007_drop_fts_tables", include_str!("../../../migrations/007_drop_fts_tables.sql")),
];

/// Load embedded migrations (compiled into the binary).
fn load_embedded_migrations() -> Vec<Migration> {
    EMBEDDED_MIGRATIONS
        .iter()
        .map(|(name, sql)| {
            let version: i64 = name
                .split('_')
                .next()
                .and_then(|v| v.parse().ok())
                .expect("embedded migration has invalid name");
            Migration {
                version,
                name: name.to_string(),
                sql: sql.to_string(),
                checksum: compute_checksum(sql),
            }
        })
        .collect()
}

/// Run all pending migrations (embedded at compile time).
///
/// The `_migrations_dir` parameter is kept for backward compatibility but ignored;
/// migrations are compiled into the binary and always available.
pub fn run_migrations(conn: &Connection, _migrations_dir: &Path) -> anyhow::Result<()> {
    run_embedded_migrations(conn)
}

/// Run all pending embedded migrations.
pub fn run_embedded_migrations(conn: &Connection) -> anyhow::Result<()> {
    // Create migrations tracking table
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );",
    )?;

    let migrations = load_embedded_migrations();

    for migration in &migrations {
        // Check if already applied
        let already_applied: bool = conn.query_row(
            "SELECT COUNT(*) > 0 FROM migrations WHERE version = ?1",
            [migration.version],
            |row| row.get(0),
        )?;

        if already_applied {
            // Verify checksum hasn't changed
            let stored_checksum: String = conn.query_row(
                "SELECT checksum FROM migrations WHERE version = ?1",
                [migration.version],
                |row| row.get(0),
            )?;

            if stored_checksum != migration.checksum {
                anyhow::bail!(
                    "Migration {} checksum mismatch! Expected {}, found {}. \
                     Migration files must not be modified after being applied.",
                    migration.name,
                    stored_checksum,
                    migration.checksum
                );
            }

            continue;
        }

        // Apply migration within a transaction so partial failure doesn't wedge the DB
        info!(version = migration.version, name = %migration.name, "Applying migration");
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(&migration.sql)?;

        // Record migration inside the same transaction
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        tx.execute(
            "INSERT INTO migrations (version, name, applied_at, checksum) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![migration.version, migration.name, now, migration.checksum],
        )?;
        tx.commit()?;

        info!(version = migration.version, name = %migration.name, "Migration applied successfully");
    }

    let count = migrations.len();
    info!(count = count, "All migrations up to date");
    Ok(())
}

/// Get list of applied migrations
pub fn get_applied_migrations(conn: &Connection) -> anyhow::Result<Vec<(i64, String, String)>> {
    let mut stmt =
        conn.prepare("SELECT version, name, applied_at FROM migrations ORDER BY version")?;
    let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_db_wal_mode() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");
        let conn = init_db(db_path.to_str().unwrap()).unwrap();

        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");

        let fk: i32 = conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert_eq!(fk, 1);

        let timeout: i32 = conn
            .query_row("PRAGMA busy_timeout", [], |row| row.get(0))
            .unwrap();
        assert_eq!(timeout, 5000);

        let sync: i32 = conn
            .query_row("PRAGMA synchronous", [], |row| row.get(0))
            .unwrap();
        assert_eq!(sync, 1); // NORMAL
    }

    #[test]
    fn test_compute_checksum() {
        let checksum = compute_checksum("SELECT 1;");
        assert!(!checksum.is_empty());
        assert_eq!(checksum.len(), 64); // SHA-256 hex
    }
}
