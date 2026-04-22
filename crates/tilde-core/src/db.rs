//! SQLite database initialization and migration runner

use rusqlite::Connection;
use tracing::info;

/// Initialize SQLite database with required PRAGMAs
pub fn init_db(path: &str) -> anyhow::Result<Connection> {
    let conn = Connection::open(path)?;

    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA busy_timeout=5000;
         PRAGMA foreign_keys=ON;
         PRAGMA mmap_size=33554432;"
    )?;

    info!(path = path, "Database initialized with WAL mode");
    Ok(conn)
}

/// Run all pending migrations
pub fn run_migrations(conn: &Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );"
    )?;
    info!("Migration table ready");
    Ok(())
}
