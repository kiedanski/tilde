//! SQLite database initialization and migration runner

use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::info;

/// Initialize SQLite database with required PRAGMAs
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

/// Load migrations from the migrations directory
fn load_migrations(migrations_dir: &Path) -> anyhow::Result<Vec<Migration>> {
    let mut migrations = Vec::new();

    if !migrations_dir.exists() {
        return Ok(migrations);
    }

    let mut entries: Vec<_> = std::fs::read_dir(migrations_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "sql"))
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let filename = entry.file_name().to_string_lossy().to_string();
        // Parse version from filename like "001_initial.sql"
        let version: i64 = filename
            .split('_')
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| anyhow::anyhow!("Invalid migration filename: {}", filename))?;

        let name = filename.trim_end_matches(".sql").to_string();
        let sql = std::fs::read_to_string(entry.path())?;
        let checksum = compute_checksum(&sql);

        migrations.push(Migration {
            version,
            name,
            sql,
            checksum,
        });
    }

    Ok(migrations)
}

/// Run all pending migrations from the migrations directory
pub fn run_migrations(conn: &Connection, migrations_dir: &Path) -> anyhow::Result<()> {
    // Create migrations tracking table
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS migrations (
            version INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            applied_at TEXT NOT NULL,
            checksum TEXT NOT NULL
        );",
    )?;

    let migrations = load_migrations(migrations_dir)?;

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

        // Apply migration
        info!(version = migration.version, name = %migration.name, "Applying migration");
        conn.execute_batch(&migration.sql)?;

        // Record migration
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO migrations (version, name, applied_at, checksum) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![migration.version, migration.name, now, migration.checksum],
        )?;

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
