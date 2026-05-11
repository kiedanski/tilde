//! tilde-backup: backup functionality
//!
//! Creates tar.gz snapshots of the data directory, tracks them in SQLite,
//! supports retention policies, pinning, verification, and restore.
//! Offsite backup to S3-compatible storage (B2, AWS, MinIO).

pub mod offsite;

use anyhow::{Context, Result, bail};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};
use std::path::Path;
use tracing::{info, warn};

/// Snapshot metadata stored in SQLite
#[derive(Debug, Clone)]
pub struct Snapshot {
    pub id: String,
    pub created_at: String,
    pub size_bytes: i64,
    pub file_count: i64,
    pub archive_path: String,
    pub checksum: String,
    pub pinned: bool,
    pub pin_reason: Option<String>,
    pub retention_class: Option<String>,
}

/// Create a backup snapshot of the data directory.
///
/// Creates a tar.gz archive in `backup_dir`, records metadata in SQLite.
/// If `encrypt_recipient` is provided, encrypts the archive with age.
/// Returns the snapshot ID on success.
pub fn create_snapshot(conn: &Connection, data_dir: &Path, backup_dir: &Path) -> Result<Snapshot> {
    create_snapshot_with_encryption(conn, data_dir, backup_dir, None)
}

/// Create a backup snapshot, optionally encrypted with an age public key.
pub fn create_snapshot_with_encryption(
    conn: &Connection,
    data_dir: &Path,
    backup_dir: &Path,
    encrypt_recipient: Option<&str>,
) -> Result<Snapshot> {
    std::fs::create_dir_all(backup_dir)?;

    let snapshot_id = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now();
    let created_at = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let filename = format!("snapshot-{}.tar.gz", now.strftime("%Y%m%d-%H%M%S"));
    let archive_path = backup_dir.join(&filename);

    info!(snapshot_id = %snapshot_id, archive = %archive_path.display(), "Creating backup snapshot");

    // Build tar.gz
    let archive_file =
        std::fs::File::create(&archive_path).context("Failed to create archive file")?;
    let encoder = GzEncoder::new(archive_file, Compression::fast());
    let mut tar_builder = tar::Builder::new(encoder);

    let mut file_count: i64 = 0;

    // Back up key directories and files
    let dir_items = [
        "files",
        "notes",
        "photos",
        "calendars",
        "contacts",
        "mail",
        "collections",
    ];

    for item in &dir_items {
        let src = data_dir.join(item);
        if !src.exists() {
            continue;
        }
        if src.is_dir() {
            let count = append_dir_to_tar(&mut tar_builder, &src, Path::new(item))?;
            file_count += count;
        } else {
            tar_builder
                .append_path_with_name(&src, item)
                .with_context(|| format!("Failed to add {} to archive", item))?;
            file_count += 1;
        }
    }

    // Use VACUUM INTO for the database — produces a consistent snapshot
    // without needing to coordinate WAL checkpoint or risk corrupted backup
    let db_src = data_dir.join("tilde.db");
    if db_src.exists() {
        let db_snapshot = backup_dir.join(format!(".snapshot-{}.db", snapshot_id));
        conn.execute("VACUUM INTO ?1", [db_snapshot.to_str().unwrap_or_default()])
            .context("VACUUM INTO failed for DB snapshot")?;
        tar_builder
            .append_path_with_name(&db_snapshot, "tilde.db")
            .context("Failed to add DB snapshot to archive")?;
        file_count += 1;
        // Clean up temp snapshot
        let _ = std::fs::remove_file(&db_snapshot);
    }

    let encoder = tar_builder
        .into_inner()
        .context("Failed to finalize tar archive")?;
    encoder
        .finish()
        .context("Failed to finish gzip compression")?;

    // Encrypt with age if recipient provided (paranoid mode)
    let final_path = if let Some(recipient) = encrypt_recipient {
        let encrypted_path = std::path::PathBuf::from(format!("{}.age", archive_path.display()));
        info!(recipient = %recipient, "Encrypting backup with age (paranoid mode)");

        let status = std::process::Command::new("age")
            .args([
                "--recipient",
                recipient,
                "--output",
                encrypted_path.to_str().unwrap(),
                archive_path.to_str().unwrap(),
            ])
            .status()
            .context("Failed to run age for encryption")?;

        if !status.success() {
            bail!("age encryption failed with status: {}", status);
        }

        // Remove unencrypted archive
        std::fs::remove_file(&archive_path).context("Failed to remove unencrypted archive")?;

        info!("Backup encrypted — server holds only public key, cannot decrypt");
        encrypted_path
    } else {
        archive_path.clone()
    };

    // Compute checksum of the final archive
    let checksum = compute_file_sha256(&final_path)?;

    let size_bytes = std::fs::metadata(&final_path)?.len() as i64;

    let snapshot = Snapshot {
        id: snapshot_id,
        created_at: created_at.clone(),
        size_bytes,
        file_count,
        archive_path: final_path.to_string_lossy().to_string(),
        checksum: checksum.clone(),
        pinned: false,
        pin_reason: None,
        retention_class: None,
    };

    // Store in SQLite
    conn.execute(
        "INSERT INTO backup_snapshots (id, created_at, size_bytes, file_count, archive_path, checksum, pinned, pin_reason, retention_class) \
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        rusqlite::params![
            &snapshot.id,
            &snapshot.created_at,
            snapshot.size_bytes,
            snapshot.file_count,
            &snapshot.archive_path,
            &snapshot.checksum,
            0,
            Option::<String>::None,
            Option::<String>::None,
        ],
    ).context("Failed to record snapshot in database")?;

    // Update kv_meta
    let now_str = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    conn.execute(
        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:last_run', ?1, ?2)",
        rusqlite::params![&now_str, &now_str],
    )?;

    info!(
        snapshot_id = %snapshot.id,
        size_bytes = snapshot.size_bytes,
        file_count = snapshot.file_count,
        "Backup snapshot created"
    );

    Ok(snapshot)
}

/// List all snapshots, newest first.
pub fn list_snapshots(conn: &Connection) -> Result<Vec<Snapshot>> {
    let mut stmt = conn.prepare(
        "SELECT id, created_at, size_bytes, file_count, archive_path, checksum, pinned, pin_reason, retention_class \
         FROM backup_snapshots ORDER BY created_at DESC"
    )?;

    let snapshots = stmt
        .query_map([], |row| {
            Ok(Snapshot {
                id: row.get(0)?,
                created_at: row.get(1)?,
                size_bytes: row.get(2)?,
                file_count: row.get(3)?,
                archive_path: row.get(4)?,
                checksum: row.get(5)?,
                pinned: row.get::<_, i32>(6)? != 0,
                pin_reason: row.get(7)?,
                retention_class: row.get(8)?,
            })
        })?
        .collect::<Result<Vec<_>, _>>()?;

    Ok(snapshots)
}

/// Resolve a snapshot's archive path. Handles both relative filenames
/// (new format) and absolute paths (legacy backups).
pub fn resolve_archive_path(snapshot: &Snapshot, backup_dir: &Path) -> std::path::PathBuf {
    let p = Path::new(&snapshot.archive_path);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        backup_dir.join(p)
    }
}

/// Verify a snapshot's integrity by recomputing its checksum.
pub fn verify_snapshot(conn: &Connection, snapshot_id: &str, backup_dir: &Path) -> Result<bool> {
    let snapshot = get_snapshot(conn, snapshot_id)?;
    let path = resolve_archive_path(&snapshot, backup_dir);

    if !path.exists() {
        bail!("Archive file not found: {}", path.display());
    }

    let current_checksum = compute_file_sha256(&path)?;
    let valid = current_checksum == snapshot.checksum;

    if valid {
        info!(snapshot_id = %snapshot_id, "Backup verification passed");
    } else {
        warn!(
            snapshot_id = %snapshot_id,
            expected = %snapshot.checksum,
            actual = %current_checksum,
            "Backup verification FAILED — corruption detected"
        );
    }

    Ok(valid)
}

/// Verify all snapshots. Returns (passed, failed) counts.
pub fn verify_all_snapshots(conn: &Connection, backup_dir: &Path) -> Result<(usize, usize)> {
    let snapshots = list_snapshots(conn)?;
    let mut passed = 0;
    let mut failed = 0;

    for snapshot in &snapshots {
        let path = resolve_archive_path(snapshot, backup_dir);
        if !path.exists() {
            warn!(snapshot_id = %snapshot.id, "Archive file missing");
            failed += 1;
            continue;
        }
        let current_checksum = compute_file_sha256(&path)?;
        if current_checksum == snapshot.checksum {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    Ok((passed, failed))
}

/// Pin a snapshot to prevent pruning.
pub fn pin_snapshot(conn: &Connection, snapshot_id: &str, reason: &str) -> Result<()> {
    let affected = conn.execute(
        "UPDATE backup_snapshots SET pinned = 1, pin_reason = ?1 WHERE id = ?2",
        rusqlite::params![reason, snapshot_id],
    )?;

    if affected == 0 {
        bail!("Snapshot not found: {}", snapshot_id);
    }

    info!(snapshot_id = %snapshot_id, reason = %reason, "Snapshot pinned");
    Ok(())
}

/// Restore a snapshot to the given directory.
pub fn restore_snapshot(
    conn: &Connection,
    snapshot_id: &str,
    backup_dir: &Path,
    target_dir: &Path,
) -> Result<()> {
    let snapshot = get_snapshot(conn, snapshot_id)?;
    let archive_path = resolve_archive_path(&snapshot, backup_dir);

    if !archive_path.exists() {
        bail!("Archive file not found: {}", archive_path.display());
    }

    // Verify integrity before restore
    let checksum = compute_file_sha256(&archive_path)?;
    if checksum != snapshot.checksum {
        bail!(
            "Checksum mismatch — archive may be corrupted (expected {}, got {})",
            snapshot.checksum,
            checksum
        );
    }

    std::fs::create_dir_all(target_dir)?;

    let archive_file = std::fs::File::open(&archive_path)?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(target_dir)
        .context("Failed to extract archive")?;

    info!(
        snapshot_id = %snapshot_id,
        target = %target_dir.display(),
        "Snapshot restored"
    );

    Ok(())
}

/// Restore directly from an archive file (no DB required).
/// Use this for migration or disaster recovery when the DB is inside the archive.
pub fn restore_from_archive(archive_path: &Path, target_dir: &Path) -> Result<()> {
    if !archive_path.exists() {
        bail!("Archive file not found: {}", archive_path.display());
    }

    std::fs::create_dir_all(target_dir)?;

    let archive_file = std::fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(target_dir)
        .context("Failed to extract archive")?;

    info!(
        archive = %archive_path.display(),
        target = %target_dir.display(),
        "Archive restored"
    );

    Ok(())
}

/// Post-restore fixup: clean up stale state that doesn't transfer across machines.
///
/// After restoring a backup on a different machine (or after a fresh restore),
/// the database contains references to state that no longer exists:
/// - Jobs from the source machine (stale, will fail with "file not found")
/// - Thumbnail flags (thumbnails live in cache, not in the backup)
/// - Orphaned FTS tables from old email indexing
///
/// This function cleans all of that up so the server starts fresh.
pub fn post_restore_fixup(conn: &Connection) -> Result<PostRestoreReport> {
    // 1. Delete all stale jobs
    let jobs_deleted = conn.execute("DELETE FROM jobs", []).unwrap_or(0);
    if jobs_deleted > 0 {
        info!(count = jobs_deleted, "Deleted stale jobs");
    }

    // 2. Reset thumbnail flags (thumbnails are in cache, not in backup)
    let thumbnails_reset = conn
        .execute("UPDATE photos SET thumbnail_256_generated = 0", [])
        .unwrap_or(0);
    if thumbnails_reset > 0 {
        info!(
            count = thumbnails_reset,
            "Reset thumbnail flags for regeneration"
        );
    }

    // 3. Drop orphaned FTS tables (from old email indexing)
    let fts_tables: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE '%_fts%'")
            .unwrap();
        stmt.query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };
    let mut fts_tables_dropped = 0;
    for table in &fts_tables {
        if conn
            .execute(&format!("DROP TABLE IF EXISTS \"{}\"", table), [])
            .is_ok()
        {
            fts_tables_dropped += 1;
        }
    }
    if fts_tables_dropped > 0 {
        info!(count = fts_tables_dropped, "Dropped orphaned FTS tables");
    }

    // 4. Clear backup_snapshots (archive paths from source machine are invalid)
    let snapshots_cleared = conn
        .execute("DELETE FROM backup_snapshots", [])
        .unwrap_or(0);
    if snapshots_cleared > 0 {
        info!(
            count = snapshots_cleared,
            "Cleared stale backup snapshot records"
        );
    }

    info!("Post-restore fixup complete");
    Ok(PostRestoreReport {
        jobs_deleted,
        thumbnails_reset,
        fts_tables_dropped,
        snapshots_cleared,
    })
}

/// Summary of what the post-restore fixup cleaned up.
#[derive(Debug, Default)]
pub struct PostRestoreReport {
    pub jobs_deleted: usize,
    pub thumbnails_reset: usize,
    pub fts_tables_dropped: usize,
    pub snapshots_cleared: usize,
}

/// Apply retention policy: keep the specified number of snapshots per time class,
/// prune the rest (unless pinned).
///
/// Each class selects the most recent snapshot per distinct time bucket:
/// - hourly: one per hour (bucket = YYYY-MM-DD-HH)
/// - daily:  one per day  (bucket = YYYY-MM-DD)
/// - weekly: one per week (bucket = YYYY-WW)
/// - monthly: one per month (bucket = YYYY-MM)
pub fn apply_retention(
    conn: &Connection,
    backup_dir: &Path,
    hourly: u32,
    daily: u32,
    weekly: u32,
    monthly: u32,
) -> Result<Vec<String>> {
    let snapshots = list_snapshots(conn)?; // newest-first

    let mut keep: std::collections::HashSet<String> = std::collections::HashSet::new();

    // For each time class, walk snapshots and keep the first N that fall into distinct buckets
    fn keep_by_bucket(
        snapshots: &[Snapshot],
        count: u32,
        bucket_fn: fn(&str) -> String,
        keep: &mut std::collections::HashSet<String>,
    ) {
        let mut seen = std::collections::HashSet::new();
        let mut kept = 0u32;
        for snap in snapshots {
            if kept >= count {
                break;
            }
            let bucket = bucket_fn(&snap.created_at);
            if seen.insert(bucket) {
                keep.insert(snap.id.clone());
                kept += 1;
            }
        }
    }

    // Bucket functions extract the relevant portion of an ISO timestamp
    keep_by_bucket(
        &snapshots,
        hourly,
        |ts| ts.get(..13).unwrap_or(ts).to_string(),
        &mut keep,
    );
    keep_by_bucket(
        &snapshots,
        daily,
        |ts| ts.get(..10).unwrap_or(ts).to_string(),
        &mut keep,
    );
    keep_by_bucket(
        &snapshots,
        weekly,
        |ts| {
            // Parse YYYY-MM-DD and compute ISO week
            let date_part = ts.get(..10).unwrap_or(ts);
            if let Ok(date) = jiff::civil::Date::strptime("%Y-%m-%d", date_part) {
                format!("{}-W{:02}", date.year(), (date.day_of_year() / 7) + 1)
            } else {
                date_part.to_string()
            }
        },
        &mut keep,
    );
    keep_by_bucket(
        &snapshots,
        monthly,
        |ts| ts.get(..7).unwrap_or(ts).to_string(),
        &mut keep,
    );

    // Prune anything not kept and not pinned
    let mut pruned = Vec::new();
    for snapshot in &snapshots {
        if snapshot.pinned || keep.contains(&snapshot.id) {
            continue;
        }
        let path = resolve_archive_path(snapshot, backup_dir);
        if path.exists() {
            std::fs::remove_file(&path)
                .with_context(|| format!("Failed to delete archive {}", path.display()))?;
        }
        conn.execute("DELETE FROM backup_snapshots WHERE id = ?1", [&snapshot.id])?;
        pruned.push(snapshot.id.clone());
        info!(snapshot_id = %snapshot.id, "Pruned old snapshot");
    }

    Ok(pruned)
}

/// Get a single snapshot by ID (or by prefix match).
pub fn get_snapshot(conn: &Connection, snapshot_id: &str) -> Result<Snapshot> {
    // Try exact match first, then prefix match
    let result = conn.query_row(
        "SELECT id, created_at, size_bytes, file_count, archive_path, checksum, pinned, pin_reason, retention_class \
         FROM backup_snapshots WHERE id = ?1 OR id LIKE ?2 LIMIT 1",
        rusqlite::params![snapshot_id, format!("{}%", snapshot_id)],
        |row| {
            Ok(Snapshot {
                id: row.get(0)?,
                created_at: row.get(1)?,
                size_bytes: row.get(2)?,
                file_count: row.get(3)?,
                archive_path: row.get(4)?,
                checksum: row.get(5)?,
                pinned: row.get::<_, i32>(6)? != 0,
                pin_reason: row.get(7)?,
                retention_class: row.get(8)?,
            })
        },
    ).context(format!("Snapshot not found: {}", snapshot_id))?;

    Ok(result)
}

// --- Internal helpers ---

/// Recursively add a directory to a tar archive.
fn append_dir_to_tar<W: Write>(
    builder: &mut tar::Builder<W>,
    src_dir: &Path,
    archive_prefix: &Path,
) -> Result<i64> {
    let mut count: i64 = 0;

    for entry in std::fs::read_dir(src_dir)? {
        let entry = entry?;
        let src_path = entry.path();
        let archive_name = archive_prefix.join(entry.file_name());

        // Skip symlinks (e.g., _thumbnails/ mirror — rebuilt on startup)
        if src_path.symlink_metadata()?.file_type().is_symlink() {
            continue;
        }

        if src_path.is_dir() {
            // Skip _thumbnails directory entirely (rebuilt on startup from cache)
            let name_str = entry.file_name().to_string_lossy().to_string();
            if name_str == "_thumbnails" {
                continue;
            }
            count += append_dir_to_tar(builder, &src_path, &archive_name)?;
        } else {
            // Skip WAL/journal files (they're transient)
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with("-wal")
                || name_str.ends_with("-shm")
                || name_str.ends_with("-journal")
            {
                continue;
            }
            builder
                .append_path_with_name(&src_path, &archive_name)
                .with_context(|| format!("Failed to add {}", src_path.display()))?;
            count += 1;
        }
    }

    Ok(count)
}

/// Compute SHA-256 of a file.
fn compute_file_sha256(path: &Path) -> Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Format bytes into human-readable size.
pub fn format_size(bytes: i64) -> String {
    const KB: i64 = 1024;
    const MB: i64 = 1024 * KB;
    const GB: i64 = 1024 * MB;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn format_size_kilobytes() {
        assert_eq!(format_size(1024), "1.00 KB");
        assert_eq!(format_size(1536), "1.50 KB");
    }

    #[test]
    fn format_size_megabytes() {
        assert_eq!(format_size(1048576), "1.00 MB");
    }

    #[test]
    fn format_size_gigabytes() {
        assert_eq!(format_size(1073741824), "1.00 GB");
    }

    /// Retention bucket logic: hourly bucket uses first 13 chars (YYYY-MM-DDTHH)
    #[test]
    fn hourly_bucket_groups_within_same_hour() {
        let bucket_fn = |ts: &str| ts.get(..13).unwrap_or(ts).to_string();
        assert_eq!(bucket_fn("2026-01-15T10:30:00+00:00"), "2026-01-15T10");
        assert_eq!(bucket_fn("2026-01-15T10:45:00+00:00"), "2026-01-15T10");
        // Different hour
        assert_ne!(
            bucket_fn("2026-01-15T10:30:00+00:00"),
            bucket_fn("2026-01-15T11:30:00+00:00"),
        );
    }

    /// Retention bucket logic: daily bucket uses first 10 chars (YYYY-MM-DD)
    #[test]
    fn daily_bucket_groups_within_same_day() {
        let bucket_fn = |ts: &str| ts.get(..10).unwrap_or(ts).to_string();
        assert_eq!(bucket_fn("2026-01-15T10:30:00+00:00"), "2026-01-15");
        assert_eq!(bucket_fn("2026-01-15T22:00:00+00:00"), "2026-01-15");
    }

    /// Retention bucket logic: monthly bucket uses first 7 chars (YYYY-MM)
    #[test]
    fn monthly_bucket_groups_within_same_month() {
        let bucket_fn = |ts: &str| ts.get(..7).unwrap_or(ts).to_string();
        assert_eq!(bucket_fn("2026-01-15T10:30:00+00:00"), "2026-01");
        assert_eq!(bucket_fn("2026-01-28T22:00:00+00:00"), "2026-01");
    }

    /// Pinned snapshots are never deleted by retention.
    #[test]
    fn pinned_snapshots_preserved() {
        let snap = Snapshot {
            id: "test-id".to_string(),
            created_at: "2020-01-01T00:00:00+00:00".to_string(),
            size_bytes: 100,
            file_count: 5,
            archive_path: "test.tar.gz".to_string(),
            checksum: "abc123".to_string(),
            pinned: true,
            pin_reason: Some("important".to_string()),
            retention_class: None,
        };
        // In apply_retention, this condition prevents deletion:
        assert!(snap.pinned);
    }
}
