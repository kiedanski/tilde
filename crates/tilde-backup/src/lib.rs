//! tilde-backup: backup functionality
//!
//! Creates tar.gz snapshots of the data directory, tracks them in SQLite,
//! supports retention policies, pinning, verification, and restore.

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
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
/// Returns the snapshot ID on success.
pub fn create_snapshot(
    conn: &Connection,
    data_dir: &Path,
    backup_dir: &Path,
) -> Result<Snapshot> {
    std::fs::create_dir_all(backup_dir)?;

    let snapshot_id = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now();
    let created_at = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let filename = format!("snapshot-{}.tar.gz", now.strftime("%Y%m%d-%H%M%S"));
    let archive_path = backup_dir.join(&filename);

    info!(snapshot_id = %snapshot_id, archive = %archive_path.display(), "Creating backup snapshot");

    // Build tar.gz
    let archive_file = std::fs::File::create(&archive_path)
        .context("Failed to create archive file")?;
    let encoder = GzEncoder::new(archive_file, Compression::fast());
    let mut tar_builder = tar::Builder::new(encoder);

    let mut file_count: i64 = 0;

    // Back up key directories and files
    let items_to_backup = [
        "files", "photos", "calendars", "contacts", "mail",
        "collections", "tilde.db",
    ];

    for item in &items_to_backup {
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

    let encoder = tar_builder
        .into_inner()
        .context("Failed to finalize tar archive")?;
    encoder.finish().context("Failed to finish gzip compression")?;

    // Compute checksum of the archive
    let checksum = compute_file_sha256(&archive_path)?;

    let size_bytes = std::fs::metadata(&archive_path)?.len() as i64;

    let snapshot = Snapshot {
        id: snapshot_id,
        created_at: created_at.clone(),
        size_bytes,
        file_count,
        archive_path: archive_path.to_string_lossy().to_string(),
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
    let now_str = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
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

    let snapshots = stmt.query_map([], |row| {
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
    })?.collect::<Result<Vec<_>, _>>()?;

    Ok(snapshots)
}

/// Verify a snapshot's integrity by recomputing its checksum.
pub fn verify_snapshot(conn: &Connection, snapshot_id: &str) -> Result<bool> {
    let snapshot = get_snapshot(conn, snapshot_id)?;
    let path = Path::new(&snapshot.archive_path);

    if !path.exists() {
        bail!("Archive file not found: {}", snapshot.archive_path);
    }

    let current_checksum = compute_file_sha256(path)?;
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
pub fn verify_all_snapshots(conn: &Connection) -> Result<(usize, usize)> {
    let snapshots = list_snapshots(conn)?;
    let mut passed = 0;
    let mut failed = 0;

    for snapshot in &snapshots {
        let path = Path::new(&snapshot.archive_path);
        if !path.exists() {
            warn!(snapshot_id = %snapshot.id, "Archive file missing");
            failed += 1;
            continue;
        }
        let current_checksum = compute_file_sha256(path)?;
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
pub fn restore_snapshot(conn: &Connection, snapshot_id: &str, target_dir: &Path) -> Result<()> {
    let snapshot = get_snapshot(conn, snapshot_id)?;
    let archive_path = Path::new(&snapshot.archive_path);

    if !archive_path.exists() {
        bail!("Archive file not found: {}", snapshot.archive_path);
    }

    // Verify integrity before restore
    let checksum = compute_file_sha256(archive_path)?;
    if checksum != snapshot.checksum {
        bail!(
            "Checksum mismatch — archive may be corrupted (expected {}, got {})",
            snapshot.checksum,
            checksum
        );
    }

    std::fs::create_dir_all(target_dir)?;

    let archive_file = std::fs::File::open(archive_path)?;
    let decoder = GzDecoder::new(archive_file);
    let mut archive = tar::Archive::new(decoder);
    archive.unpack(target_dir).context("Failed to extract archive")?;

    info!(
        snapshot_id = %snapshot_id,
        target = %target_dir.display(),
        "Snapshot restored"
    );

    Ok(())
}

/// Apply retention policy: keep the specified number of snapshots per time class,
/// prune the rest (unless pinned).
pub fn apply_retention(
    conn: &Connection,
    hourly: u32,
    daily: u32,
    weekly: u32,
    monthly: u32,
) -> Result<Vec<String>> {
    let snapshots = list_snapshots(conn)?;
    let total = hourly + daily + weekly + monthly;

    // Simple retention: keep the most recent `total` snapshots plus any pinned ones
    let mut pruned = Vec::new();
    for (i, snapshot) in snapshots.iter().enumerate() {
        if snapshot.pinned {
            continue;
        }
        if i >= total as usize {
            // Prune this snapshot
            let path = Path::new(&snapshot.archive_path);
            if path.exists() {
                std::fs::remove_file(path)
                    .with_context(|| format!("Failed to delete archive {}", snapshot.archive_path))?;
            }
            conn.execute(
                "DELETE FROM backup_snapshots WHERE id = ?1",
                [&snapshot.id],
            )?;
            pruned.push(snapshot.id.clone());
            info!(snapshot_id = %snapshot.id, "Pruned old snapshot");
        }
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

        if src_path.is_dir() {
            count += append_dir_to_tar(builder, &src_path, &archive_name)?;
        } else {
            // Skip WAL/journal files (they're transient)
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if name_str.ends_with("-wal") || name_str.ends_with("-shm") || name_str.ends_with("-journal") {
                continue;
            }
            builder.append_path_with_name(&src_path, &archive_name)
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
