//! tilde-backup: incremental encrypted backups via restic.
//!
//! Shells out to the `restic` binary for deduplicated, encrypted backups
//! directly to B2/S3. Also supports restoring from legacy tar.gz archives.

pub mod restic;

use anyhow::{Context, Result, bail};
use flate2::read::GzDecoder;
use rusqlite::Connection;
use std::path::Path;
use tracing::info;

/// Restore directly from a tar.gz archive file (no DB required).
/// Used for migration or disaster recovery when restoring legacy backups.
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
pub fn post_restore_fixup(conn: &Connection) -> Result<PostRestoreReport> {
    let jobs_deleted = conn.execute("DELETE FROM jobs", []).unwrap_or(0);
    if jobs_deleted > 0 {
        info!(count = jobs_deleted, "Deleted stale jobs");
    }

    let thumbnails_reset = conn
        .execute("UPDATE photos SET thumbnail_256_generated = 0", [])
        .unwrap_or(0);
    if thumbnails_reset > 0 {
        info!(
            count = thumbnails_reset,
            "Reset thumbnail flags for regeneration"
        );
    }

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

#[derive(Debug, Default)]
pub struct PostRestoreReport {
    pub jobs_deleted: usize,
    pub thumbnails_reset: usize,
    pub fts_tables_dropped: usize,
    pub snapshots_cleared: usize,
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
}
