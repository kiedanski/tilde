//! Restic backup backend — incremental, deduplicated, encrypted backups.
//!
//! Shells out to the `restic` binary for all operations. Restic handles
//! deduplication, encryption, and direct upload to B2/S3.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::Command;
use tilde_core::config::BackupConfig;
use tracing::{info, warn};

/// Resolved restic configuration (env vars already read).
pub struct ResticConfig {
    pub binary: String,
    pub repository: String,
    pub password_file: String,
    pub b2_account_id: String,
    pub b2_account_key: String,
    pub keep_daily: u32,
    pub keep_weekly: u32,
    pub keep_monthly: u32,
}

impl ResticConfig {
    /// Build a ResticConfig by resolving env vars from BackupConfig.
    pub fn from_backup_config(cfg: &BackupConfig) -> Result<Self> {
        let repository = std::env::var(&cfg.repository_env).with_context(|| {
            format!(
                "Env var '{}' not set. Set it to e.g. 'b2:bucket-name:path'",
                cfg.repository_env
            )
        })?;

        if cfg.password_file.is_empty() {
            bail!("backup.password_file must be set (path to file containing restic password)");
        }

        if !Path::new(&cfg.password_file).exists() {
            bail!("Restic password file not found: {}", cfg.password_file);
        }

        let b2_account_id = std::env::var(&cfg.b2_account_id_env).unwrap_or_default();
        let b2_account_key = std::env::var(&cfg.b2_account_key_env).unwrap_or_default();

        Ok(Self {
            binary: cfg.binary.clone(),
            repository,
            password_file: cfg.password_file.clone(),
            b2_account_id,
            b2_account_key,
            keep_daily: cfg.keep_daily,
            keep_weekly: cfg.keep_weekly,
            keep_monthly: cfg.keep_monthly,
        })
    }
}

/// Snapshot info parsed from `restic snapshots --json`.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ResticSnapshot {
    pub short_id: String,
    pub time: String,
    pub hostname: String,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub tags: Option<Vec<String>>,
}

/// Build a Command with restic env vars set.
fn restic_cmd(config: &ResticConfig) -> Command {
    let mut cmd = Command::new(&config.binary);
    cmd.env("RESTIC_REPOSITORY", &config.repository);
    cmd.env("RESTIC_PASSWORD_FILE", &config.password_file);
    if !config.b2_account_id.is_empty() {
        cmd.env("B2_ACCOUNT_ID", &config.b2_account_id);
    }
    if !config.b2_account_key.is_empty() {
        cmd.env("B2_ACCOUNT_KEY", &config.b2_account_key);
    }
    cmd
}

/// Check if restic binary is available.
pub fn check(config: &ResticConfig) -> Result<()> {
    let output = Command::new(&config.binary)
        .arg("version")
        .output()
        .with_context(|| format!("Failed to run '{}' — is restic installed?", config.binary))?;

    if !output.status.success() {
        bail!("restic version check failed");
    }

    let version = String::from_utf8_lossy(&output.stdout);
    info!(version = %version.trim(), "Restic available");
    Ok(())
}

/// Initialize the restic repository (idempotent — safe to call if already initialized).
pub fn init(config: &ResticConfig) -> Result<()> {
    let output = restic_cmd(config)
        .args(["init", "--repository-version", "2"])
        .output()
        .context("Failed to run restic init")?;

    if output.status.success() {
        info!("Restic repository initialized");
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("already initialized") || stderr.contains("already exists") {
            info!("Restic repository already initialized");
        } else {
            bail!("restic init failed: {}", stderr);
        }
    }
    Ok(())
}

/// Run an incremental backup of the data directory.
///
/// 1. VACUUM INTO a temp copy of the SQLite DB (consistent snapshot)
/// 2. Run restic backup with the live DB excluded
/// 3. Clean up the temp DB copy
pub fn backup(
    config: &ResticConfig,
    data_dir: &Path,
    db_conn: &rusqlite::Connection,
) -> Result<()> {
    // 1. Create a consistent DB snapshot via VACUUM INTO
    let db_snapshot = data_dir.join(".tilde-backup.db");
    if db_snapshot.exists() {
        std::fs::remove_file(&db_snapshot)?;
    }
    db_conn
        .execute("VACUUM INTO ?1", [db_snapshot.to_str().unwrap_or_default()])
        .context("VACUUM INTO failed for restic backup")?;
    info!("Created consistent DB snapshot for backup");

    // 2. Run restic backup
    let data_dir_str = data_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Data dir path is not valid UTF-8"))?;

    let output = restic_cmd(config)
        .args(["backup", data_dir_str])
        .args(["--exclude", "backup"])
        .args(["--exclude", "_thumbnails"])
        .args(["--exclude", "tilde.db"])
        .args(["--exclude", "tilde.db-wal"])
        .args(["--exclude", "tilde.db-shm"])
        .args(["--exclude", "tilde.db-journal"])
        .args(["--exclude", "uploads"])
        .args(["--tag", "tilde"])
        .output()
        .context("Failed to run restic backup")?;

    // Clean up temp DB regardless of outcome
    let _ = std::fs::remove_file(&db_snapshot);

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic backup failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!(output = %stdout.trim(), "Restic backup completed");

    // Update kv_meta with last backup time
    let now_str = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db_conn.execute(
        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:last_run', ?1, ?2)",
        rusqlite::params![&now_str, &now_str],
    );

    Ok(())
}

/// List snapshots in the restic repository.
pub fn snapshots(config: &ResticConfig) -> Result<Vec<ResticSnapshot>> {
    let output = restic_cmd(config)
        .args(["snapshots", "--json"])
        .output()
        .context("Failed to run restic snapshots")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic snapshots failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    if stdout.trim().is_empty() || stdout.trim() == "null" {
        return Ok(Vec::new());
    }

    let snaps: Vec<ResticSnapshot> =
        serde_json::from_str(&stdout).context("Failed to parse restic snapshots JSON")?;
    Ok(snaps)
}

/// Apply retention policy and prune unreferenced data.
pub fn forget_and_prune(config: &ResticConfig) -> Result<()> {
    let output = restic_cmd(config)
        .args([
            "forget",
            "--prune",
            "--keep-daily",
            &config.keep_daily.to_string(),
            "--keep-weekly",
            &config.keep_weekly.to_string(),
            "--keep-monthly",
            &config.keep_monthly.to_string(),
            "--tag",
            "tilde",
        ])
        .output()
        .context("Failed to run restic forget")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic forget --prune failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!(output = %stdout.trim(), "Restic retention applied");
    Ok(())
}

/// Restore a snapshot to the target directory.
/// Use "latest" for the most recent snapshot.
pub fn restore(config: &ResticConfig, snapshot_id: &str, target_dir: &Path) -> Result<()> {
    let target_str = target_dir
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Target dir path is not valid UTF-8"))?;

    let output = restic_cmd(config)
        .args(["restore", snapshot_id, "--target", target_str])
        .output()
        .context("Failed to run restic restore")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic restore failed: {}", stderr);
    }

    info!(snapshot = %snapshot_id, target = %target_dir.display(), "Restic restore completed");
    Ok(())
}

/// Verify repository integrity.
pub fn check_repo(config: &ResticConfig) -> Result<()> {
    let output = restic_cmd(config)
        .arg("check")
        .output()
        .context("Failed to run restic check")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic check failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    info!(output = %stdout.trim(), "Restic repository check passed");
    Ok(())
}

/// Get repository stats as a displayable string.
pub fn stats(config: &ResticConfig) -> Result<String> {
    let output = restic_cmd(config)
        .args(["stats", "--json"])
        .output()
        .context("Failed to run restic stats")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("restic stats failed: {}", stderr);
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Post-restore fixup for restic backups.
///
/// Restic restores files preserving the original directory structure under target_dir.
/// The data will be at `target_dir/<original-data-dir-path>/...`.
/// The .tilde-backup.db needs to be renamed to tilde.db.
pub fn post_restore_rename_db(target_dir: &Path, original_data_dir: &Path) -> Result<()> {
    // Restic restores with the full path, so files end up at
    // target_dir/data/tilde/... (or whatever the original path was)
    let restored_root = target_dir.join(
        original_data_dir
            .strip_prefix("/")
            .unwrap_or(original_data_dir),
    );

    let backup_db = restored_root.join(".tilde-backup.db");
    let target_db = restored_root.join("tilde.db");

    if backup_db.exists() {
        if target_db.exists() {
            warn!("Both .tilde-backup.db and tilde.db exist after restore — replacing tilde.db");
            std::fs::remove_file(&target_db)?;
        }
        std::fs::rename(&backup_db, &target_db)
            .context("Failed to rename .tilde-backup.db to tilde.db")?;
        info!("Renamed .tilde-backup.db → tilde.db");
    } else if !target_db.exists() {
        warn!("No database found after restore — neither .tilde-backup.db nor tilde.db");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_restic_snapshots_json() {
        let json = r#"[
            {
                "short_id": "abc12345",
                "time": "2026-05-15T04:00:00.123456789+00:00",
                "hostname": "tilde-server",
                "paths": ["/data/tilde"],
                "tags": ["tilde"]
            }
        ]"#;
        let snaps: Vec<ResticSnapshot> = serde_json::from_str(json).unwrap();
        assert_eq!(snaps.len(), 1);
        assert_eq!(snaps[0].short_id, "abc12345");
        assert_eq!(snaps[0].hostname, "tilde-server");
        assert_eq!(snaps[0].paths, vec!["/data/tilde"]);
    }

    #[test]
    fn parse_empty_snapshots() {
        let json = "[]";
        let snaps: Vec<ResticSnapshot> = serde_json::from_str(json).unwrap();
        assert!(snaps.is_empty());
    }

    #[test]
    fn parse_null_snapshots() {
        // restic returns null for empty repos
        let json = "null";
        let result: Result<Vec<ResticSnapshot>, _> = serde_json::from_str(json);
        // null deserializes to None for Option, but not Vec — handle in snapshots()
        assert!(result.is_err());
    }

    #[test]
    fn config_resolution_missing_repo() {
        let cfg = BackupConfig::default();
        // Should fail because RESTIC_REPOSITORY env var isn't set
        let result = ResticConfig::from_backup_config(&cfg);
        assert!(result.is_err());
    }

    #[test]
    fn config_resolution_missing_password_file() {
        unsafe {
            std::env::set_var("RESTIC_REPOSITORY", "b2:test-bucket:test-path");
        }
        let cfg = BackupConfig::default();
        // Should fail because password_file is empty
        let result = ResticConfig::from_backup_config(&cfg);
        unsafe {
            std::env::remove_var("RESTIC_REPOSITORY");
        }
        assert!(result.is_err());
    }
}
