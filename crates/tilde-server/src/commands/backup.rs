use tilde_backup::restic::ResticConfig;
use tilde_cli::BackupCommands;
use tilde_core::{config::Config, db};

pub async fn run_backup(config_path: Option<&str>, command: BackupCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let data_dir = config.data_dir();
    let restic_config = ResticConfig::from_backup_config(&config.backup)?;

    match command {
        BackupCommands::Status => {
            println!("Backup Status");
            println!("=============");
            println!("Backup enabled: {}", config.backup.enabled);
            println!("Schedule: {}", config.backup.schedule);
            println!(
                "Retention: daily={}, weekly={}, monthly={}",
                config.backup.keep_daily, config.backup.keep_weekly, config.backup.keep_monthly,
            );
            println!("Repository: {}", restic_config.repository);

            match tilde_backup::restic::snapshots(&restic_config) {
                Ok(snaps) => {
                    println!("Snapshots: {}", snaps.len());
                    if let Some(latest) = snaps.last() {
                        println!("Latest: {} ({})", latest.short_id, latest.time);
                    }
                }
                Err(e) => println!("Snapshots: error ({})", e),
            }

            let last_run: Option<String> = conn
                .query_row(
                    "SELECT value FROM kv_meta WHERE key = 'backup:last_run'",
                    [],
                    |row| row.get(0),
                )
                .ok();
            let next_scheduled: Option<String> = conn
                .query_row(
                    "SELECT value FROM kv_meta WHERE key = 'backup:next_scheduled'",
                    [],
                    |row| row.get(0),
                )
                .ok();

            println!("Last backup: {}", last_run.as_deref().unwrap_or("never"));
            println!(
                "Next scheduled: {}",
                next_scheduled.as_deref().unwrap_or("not scheduled")
            );
        }
        BackupCommands::Now => {
            println!("Creating backup...");
            tilde_backup::restic::backup(&restic_config, &data_dir, &conn)?;
            println!("Backup completed (incremental, encrypted)");

            println!("Applying retention policy...");
            tilde_backup::restic::forget_and_prune(&restic_config)?;
            println!("Done");
        }
        BackupCommands::List => {
            let snaps = tilde_backup::restic::snapshots(&restic_config)?;

            if snaps.is_empty() {
                println!("No snapshots found.");
                return Ok(());
            }

            println!("Snapshots ({} total)", snaps.len());
            println!("{:<12} {:<32} {:<20}", "ID", "Time", "Hostname");
            println!("{}", "-".repeat(64));
            for s in &snaps {
                println!("{:<12} {:<32} {:<20}", s.short_id, s.time, s.hostname);
            }
        }
        BackupCommands::Verify => {
            println!("Verifying repository integrity...");
            tilde_backup::restic::check_repo(&restic_config)?;
            println!("Repository integrity verified.");
        }
    }
    Ok(())
}

pub async fn run_restore(
    config_path: Option<&str>,
    from: &str,
    snapshot_id: &str,
    target_path: &str,
) -> anyhow::Result<()> {
    let target_dir = std::path::Path::new(target_path);

    // If --from is a file path, restore from a legacy tar.gz archive
    let from_path = std::path::Path::new(from);
    if from_path.is_file() {
        println!("Restoring from archive {} to {}...", from, target_path);
        tilde_backup::restore_from_archive(from_path, target_dir)?;

        let restored_db = target_dir.join("tilde.db");
        if restored_db.exists() {
            println!("Running post-restore fixup...");
            let conn = db::init_db(restored_db.to_str().unwrap())?;
            let migrations_dir = tilde_cli::find_migrations_dir();
            db::run_migrations(&conn, &migrations_dir)?;
            let report = tilde_backup::post_restore_fixup(&conn)?;
            println!(
                "Fixup: {} jobs deleted, {} thumbnail flags reset, {} FTS tables dropped",
                report.jobs_deleted, report.thumbnails_reset, report.fts_tables_dropped,
            );
        }

        println!("Restore completed to {}", target_path);
        return Ok(());
    }

    // Restic restore
    let config = Config::load(config_path)?;
    let restic_config = ResticConfig::from_backup_config(&config.backup)?;

    let snap_id = if snapshot_id.is_empty() || snapshot_id == "latest" {
        "latest"
    } else {
        snapshot_id
    };

    println!("Restoring from restic (snapshot: {})...", snap_id);
    tilde_backup::restic::restore(&restic_config, snap_id, target_dir)?;

    // Rename .tilde-backup.db -> tilde.db
    let data_dir = config.data_dir();
    tilde_backup::restic::post_restore_rename_db(target_dir, &data_dir)?;

    // Run fixup on the restored DB
    let restored_root = target_dir.join(data_dir.strip_prefix("/").unwrap_or(&data_dir));
    let restored_db = restored_root.join("tilde.db");
    if restored_db.exists() {
        println!("Running post-restore fixup...");
        let conn = db::init_db(restored_db.to_str().unwrap())?;
        let migrations_dir = tilde_cli::find_migrations_dir();
        db::run_migrations(&conn, &migrations_dir)?;
        let report = tilde_backup::post_restore_fixup(&conn)?;
        println!(
            "Fixup: {} jobs deleted, {} thumbnail flags reset, {} FTS tables dropped",
            report.jobs_deleted, report.thumbnails_reset, report.fts_tables_dropped,
        );
    }

    println!("Restore completed to {}", target_path);
    Ok(())
}
