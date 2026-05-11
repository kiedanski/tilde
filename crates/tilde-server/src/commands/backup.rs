use tilde_cli::BackupCommands;
use tilde_core::{config::Config, db};

pub async fn run_backup(config_path: Option<&str>, command: BackupCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let data_dir = config.data_dir();
    let backup_dir = data_dir.join("backup");

    match command {
        BackupCommands::Status => {
            println!("Backup Status");
            println!("=============");
            println!("Backup enabled: {}", config.backup.enabled);
            println!("Schedule: {}", config.backup.schedule);
            println!(
                "Retention: hourly={}, daily={}, weekly={}, monthly={}",
                config.backup.local_retention.hourly,
                config.backup.local_retention.daily,
                config.backup.local_retention.weekly,
                config.backup.local_retention.monthly,
            );

            // Read last run and next scheduled from kv_meta
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

            // Show snapshot count
            let snapshots = tilde_backup::list_snapshots(&conn)?;
            println!("Snapshots: {}", snapshots.len());

            if !config.backup.offsite.is_empty() {
                println!("\nOffsite destinations:");
                for dest in &config.backup.offsite {
                    println!(
                        "  - {} (type: {}, schedule: {})",
                        dest.name, dest.r#type, dest.schedule
                    );
                }
            }
        }
        BackupCommands::Now { offsite } => {
            println!("Creating backup snapshot...");
            let encrypt_recipient = if config.backup.encrypt_recipient.is_empty() {
                None
            } else {
                Some(config.backup.encrypt_recipient.as_str())
            };
            let snapshot = tilde_backup::create_snapshot_with_encryption(
                &conn,
                &data_dir,
                &backup_dir,
                encrypt_recipient,
            )?;
            if encrypt_recipient.is_some() {
                println!("  Encrypted with age (paranoid mode — server cannot decrypt)");
            }
            println!("Snapshot created successfully:");
            println!("  ID:         {}", snapshot.id);
            println!("  Created:    {}", snapshot.created_at);
            println!(
                "  Size:       {}",
                tilde_backup::format_size(snapshot.size_bytes)
            );
            println!("  Files:      {}", snapshot.file_count);
            println!("  Checksum:   {}", &snapshot.checksum[..16]);

            // Upload to offsite if requested
            if let Some(dest_name) = offsite {
                let offsite_cfg = config
                    .backup
                    .offsite
                    .iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name)
                    })?;

                let s3_config = tilde_backup::offsite::OffsiteConfig::from_config(offsite_cfg)?;
                println!("Uploading to offsite destination '{}'...", dest_name);
                let backup_dir = config.data_dir().join("backup");
                let remote_key =
                    tilde_backup::offsite::upload_snapshot(&s3_config, &snapshot, &backup_dir)
                        .await?;
                println!("  Uploaded to: {}", remote_key);
            }

            // Apply retention policy
            let retention = &config.backup.local_retention;
            let pruned = tilde_backup::apply_retention(
                &conn,
                &backup_dir,
                retention.hourly,
                retention.daily,
                retention.weekly,
                retention.monthly,
            )?;
            if !pruned.is_empty() {
                println!("  Pruned {} old snapshot(s)", pruned.len());
            }
        }
        BackupCommands::List { offsite } => {
            if let Some(dest_name) = offsite {
                let offsite_cfg = config
                    .backup
                    .offsite
                    .iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name)
                    })?;

                let s3_config = tilde_backup::offsite::OffsiteConfig::from_config(offsite_cfg)?;
                println!("Listing remote snapshots from '{}'...", dest_name);
                let objects = tilde_backup::offsite::list_remote_snapshots(&s3_config).await?;

                if objects.is_empty() {
                    println!("No remote snapshots found.");
                    return Ok(());
                }

                println!("Remote Snapshots ({} total)", objects.len());
                println!("=============");
                println!("{:<50} {:>12} Last Modified", "Key", "Size");
                println!("{}", "-".repeat(80));
                for obj in &objects {
                    println!(
                        "{:<50} {:>12} {}",
                        &obj.key,
                        tilde_backup::format_size(obj.size),
                        &obj.last_modified,
                    );
                }
                return Ok(());
            }

            let snapshots = tilde_backup::list_snapshots(&conn)?;
            if snapshots.is_empty() {
                println!("No snapshots found.");
                return Ok(());
            }

            println!("Backup Snapshots ({} total)", snapshots.len());
            println!("=============");
            println!(
                "{:<38} {:<26} {:>10} {:>6} Pinned",
                "ID", "Created", "Size", "Files"
            );
            println!("{}", "-".repeat(90));

            for s in &snapshots {
                let pin_mark = if s.pinned {
                    format!("YES ({})", s.pin_reason.as_deref().unwrap_or(""))
                } else {
                    String::new()
                };
                println!(
                    "{:<38} {:<26} {:>10} {:>6} {}",
                    &s.id[..36.min(s.id.len())],
                    &s.created_at,
                    tilde_backup::format_size(s.size_bytes),
                    s.file_count,
                    pin_mark,
                );
            }
        }
        BackupCommands::Verify { offsite } => {
            if let Some(dest_name) = offsite {
                // Verify offsite: check that remote snapshots exist and are listed
                let offsite_cfg = config
                    .backup
                    .offsite
                    .iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name)
                    })?;

                let s3_config = tilde_backup::offsite::OffsiteConfig::from_config(offsite_cfg)?;
                println!("Verifying offsite snapshots in '{}'...", dest_name);
                let objects = tilde_backup::offsite::list_remote_snapshots(&s3_config).await?;

                if objects.is_empty() {
                    println!("No remote snapshots found — nothing to verify.");
                } else {
                    println!(
                        "Found {} remote snapshot(s) — offsite storage accessible",
                        objects.len()
                    );
                    for obj in &objects {
                        println!(
                            "  {} ({}, {})",
                            obj.key,
                            tilde_backup::format_size(obj.size),
                            obj.last_modified
                        );
                    }
                }
                return Ok(());
            }

            let snapshots = tilde_backup::list_snapshots(&conn)?;
            if snapshots.is_empty() {
                println!("No snapshots to verify.");
                return Ok(());
            }

            println!("Verifying {} snapshot(s)...", snapshots.len());
            let (passed, failed) = tilde_backup::verify_all_snapshots(&conn, &backup_dir)?;
            println!("Results: {} passed, {} failed", passed, failed);

            if failed > 0 {
                println!("WARNING: Some snapshots failed integrity verification!");
                std::process::exit(1);
            } else {
                println!("All snapshots verified successfully.");
            }
        }
        BackupCommands::Pin {
            snapshot_id,
            reason,
        } => {
            tilde_backup::pin_snapshot(&conn, &snapshot_id, &reason)?;
            println!("Snapshot {} pinned (reason: {})", snapshot_id, reason);
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

    // If --from is a file path, restore directly without needing a DB
    let from_path = std::path::Path::new(from);
    if from_path.is_file() {
        println!("Restoring from archive {} to {}...", from, target_path);
        tilde_backup::restore_from_archive(from_path, target_dir)?;

        // Run post-restore fixup on the restored database
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

        println!("Restore completed successfully to {}", target_path);
        return Ok(());
    }

    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    if from != "local" {
        let offsite_cfg = config
            .backup
            .offsite
            .iter()
            .find(|d| d.name == from)
            .ok_or_else(|| anyhow::anyhow!("Offsite destination '{}' not found in config", from))?;

        println!(
            "Offsite restore from '{}' is not yet supported — download manually and use --from local",
            from
        );
        let _ = offsite_cfg;
        return Ok(());
    }

    println!("Restoring snapshot {} to {}...", snapshot_id, target_path);
    let backup_dir = config.data_dir().join("backup");
    tilde_backup::restore_snapshot(&conn, snapshot_id, &backup_dir, target_dir)?;

    // Run post-restore fixup on the restored database
    let restored_db = target_dir.join("tilde.db");
    if restored_db.exists() {
        println!("Running post-restore fixup...");
        let restored_conn = db::init_db(restored_db.to_str().unwrap())?;
        let migrations_dir = tilde_cli::find_migrations_dir();
        db::run_migrations(&restored_conn, &migrations_dir)?;
        let report = tilde_backup::post_restore_fixup(&restored_conn)?;
        println!(
            "Fixup: {} jobs deleted, {} thumbnail flags reset, {} FTS tables dropped",
            report.jobs_deleted, report.thumbnails_reset, report.fts_tables_dropped,
        );
    }

    println!("Restore completed successfully to {}", target_path);

    Ok(())
}
