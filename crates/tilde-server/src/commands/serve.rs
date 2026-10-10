use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tilde_core::{
    config::Config,
    db::{self, DbPool},
};
use tilde_server::{AppState, SharedState, build_router};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use super::{parse_schedule_interval, secs_until_next_run, walkdir_media};

pub async fn run_serve(config_path: Option<&str>) -> anyhow::Result<()> {
    info!("Starting tilde server...");

    // Resolve our own path before anything can replace the binary: once
    // `tilde update apply` swaps it, Linux reports the running image as
    // "<path> (deleted)", which cannot be exec'd. The path itself then holds
    // the new binary, which is exactly what a SIGUSR2 re-exec wants.
    let exe_path = std::env::current_exe().ok();

    let config = Config::load(config_path)?;
    let db_path = config.db_path();

    // Run migrations on a single connection first, then create the pool
    {
        let conn = db::init_db(db_path.to_str().unwrap())?;
        db::run_embedded_migrations(&conn)?;
    }

    let pool: DbPool = db::init_pool(db_path.to_str().unwrap())?;

    let listen_addr = format!(
        "{}:{}",
        config.server.listen_addr, config.server.listen_port
    );

    let data_dir = config.data_dir();
    let cache_dir = config.cache_dir();
    let files_root = data_dir.join("files");

    // Ensure all data directories exist
    for dir in &[
        files_root.clone(),
        data_dir.join("notes"),
        files_root.join("documents"),
        files_root.join("health/_inbox"),
        data_dir.join("photos/_inbox"),
        data_dir.join("photos/_library-drop"),
        data_dir.join("photos/_untriaged"),
        data_dir.join("photos/_errors"),
        data_dir.join("calendars"),
        data_dir.join("contacts"),
        data_dir.join("mail"),
        data_dir.join("collections"),
        data_dir.join("uploads"),
        data_dir.join("backup"),
        data_dir.join("blobs/by-id"),
        cache_dir.join("thumbnails"),
    ] {
        std::fs::create_dir_all(dir)?;
    }

    let uploads_root = data_dir.join("uploads");

    // Cleanup expired upload sessions on startup
    {
        let conn = pool.get()?;
        let now_str = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        let mut stmt = conn
            .prepare("SELECT session_id, staging_dir FROM chunked_uploads WHERE expires_at < ?1")?;
        let expired: Vec<(String, String)> = stmt
            .query_map([&now_str], |row| Ok((row.get(0)?, row.get(1)?)))?
            .filter_map(|r| r.ok())
            .collect();

        for (session_id, staging_dir) in &expired {
            let _ = std::fs::remove_dir_all(staging_dir);
            info!(session = %session_id, "Cleaned up expired upload session");
        }
        if !expired.is_empty() {
            conn.execute(
                "DELETE FROM chunked_uploads WHERE expires_at < ?1",
                [&now_str],
            )?;
            info!(count = expired.len(), "Expired upload sessions cleaned up");
        }
    }

    // Crash recovery: reset any 'running' jobs back to 'pending'
    {
        let conn = pool.get()?;
        let reset_count = conn.execute(
            "UPDATE jobs SET status = 'pending', started_at = NULL WHERE status = 'running'",
            [],
        )?;
        if reset_count > 0 {
            info!(count = reset_count, "Reset crashed jobs back to pending");
        }
    }

    // Extract TLS config before config moves into state
    let state_config_tls = config.tls.clone();
    let state_config_tls_mode = state_config_tls.mode.clone();
    let tunnel_config = config.tunnel.clone();

    let livesync = config
        .notes
        .livesync
        .as_ref()
        .map(|remote| {
            tilde_livesync::Client::new(
                &remote.server_url,
                &remote.database,
                &remote.username,
                &remote.password,
            )
        })
        .transpose()?;
    // The health import mirrors its notes here once a vault is configured.
    let job_livesync = livesync.clone();
    let notes_index =
        livesync
            .as_ref()
            .zip(config.notes.livesync.as_ref())
            .map(|(client, remote)| {
                Arc::new(tilde_mcp::notes_index::NotesIndex::new(
                    client.clone(),
                    pool.clone(),
                    &remote.database,
                ))
            });
    let mcp_state: tilde_mcp::SharedMcpState = Arc::new(tilde_mcp::McpState {
        db: pool.clone(),
        data_dir: data_dir.clone(),
        livesync,
        notes_index: notes_index.clone(),
        rate_limits: Mutex::new(std::collections::HashMap::new()),
    });

    let state: SharedState = Arc::new(AppState {
        config: arc_swap::ArcSwap::new(Arc::new(config)),
        db: pool.clone(),
        start_time: Instant::now(),
        mcp_state,
        tunnel_status: if tunnel_config.enabled {
            info!("Tunnel configured — starting newt subprocess");
            let (status, _handle) = tilde_server::tunnel::spawn_tunnel_supervisor(tunnel_config);
            Some(status)
        } else {
            None
        },
    });

    let dav_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: pool.clone(),
        files_root,
        uploads_root,
        db_path_prefix: String::new(),
        scope_prefix: "/dav/".to_string(),
        organization_pattern: String::new(),
        allowed_symlink_targets: vec![],
        cache_dir: None,
        blobs_root: data_dir.join("blobs/by-id"),
    });

    let caldav_state: tilde_cal::SharedCalDavState =
        Arc::new(tilde_cal::CalDavState { db: pool.clone() });

    let carddav_state: tilde_card::SharedCardDavState =
        Arc::new(tilde_card::CardDavState { db: pool.clone() });

    // Ensure default calendar and addressbook exist
    {
        let db = caldav_state.db.get().unwrap();
        tilde_cal::ensure_default_calendar(&db);
        tilde_card::ensure_default_addressbook(&db);
    }

    // Start photo file watcher for _inbox/ and _library-drop/
    let _photo_watcher = {
        let photos_base = data_dir.join("photos");
        let pattern = state.config().photos.organization_pattern.clone();
        let debounce = state.config().photos.watch_debounce_seconds;
        let quality = state.config().photos.thumbnail_quality;
        match tilde_photos::watcher::start_watcher(
            state.db.clone(),
            photos_base,
            cache_dir,
            pattern,
            debounce,
            quality,
        ) {
            Ok(w) => {
                info!("Photo file watcher started");
                Some(w)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start photo file watcher");
                None
            }
        }
    };

    // Start health inbox watcher for Gadgetbridge uploads
    let _health_watcher = if state.config().gadgetbridge.enabled {
        let health_base = data_dir.join("files/health");
        let debounce = state.config().gadgetbridge.watch_debounce_seconds;
        match tilde_health::watcher::start_watcher(state.db.clone(), health_base.clone(), debounce)
        {
            Ok(w) => {
                // Catch up on uploads that arrived while the server was down.
                let has_pending = std::fs::read_dir(health_base.join("_inbox"))
                    .map(|entries| {
                        entries.flatten().any(|e| {
                            e.path().is_file() && !e.file_name().to_string_lossy().starts_with('.')
                        })
                    })
                    .unwrap_or(false);
                if has_pending && let Ok(conn) = state.db.get() {
                    match tilde_health::watcher::enqueue_import_job(&conn) {
                        Ok(true) => {
                            info!("Health inbox has pending files — import job enqueued")
                        }
                        Ok(false) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "Failed to enqueue startup health import")
                        }
                    }
                }
                Some(w)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to start health inbox watcher");
                None
            }
        }
    } else {
        None
    };

    // Graceful-shutdown coordination
    let shutdown = CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();

    // ── Notification sinks ────────────────────────────────────────────────
    let notification_sinks: std::sync::Arc<
        Vec<Box<dyn tilde_notify::NotificationSink + Send + Sync>>,
    > = {
        let mut sinks: Vec<Box<dyn tilde_notify::NotificationSink + Send + Sync>> = Vec::new();

        // Always add a file sink
        sinks.push(Box::new(tilde_notify::create_file_sink(&data_dir)));

        // ntfy sink from env vars
        if let Ok(topic) = std::env::var("TILDE_NTFY_TOPIC")
            && !topic.is_empty()
        {
            let token = std::env::var("TILDE_NTFY_TOKEN")
                .ok()
                .filter(|t| !t.is_empty());
            sinks.push(Box::new(tilde_notify::NtfySink::new(
                topic,
                token,
                tilde_notify::Priority::Medium,
            )));
            info!("Notification sink: ntfy");
        }

        info!(count = sinks.len(), "Notification sinks configured");
        std::sync::Arc::new(sinks)
    };
    let notification_rate_limiter =
        std::sync::Arc::new(tilde_notify::NotificationRateLimiter::new(10));

    // Send startup notification
    {
        let hostname = &state.config().server.hostname;
        let label = if hostname.is_empty() {
            "localhost"
        } else {
            hostname
        };
        let conn = state.db.get().unwrap();
        tilde_notify::notify(
            &notification_sinks,
            &notification_rate_limiter,
            &conn,
            tilde_notify::NotificationEvent {
                event_type: "server_started".into(),
                priority: tilde_notify::Priority::Low,
                message: format!("tilde started on {}", label),
            },
        );
    }

    // Keep the LiveSync notes search index following CouchDB.
    if let Some(index) = notes_index {
        let token = shutdown.clone();
        tasks.spawn(async move {
            tokio::select! {
                _ = token.cancelled() => {}
                _ = index.run() => {}
            }
        });
    }

    // Periodic disk usage check (every 6 hours)
    {
        let disk_sinks = notification_sinks.clone();
        let disk_limiter = notification_rate_limiter.clone();
        let disk_db = state.db.clone();
        let disk_path = data_dir.clone();
        let token = shutdown.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(6 * 3600)) => {
                        if let Ok(conn) = disk_db.get() {
                            tilde_notify::check_disk_usage(&disk_path, &disk_sinks, &disk_limiter, &conn);
                        }
                    }
                }
            }
        });
    }

    // Start background job processor for thumbnail generation etc.
    // Fetches batches of pending jobs and processes them concurrently
    // (up to 4 at a time). Only HEIC decoding is serialized (OOM protection);
    // JPEG/PNG thumbnails run in parallel.
    {
        let job_db = state.db.clone();
        let job_photos_base = data_dir.join("photos");
        let job_cache_dir = state.config().cache_dir();
        let job_thumb_quality = state.config().photos.thumbnail_quality;
        let job_files_root = data_dir.join("files");
        let job_gb_timezone = state.config().gadgetbridge.timezone.clone();
        // Relative to the notes root; empty disables the Markdown mirror.
        let job_gb_notes_dir = state.config().gadgetbridge.notes_dir.clone();
        let job_notes_root = data_dir.join("notes");
        let token = shutdown.clone();
        const JOB_CONCURRENCY: usize = 4;
        tasks.spawn(async move {
            loop {
                if token.is_cancelled() {
                    break;
                }

                // Fetch a batch of pending jobs
                let batch: Vec<(i64, String, String, i64, i64)> = {
                    let conn = match job_db.get() {
                        Ok(c) => c,
                        Err(_) => {
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            continue;
                        }
                    };
                    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let mut stmt = conn.prepare(
                        "SELECT id, job_type, payload_json, attempts, max_attempts FROM jobs WHERE status = 'pending' ORDER BY created_at ASC LIMIT ?1"
                    ).unwrap();
                    let jobs: Vec<_> = stmt.query_map([JOB_CONCURRENCY as i64 * 2], |row| {
                        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?, row.get::<_, i64>(3)?, row.get::<_, i64>(4)?))
                    }).unwrap().flatten().collect();
                    // Mark them as running
                    for (id, _, _, _, _) in &jobs {
                        conn.execute(
                            "UPDATE jobs SET status = 'running', started_at = ?1, attempts = attempts + 1 WHERE id = ?2",
                            rusqlite::params![now, id],
                        ).ok();
                    }
                    jobs
                };

                if batch.is_empty() {
                    // No work — sleep before polling again
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {}
                    }
                    continue;
                }

                // Process batch concurrently
                let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(JOB_CONCURRENCY));
                let mut handles = Vec::new();

                for (job_id, job_type, payload_json, attempts, max_attempts) in batch {
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let db = job_db.clone();
                    let photos = job_photos_base.clone();
                    let cache = job_cache_dir.clone();
                    let quality = job_thumb_quality;
                    let files = job_files_root.clone();
                    let gb_timezone = job_gb_timezone.clone();
                    let gb_notes_dir = job_gb_notes_dir.clone();
                    let notes_root = job_notes_root.clone();
                    let livesync = job_livesync.clone();
                    let runtime = tokio::runtime::Handle::current();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let conn = db.get().unwrap();
                        let result = match job_type.as_str() {
                            "thumbnail" => tilde_photos::process_thumbnail_job_standalone(
                                &payload_json, &conn, &photos, &cache, quality,
                            ),
                            "gadgetbridge_import" => tilde_health::process_import_job(
                                &payload_json,
                                &files,
                                &gb_timezone,
                            )
                            .and_then(|stats| {
                                // Server-side writes bypass DAV, so warm the stat
                                // cache for the subtree and prune deleted rows.
                                tilde_dav::reindex_tree(
                                    &conn,
                                    &files.join("health"),
                                    "health/",
                                    true,
                                )?;
                                if let Some(export) = &stats.export {
                                    info!(
                                        files = export.files_written,
                                        days = export.days,
                                        workouts = stats.workouts_copied,
                                        "Gadgetbridge import complete"
                                    );
                                }
                                // Optional Markdown mirror for Obsidian. With a
                                // LiveSync vault it goes to CouchDB, which is what
                                // Obsidian reads; otherwise to the on-disk notes
                                // tree, which then needs its own reindex.
                                if !gb_notes_dir.is_empty()
                                    && let Some(client) = &livesync
                                {
                                    let notes = tilde_health::render_notes(&files.join("health"));
                                    let written = runtime.block_on(
                                        super::health_notes::mirror_to_livesync(
                                            client,
                                            &gb_notes_dir,
                                            &notes,
                                        ),
                                    )?;
                                    info!(notes = written, "health notes mirrored to LiveSync");
                                } else if !gb_notes_dir.is_empty() {
                                    let target = notes_root.join(&gb_notes_dir);
                                    let notes = tilde_health::export_notes(
                                        &files.join("health"),
                                        &target,
                                    )?;
                                    if notes.files_written > 0 {
                                        tilde_dav::reindex_tree(
                                            &conn,
                                            &target,
                                            &format!("{}/", gb_notes_dir.trim_matches('/')),
                                            true,
                                        )?;
                                    }
                                }
                                Ok(())
                            }),
                            _ => Err(anyhow::anyhow!("Unknown job type: {}", job_type)),
                        };
                        let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                        match result {
                            Ok(()) => {
                                conn.execute(
                                    "UPDATE jobs SET status = 'completed', completed_at = ?1 WHERE id = ?2",
                                    rusqlite::params![now, job_id],
                                ).ok();
                            }
                            Err(e) => {
                                let error_msg = format!("{}", e);
                                if attempts + 1 >= max_attempts {
                                    conn.execute(
                                        "UPDATE jobs SET status = 'failed', error_message = ?1 WHERE id = ?2",
                                        rusqlite::params![error_msg, job_id],
                                    ).ok();
                                } else {
                                    conn.execute(
                                        "UPDATE jobs SET status = 'pending', error_message = ?1, started_at = NULL WHERE id = ?2",
                                        rusqlite::params![error_msg, job_id],
                                    ).ok();
                                }
                            }
                        }
                    }));
                }

                let mut completed = 0;
                for handle in handles {
                    if handle.await.is_ok() {
                        completed += 1;
                    }
                }
                if completed > 0 {
                    info!(count = completed, "Processed background jobs");
                }
                // Loop immediately to check for more work
            }
        });
        info!(
            "Background job processor started (concurrency={})",
            JOB_CONCURRENCY
        );
    }

    // Start trash purge scheduler (daily, purges entries older than 30 days)
    {
        let trash_data_dir = data_dir.clone();
        let token = shutdown.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(86400)) => {
                        let roots = [
                            trash_data_dir.join("files"),
                            trash_data_dir.join("notes"),
                            trash_data_dir.join("photos"),
                        ];
                        for root in &roots {
                            tilde_dav::purge_trash(root, 30);
                        }
                    }
                }
            }
        });
    }

    // Start backup scheduler if backup is enabled
    if state.config().backup.enabled {
        let backup_schedule = state.config().backup.schedule.clone();
        let backup_config = state.config().backup.clone();
        let backup_db = state.db.clone();
        let backup_data_dir = data_dir.clone();
        let backup_sinks = notification_sinks.clone();
        let backup_limiter = notification_rate_limiter.clone();
        let token = shutdown.clone();
        tasks.spawn(async move {
            let interval_secs = parse_schedule_interval(&backup_schedule);
            let first_wait = secs_until_next_run(&backup_schedule);
            info!(
                schedule = %backup_schedule,
                next_run_secs = first_wait,
                interval_secs = interval_secs,
                "Backup scheduler started"
            );

            // Record next scheduled time
            if let Ok(conn) = backup_db.get() {
                let next_run = jiff::Zoned::now()
                    .checked_add(jiff::SignedDuration::from_secs(first_wait as i64))
                    .unwrap_or_else(|_| jiff::Zoned::now());
                let next_str = next_run.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                let _ = conn.execute(
                    "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:next_scheduled', ?1, ?2)",
                    rusqlite::params![&next_str, &jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()],
                );
            }

            // First wait: until the scheduled time (e.g., 4:00 AM)
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(first_wait)) => {}
            }

            loop {
                info!("Backup scheduler: triggering scheduled backup");

                // Record the backup attempt and update next scheduled time
                if let Ok(conn) = backup_db.get() {
                    let now_str = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:last_run', ?1, ?2)",
                        rusqlite::params![&now_str, &now_str],
                    );

                    match tilde_backup::restic::ResticConfig::from_backup_config(&backup_config) {
                        Ok(restic_config) => {
                            match tilde_backup::restic::backup(&restic_config, &backup_data_dir, &conn) {
                                Ok(()) => {
                                    info!("Scheduled backup completed");
                                    if let Err(e) = tilde_backup::restic::forget_and_prune(&restic_config) {
                                        warn!(error = %e, "Backup retention failed");
                                    }
                                }
                                Err(e) => {
                                    tracing::error!(error = %e, "Scheduled backup failed");
                                    tilde_notify::notify(
                                        &backup_sinks,
                                        &backup_limiter,
                                        &conn,
                                        tilde_notify::events::backup_failed(&e.to_string()),
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Backup config resolution failed");
                            tilde_notify::notify(
                                &backup_sinks,
                                &backup_limiter,
                                &conn,
                                tilde_notify::events::backup_failed(&e.to_string()),
                            );
                        }
                    }
                }

                // Recalculate against the wall clock after each run. A fixed
                // interval drifts when backups take time or daylight saving changes.
                let next_wait = secs_until_next_run(&backup_schedule);
                if let Ok(conn) = backup_db.get() {
                    let now = jiff::Zoned::now();
                    let next_run = now
                        .checked_add(jiff::SignedDuration::from_secs(next_wait as i64))
                        .unwrap_or_else(|_| now.clone());
                    let next_str = next_run.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let now_str = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:next_scheduled', ?1, ?2)",
                        rusqlite::params![&next_str, &now_str],
                    );
                }

                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(next_wait)) => {}
                }
            }
        });
        info!(schedule = %state.config().backup.schedule, "Backup scheduler enabled");
    }

    // Process existing files in background (doesn't block server startup)
    {
        let scan_db = state.db.clone();
        let scan_photos_base = data_dir.join("photos");
        let scan_pattern = state.config().photos.organization_pattern.clone();
        let scan_cache_dir = state.config().cache_dir();
        let token = shutdown.clone();
        tasks.spawn(async move {
            // Small delay to let the server finish binding
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }

            // Collect file lists (fast, no DB lock)
            let inbox = scan_photos_base.join("_inbox");
            let library_drop = scan_photos_base.join("_library-drop");

            let inbox_files = if inbox.exists() {
                walkdir_media(&inbox)
            } else {
                vec![]
            };
            let lib_files = if library_drop.exists() {
                walkdir_media(&library_drop)
            } else {
                vec![]
            };

            // Ingest is I/O-bound (hash + EXIF + copy), so run files
            // concurrently — capped below the DB pool size (4) so live
            // requests always find a free connection during a large import.
            const SCAN_CONCURRENCY: usize = 3;
            let sem = std::sync::Arc::new(tokio::sync::Semaphore::new(SCAN_CONCURRENCY));

            // Process inbox files with brief DB locks
            if !inbox_files.is_empty() {
                let total = inbox_files.len();
                let mut handles = Vec::new();
                for path in &inbox_files {
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let db = scan_db.clone();
                    let photos = scan_photos_base.clone();
                    let pat = scan_pattern.clone();
                    let p = path.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let conn = db.get().unwrap();
                        tilde_photos::ingest::process_inbox_file(&conn, &p, &photos, &pat)
                    }));
                }
                let mut processed = 0;
                for handle in handles {
                    if matches!(handle.await, Ok(Ok(_))) {
                        processed += 1;
                    }
                }
                if processed > 0 {
                    info!(processed, total, "Processed inbox files");
                }
            }

            // Process library-drop files
            if !lib_files.is_empty() {
                let total = lib_files.len();
                let mut handles = Vec::new();
                for path in &lib_files {
                    let permit = sem.clone().acquire_owned().await.unwrap();
                    let db = scan_db.clone();
                    let photos = scan_photos_base.clone();
                    let lib = library_drop.clone();
                    let p = path.clone();
                    handles.push(tokio::task::spawn_blocking(move || {
                        let _permit = permit;
                        let conn = db.get().unwrap();
                        tilde_photos::ingest::process_library_drop_file(&conn, &p, &photos, &lib)
                    }));
                }
                let mut processed = 0;
                for (i, handle) in handles.into_iter().enumerate() {
                    if matches!(handle.await, Ok(Ok(_))) {
                        processed += 1;
                    }
                    if (i + 1) % 1000 == 0 {
                        info!(progress = i + 1, total, "Library-drop scan progress");
                    }
                }
                if processed > 0 {
                    info!(processed, total, "Processed library-drop files");
                }
            }

            // Reprocess untriaged + rebuild thumbnail mirror
            let db = scan_db.clone();
            let photos = scan_photos_base.clone();
            let pat = scan_pattern.clone();
            let cache = scan_cache_dir.clone();
            tokio::task::spawn_blocking(move || {
                let conn = db.get().unwrap();
                match tilde_photos::ingest::reprocess_untriaged(&conn, &photos, &pat) {
                    Ok(n) if n > 0 => info!(count = n, "Re-organized untriaged files"),
                    Err(e) => tracing::warn!(error = %e, "Failed to reprocess untriaged"),
                    _ => {}
                }
                match tilde_photos::thumbnail::rebuild_thumbnail_mirror(&conn, &photos, &cache) {
                    Ok(n) if n > 0 => info!(count = n, "Thumbnail mirror rebuilt"),
                    Err(e) => tracing::warn!(error = %e, "Failed to rebuild thumbnail mirror"),
                    _ => {}
                }
            })
            .await
            .ok();
        });
        info!("Photo scan scheduled (runs in background)");
    }

    // Start email IMAP sync if email is enabled
    if state.config().email.enabled {
        let mail_dir = data_dir.join("mail");
        let mut accounts = state.config().email.accounts.clone();

        // If no accounts configured but env vars are set, create a default account
        if accounts.is_empty() {
            let imap_host = std::env::var("TILDE_EMAIL_IMAP_HOST").unwrap_or_default();
            if !imap_host.is_empty() {
                let account = tilde_core::config::EmailAccountConfig {
                    name: "personal".to_string(),
                    imap_host,
                    imap_port: std::env::var("TILDE_EMAIL_IMAP_PORT")
                        .ok()
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(993),
                    username_env: "TILDE_EMAIL_USERNAME".to_string(),
                    password_env: "TILDE_EMAIL_PASSWORD".to_string(),
                    ..Default::default()
                };
                accounts.push(account);
            }
        }

        for account_cfg in &accounts {
            let imap_config = tilde_email::imap::ImapAccountConfig::from_config(account_cfg);
            if imap_config.imap_host.is_empty() {
                warn!(account = %imap_config.name, "Skipping email account with empty IMAP host");
                continue;
            }
            let email_db = state.db.clone();
            let email_mail_dir = mail_dir.clone();
            info!(account = %imap_config.name, host = %imap_config.imap_host, "Starting email sync");
            let token = shutdown.clone();
            // Notify on the 3rd consecutive sync failure (issue #3). The rate
            // limiter dedups repeat streaks; the closure keeps tilde-email
            // free of a notification dependency.
            let email_sinks = notification_sinks.clone();
            let email_limiter = notification_rate_limiter.clone();
            let email_notify_db = state.db.clone();
            let on_repeated_failure: tilde_email::imap::SyncFailureCallback =
                std::sync::Arc::new(move |account: &str, error: &str| {
                    if let Ok(conn) = email_notify_db.get() {
                        tilde_notify::notify(
                            &email_sinks,
                            &email_limiter,
                            &conn,
                            tilde_notify::events::email_sync_error(account, error),
                        );
                    }
                });
            tasks.spawn(async move {
                tilde_email::imap::run_sync_loop(
                    imap_config,
                    email_db,
                    email_mail_dir,
                    token,
                    Some(on_repeated_failure),
                )
                .await;
            });
        }
        if !accounts.is_empty() {
            info!(accounts = accounts.len(), "Email sync started");
        }
    }

    // Brute-force detection: count 401s per client IP, notify on repeats (issue #3)
    let auth_notifier = std::sync::Arc::new(tilde_server::AuthFailureNotifier::new(
        notification_sinks.clone(),
        notification_rate_limiter.clone(),
        state.db.clone(),
        state.config().server.trusted_proxies.clone(),
    ));
    let app = build_router(
        state,
        dav_state,
        caldav_state,
        carddav_state,
        Some(auth_notifier),
    );

    // Flag: if set, the process will exec() itself after graceful shutdown
    // instead of exiting. Used by SIGUSR2 for zero-downtime upgrades.
    let should_reexec = Arc::new(AtomicBool::new(false));

    // Set up SIGHUP handler for config hot-reload
    #[cfg(unix)]
    {
        let config_path_for_reload = config_path.map(|s| s.to_string());
        let token = shutdown.clone();
        tasks.spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup =
                signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = sighup.recv() => {}
                }
                info!("Received SIGHUP, reloading configuration...");
                match Config::load(config_path_for_reload.as_deref()) {
                    Ok(new_config) => {
                        let level = &new_config.logging.level;
                        warn!(
                            level = %level,
                            "SIGHUP: config file re-read, but runtime config is NOT updated \
                             (AppState holds config by value). Most changes require a restart."
                        );
                    }
                    Err(e) => {
                        tracing::error!(error = %e, "Failed to reload configuration on SIGHUP");
                    }
                }
            }
        });
    }

    // Set up SIGUSR2 handler for zero-downtime upgrade (re-exec)
    #[cfg(unix)]
    {
        let token = shutdown.clone();
        let reexec_flag = should_reexec.clone();
        tasks.spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sigusr2 =
                signal(SignalKind::user_defined2()).expect("Failed to register SIGUSR2 handler");
            tokio::select! {
                _ = token.cancelled() => return,
                _ = sigusr2.recv() => {}
            }
            info!("Received SIGUSR2 — initiating zero-downtime upgrade");
            reexec_flag.store(true, Ordering::SeqCst);
            token.cancel();
        });
    }

    let listener = match inherited_listener(&listen_addr)? {
        Some(listener) => listener,
        None => tokio::net::TcpListener::bind(&listen_addr).await?,
    };
    // A second handle on the listening socket, held until a SIGUSR2 re-exec
    // hands it to the new binary. While any handle is open the kernel keeps
    // queueing connections, so clients wait out the upgrade instead of being
    // refused.
    #[cfg(unix)]
    let reexec_listen_fd = {
        use std::os::fd::AsFd;
        listener.as_fd().try_clone_to_owned()?
    };

    // Notify systemd we're ready (no-op if not running under systemd)
    let _ = sd_notify::notify(true, &[sd_notify::NotifyState::Ready]);
    info!("sd-notify: READY=1 sent");

    // Start watchdog ping task if WatchdogSec is configured
    if let Ok(watchdog_usec) = std::env::var("WATCHDOG_USEC")
        && let Ok(usec) = watchdog_usec.parse::<u64>()
    {
        let interval = std::time::Duration::from_micros(usec / 2);
        let token = shutdown.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
                    }
                }
            }
        });
        info!(
            interval_ms = usec / 2000,
            "sd-notify: watchdog pinger started"
        );
    }

    // Resolves on SIGTERM or SIGINT, or once the token is cancelled elsewhere
    // (the SIGUSR2 upgrade). Without that last arm an upgrade stopped every
    // background task but left the HTTP server running, so it never re-exec'd.
    let shutdown_signal = {
        let token = shutdown.clone();
        async move {
            let ctrl_c = tokio::signal::ctrl_c();
            #[cfg(unix)]
            {
                use tokio::signal::unix::{SignalKind, signal};
                let mut sigterm =
                    signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
                tokio::select! {
                    _ = ctrl_c => info!("Received SIGINT, shutting down..."),
                    _ = sigterm.recv() => info!("Received SIGTERM, shutting down..."),
                    _ = token.cancelled() => info!("Shutdown requested, stopping HTTP server..."),
                }
            }
            #[cfg(not(unix))]
            {
                tokio::select! {
                    _ = ctrl_c => info!("Received SIGINT, shutting down..."),
                    _ = token.cancelled() => info!("Shutdown requested, stopping HTTP server..."),
                }
            }
            token.cancel();
        }
    };

    match state_config_tls_mode.as_str() {
        "manual" => {
            let cert_path = &state_config_tls.cert_path;
            let key_path = &state_config_tls.key_path;

            if cert_path.is_empty() || key_path.is_empty() {
                anyhow::bail!(
                    "TLS mode 'manual' requires tls.cert_path and tls.key_path to be set"
                );
            }

            let cert_file = std::fs::File::open(cert_path)
                .map_err(|e| anyhow::anyhow!("Failed to open cert file '{}': {}", cert_path, e))?;
            let key_file = std::fs::File::open(key_path)
                .map_err(|e| anyhow::anyhow!("Failed to open key file '{}': {}", key_path, e))?;

            let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
                    .filter_map(|r| r.ok())
                    .collect();
            if certs.is_empty() {
                anyhow::bail!("No certificates found in {}", cert_path);
            }

            let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
                .ok_or_else(|| anyhow::anyhow!("No private key found in {}", key_path))?;

            let tls_config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

            let tls_acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(tls_config));

            println!("tilde server listening on https://{}", listen_addr);

            let make_service = app.into_make_service_with_connect_info::<std::net::SocketAddr>();

            tokio::pin!(shutdown_signal);
            loop {
                tokio::select! {
                    _ = &mut shutdown_signal => break,
                    result = listener.accept() => {
                        let (tcp_stream, addr) = result?;
                        let _ = tcp_stream.set_nodelay(true);
                        let acceptor = tls_acceptor.clone();
                        let mut make_svc = make_service.clone();

                        tokio::spawn(async move {
                            match acceptor.accept(tcp_stream).await {
                                Ok(tls_stream) => {
                                    use tower::Service;
                                    let svc = match make_svc.call(addr).await {
                                        Ok(s) => s,
                                        Err(e) => {
                                            tracing::debug!(error = %e, "Failed to create service for connection");
                                            return;
                                        }
                                    };
                                    let hyper_svc = hyper_util::service::TowerToHyperService::new(svc);
                                    let io = hyper_util::rt::TokioIo::new(tls_stream);
                                    let _ = hyper_util::server::conn::auto::Builder::new(
                                        hyper_util::rt::TokioExecutor::new(),
                                    )
                                    .serve_connection(io, hyper_svc)
                                    .await;
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, addr = %addr, "TLS handshake failed");
                                }
                            }
                        });
                    }
                }
            }
        }
        _ => {
            // "upstream" mode or default: plain HTTP
            println!("tilde server listening on http://{}", listen_addr);
            let server = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal);
            // Graceful shutdown waits for every open connection; one stuck
            // upload must not hold a stop or an upgrade hostage indefinitely.
            let drain_deadline = {
                let token = shutdown.clone();
                async move {
                    token.cancelled().await;
                    tokio::time::sleep(HTTP_DRAIN_TIMEOUT).await;
                }
            };
            tokio::select! {
                result = std::future::IntoFuture::into_future(server) => result?,
                _ = drain_deadline => warn!(
                    secs = HTTP_DRAIN_TIMEOUT.as_secs(),
                    "HTTP connections still open after shutdown; abandoning them"
                ),
            }
        }
    }

    // Drain background tasks with a timeout
    info!("Server stopped, draining background tasks...");
    shutdown.cancel();
    let deadline = tokio::time::sleep(std::time::Duration::from_secs(10));
    tokio::pin!(deadline);
    loop {
        tokio::select! {
            _ = &mut deadline => {
                warn!("Shutdown timeout — forcing exit");
                break;
            }
            result = tasks.join_next() => {
                if result.is_none() { break; }
            }
        }
    }
    info!("Graceful shutdown complete");

    // If SIGUSR2 triggered the shutdown, re-exec the new binary
    if should_reexec.load(Ordering::SeqCst) {
        info!("Re-executing with upgraded binary...");
        #[cfg(unix)]
        reexec(exe_path.as_deref(), &reexec_listen_fd);
        #[cfg(not(unix))]
        reexec();
    }

    Ok(())
}

/// How long open HTTP connections may delay a stop or an upgrade.
const HTTP_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Hands the listening socket across a SIGUSR2 re-exec, as `<pid>:<fd>`. A
/// re-exec keeps the PID, so the PID check makes any child process that
/// inherits the environment ignore it (systemd's LISTEN_PID trick).
#[cfg(unix)]
const INHERITED_LISTEN_FD: &str = "TILDE_INHERITED_LISTEN_FD";

/// Adopt the listening socket handed over by the previous process image.
/// Returns `None` on a normal start, or when the inherited socket is no longer
/// bound to `listen_addr` (the port changed in the config meanwhile).
#[cfg(unix)]
fn inherited_listener(listen_addr: &str) -> anyhow::Result<Option<tokio::net::TcpListener>> {
    use std::net::ToSocketAddrs;
    use std::os::fd::{FromRawFd, RawFd};

    let Ok(value) = std::env::var(INHERITED_LISTEN_FD) else {
        return Ok(None);
    };
    let Some((pid, fd)) = value.split_once(':') else {
        anyhow::bail!("malformed {INHERITED_LISTEN_FD}={value}");
    };
    if pid.parse::<u32>().ok() != Some(std::process::id()) {
        return Ok(None);
    }
    let fd: RawFd = fd
        .parse()
        .map_err(|_| anyhow::anyhow!("malformed {INHERITED_LISTEN_FD}={value}"))?;

    // SAFETY: the previous image of this very process cleared FD_CLOEXEC on
    // this fd immediately before exec, and nothing has claimed it since.
    let listener = unsafe { std::net::TcpListener::from_raw_fd(fd) };
    // Keep it out of anything this image spawns (backups, thumbnailers).
    // SAFETY: plain fcntl on an fd we own.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };

    let local = listener.local_addr()?;
    if !listen_addr.to_socket_addrs()?.any(|addr| addr == local) {
        warn!(inherited = %local, wanted = %listen_addr, "inherited listener is bound elsewhere; rebinding");
        return Ok(None);
    }
    listener.set_nonblocking(true)?;
    info!(addr = %local, "adopted the listening socket from the previous binary");
    Ok(Some(tokio::net::TcpListener::from_std(listener)?))
}

#[cfg(not(unix))]
fn inherited_listener(_listen_addr: &str) -> anyhow::Result<Option<tokio::net::TcpListener>> {
    Ok(None)
}

/// Replace the current process with a fresh exec of the binary at `exe`,
/// same args, handing over the listening socket. Same PID, so systemd does
/// not notice, and connections queue in the socket's backlog meanwhile.
/// If the exec fails the process exits and systemd's restart takes over.
#[cfg(unix)]
fn reexec(exe: Option<&std::path::Path>, listen_fd: &std::os::fd::OwnedFd) -> ! {
    use std::os::fd::AsRawFd;
    use std::os::unix::process::CommandExt;

    let Some(exe) = exe else {
        eprintln!("cannot re-exec: the binary's path was not known at startup");
        std::process::exit(1);
    };
    let mut command = std::process::Command::new(exe);
    let mut args = std::env::args_os();
    if let Some(arg0) = args.next() {
        command.arg0(arg0);
    }
    command.args(args);

    let fd = listen_fd.as_raw_fd();
    // SAFETY: plain fcntl on an fd we own; clearing FD_CLOEXEC lets it survive exec.
    unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
    command.env(INHERITED_LISTEN_FD, format!("{}:{fd}", std::process::id()));

    // Notify systemd we're reloading (keeps watchdog happy during exec gap)
    let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Reloading]);

    let err = command.exec();
    eprintln!("execv failed: {err}");
    std::process::exit(1);
}

#[cfg(not(unix))]
fn reexec() -> ! {
    eprintln!("Re-exec is only supported on Unix");
    std::process::exit(1);
}
