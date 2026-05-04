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

    let config = Config::load(config_path)?;
    let db_path = config.db_path();

    // Run migrations on a single connection first, then create the pool
    {
        let conn = db::init_db(db_path.to_str().unwrap())?;
        let migrations_dir = tilde_cli::find_migrations_dir();
        db::run_migrations(&conn, &migrations_dir)?;
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

    let mcp_state: tilde_mcp::SharedMcpState = Arc::new(tilde_mcp::McpState {
        db: pool.clone(),
        data_dir: data_dir.clone(),
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

    // Graceful-shutdown coordination
    let shutdown = CancellationToken::new();
    let mut tasks = tokio::task::JoinSet::new();

    // Start background job processor for thumbnail generation etc.
    {
        let job_db = state.db.clone();
        let job_photos_base = data_dir.join("photos");
        let job_cache_dir = state.config().cache_dir();
        let job_thumb_quality = state.config().photos.thumbnail_quality;
        let token = shutdown.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(5)) => {
                        if let Ok(conn) = job_db.get() {
                            match tilde_photos::process_pending_jobs(&conn, 5, &job_photos_base, &job_cache_dir, job_thumb_quality) {
                                Ok(0) => {}
                                Ok(n) => info!(count = n, "Processed background jobs"),
                                Err(e) => tracing::debug!(error = %e, "Job processor error"),
                            }
                        }
                    }
                }
            }
        });
        info!("Background job processor started");
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
        let backup_db = state.db.clone();
        let backup_data_dir = data_dir.clone();
        let backup_encrypt_recipient = state.config().backup.encrypt_recipient.clone();
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

                // Record the backup attempt
                if let Ok(conn) = backup_db.get() {
                    let now_str = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:last_run', ?1, ?2)",
                        rusqlite::params![&now_str, &now_str],
                    );

                    // Update next scheduled time
                    let next_run = jiff::Zoned::now()
                        .checked_add(jiff::SignedDuration::from_secs(interval_secs as i64))
                        .unwrap_or_else(|_| jiff::Zoned::now());
                    let next_str = next_run.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
                    let _ = conn.execute(
                        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup:next_scheduled', ?1, ?2)",
                        rusqlite::params![&next_str, &now_str],
                    );
                }

                // Run actual backup
                if let Ok(conn) = backup_db.get() {
                    let backup_dir = backup_data_dir.join("backup");
                    let encrypt = if backup_encrypt_recipient.is_empty() {
                        None
                    } else {
                        Some(backup_encrypt_recipient.as_str())
                    };
                    match tilde_backup::create_snapshot_with_encryption(&conn, &backup_data_dir, &backup_dir, encrypt) {
                        Ok(snapshot) => {
                            info!(
                                snapshot_id = %snapshot.id,
                                size = %tilde_backup::format_size(snapshot.size_bytes),
                                files = snapshot.file_count,
                                "Scheduled backup completed"
                            );
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "Scheduled backup failed");
                        }
                    }
                }

                // Wait for next interval
                tokio::select! {
                    _ = token.cancelled() => break,
                    _ = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
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

            // Process inbox files one at a time with brief DB locks
            if !inbox_files.is_empty() {
                let total = inbox_files.len();
                let mut processed = 0;
                for path in &inbox_files {
                    let db = scan_db.clone();
                    let photos = scan_photos_base.clone();
                    let pat = scan_pattern.clone();
                    let p = path.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        let conn = db.get().unwrap();
                        tilde_photos::ingest::process_inbox_file(&conn, &p, &photos, &pat)
                    })
                    .await;
                    if matches!(r, Ok(Ok(_))) {
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
                let mut processed = 0;
                for (i, path) in lib_files.iter().enumerate() {
                    let db = scan_db.clone();
                    let photos = scan_photos_base.clone();
                    let lib = library_drop.clone();
                    let p = path.clone();
                    let r = tokio::task::spawn_blocking(move || {
                        let conn = db.get().unwrap();
                        tilde_photos::ingest::process_library_drop_file(&conn, &p, &photos, &lib)
                    })
                    .await;
                    if matches!(r, Ok(Ok(_))) {
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
            tasks.spawn(async move {
                tokio::select! {
                    _ = token.cancelled() => {},
                    _ = tilde_email::imap::run_sync_loop(imap_config, email_db, email_mail_dir) => {},
                }
            });
        }
        if !accounts.is_empty() {
            info!(accounts = accounts.len(), "Email sync started");
        }
    }

    let app = build_router(state, dav_state, caldav_state, carddav_state);

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
                        // SIGHUP reload: log new config values but note that
                        // AppState.config is by-value — most changes require restart.
                        // TODO: use ArcSwap<Config> to make reload actually effective
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

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;

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

    // Build a future that resolves on SIGTERM or SIGINT for graceful shutdown
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
                }
            }
            #[cfg(not(unix))]
            {
                ctrl_c.await.ok();
                info!("Received SIGINT, shutting down...");
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
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal)
            .await?;
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

    Ok(())
}
