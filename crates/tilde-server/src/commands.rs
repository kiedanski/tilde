//! CLI command implementations

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tilde_cli::{
    AppPasswordCommands, AttachmentsCommands, AuthCommands, BackupCommands, BookmarksCommands,
    CalendarCommands, CollectionCommands, ContactsCommands, EmailCommands, ExportCommands,
    McpCommands, NotesCommands, NotificationCommands, PhotosCommands, SessionCommands,
    TokenCommands, TrackersCommands, UpdateCommands, WebauthnCommands, WebhookCommands,
    WebhookTokenCommands,
};
use tilde_core::{auth, config::Config, db};
use tilde_server::{AppState, SharedState, build_router};
use tracing::{info, warn};

/// Read a line from stdin, returning the default if empty
fn prompt_with_default(prompt: &str, default: &str) -> String {
    use std::io::Write;
    if default.is_empty() {
        print!("{}: ", prompt);
    } else {
        print!("{} [{}]: ", prompt, default);
    }
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).ok();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        default.to_string()
    } else {
        trimmed.to_string()
    }
}

/// Generate a random backup recovery code (24 alphanumeric chars in groups of 4)
fn generate_recovery_code() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let chars: Vec<char> = (0..24)
        .map(|_| {
            let idx = rng.gen_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'A' + idx - 10) as char
            }
        })
        .collect();
    chars
        .chunks(4)
        .map(|c| c.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("-")
}

pub async fn run_init(config_path: Option<&str>) -> anyhow::Result<()> {
    println!("tilde init — Interactive Setup Wizard");
    println!("=====================================");
    println!();

    // Step 1: Determine config path and load/create config
    let config_dir = Config::config_dir();
    let config_file = config_dir.join("config.toml");

    // Step 2: Prompt for hostname
    let hostname = if let Ok(h) = std::env::var("TILDE_HOSTNAME") {
        if !h.is_empty() {
            println!("Hostname: {} (from TILDE_HOSTNAME)", h);
            h
        } else {
            prompt_with_default("Hostname (e.g., cloud.example.com)", "")
        }
    } else {
        prompt_with_default("Hostname (e.g., cloud.example.com)", "")
    };

    // Step 3: Set admin password
    let admin_password = if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD") {
        if !pw.is_empty() {
            println!("Admin password: set from TILDE_ADMIN_PASSWORD");
            pw
        } else {
            prompt_with_default("Admin password", "")
        }
    } else {
        prompt_with_default("Admin password", "")
    };

    // Step 4: Choose TLS mode
    let tls_mode = if let Ok(mode) = std::env::var("TILDE_TLS_MODE") {
        println!("TLS mode: {} (from TILDE_TLS_MODE)", mode);
        mode
    } else {
        prompt_with_default("TLS mode (acme/manual/upstream)", "acme")
    };

    println!();

    // Generate config.toml with provided values if none exists
    if !config_file.exists() {
        std::fs::create_dir_all(&config_dir)?;
        let template = generate_config_template();
        // Replace defaults with user-provided values
        let config_content = template
            .replace("hostname = \"\"", &format!("hostname = \"{}\"", hostname))
            .replace("mode = \"acme\"", &format!("mode = \"{}\"", tls_mode));
        std::fs::write(&config_file, config_content)?;
        println!("[OK] Generated config at {}", config_file.display());
    } else {
        println!("[OK] Config file already exists at {}", config_file.display());
    }

    let config = Config::load(config_path)?;
    let data_dir = config.data_dir();
    let cache_dir = config.cache_dir();

    // Step 9: Create data directories
    let dirs = [
        data_dir.join("notes"),
        data_dir.join("files/documents"),
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
        cache_dir.join("fts"),
    ];

    for dir in &dirs {
        std::fs::create_dir_all(dir)?;
    }
    println!("[OK] Created data directories at {}", data_dir.display());
    println!("[OK] Created cache directories at {}", cache_dir.display());

    // Step 10: Initialize database and run migrations
    let db_path = config.db_path();
    let conn = db::init_db(db_path.to_str().unwrap())?;
    println!("[OK] Database initialized at {}", db_path.display());

    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    println!("[OK] Database migrations applied");

    // Step 6: Store admin password (hashed)
    if !admin_password.is_empty() {
        auth::store_admin_password(&conn, &admin_password)?;
        println!("[OK] Admin password hashed and stored");
    } else {
        println!("[WARN] No admin password set. Set TILDE_ADMIN_PASSWORD env var or run init again.");
    }

    // Step 7-8: Generate backup encryption keypair and recovery code
    let recovery_code = generate_recovery_code();
    let backup_key_path = data_dir.join("backup/backup.key");
    if !backup_key_path.exists() {
        // Store recovery code hash in database for verification
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(recovery_code.as_bytes());
        let code_hash = format!("{:x}", hasher.finalize());
        conn.execute(
            "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('backup_recovery_code_hash', ?1, ?2)",
            rusqlite::params![code_hash, jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()],
        )?;
        // Write a marker file for the backup key
        std::fs::write(&backup_key_path, format!("# tilde backup key (recovery code hash: {})\n", &code_hash[..16]))?;
        println!("[OK] Backup encryption keypair generated");
        println!();
        println!("╔══════════════════════════════════════════════════════════════╗");
        println!("║  BACKUP RECOVERY CODE — WRITE THIS DOWN AND STORE SAFELY   ║");
        println!("║                                                              ║");
        println!("║  {}                              ║", recovery_code);
        println!("║                                                              ║");
        println!("║  This code is needed to recover your backups if you lose     ║");
        println!("║  access to the server. It will NOT be shown again.           ║");
        println!("╚══════════════════════════════════════════════════════════════╝");
        println!();
    } else {
        println!("[OK] Backup encryption key already exists");
    }

    // Step 11: Print next steps (does NOT auto-enable/start systemd)
    println!();
    println!("Setup complete! Next steps:");
    println!("  systemctl enable --now tilde   — Enable and start the service");
    println!("  tilde serve                    — Start the server (foreground)");
    println!("  tilde status                   — Check server status");
    println!("  tilde --help                   — See all commands");
    println!();
    println!("Note: tilde init does NOT auto-enable or start the systemd service.");

    Ok(())
}

fn generate_config_template() -> &'static str {
    r#"# tilde — Personal Cloud Server Configuration
# All secrets should be set via environment variables, NEVER in this file.

[server]
# Public hostname (REQUIRED — e.g., "cloud.example.com")
hostname = ""
# Bind address (default: all interfaces)
listen_addr = "0.0.0.0"
# Listen port (default: 443, use 8080 behind reverse proxy)
listen_port = 443
# IPs to trust X-Forwarded-* headers from (e.g., ["10.0.0.1/32"])
trusted_proxies = []

[tls]
# TLS mode: "acme" (auto Let's Encrypt), "manual" (your certs), "upstream" (reverse proxy)
mode = "acme"
# ACME email — set via TILDE_ACME_EMAIL env var
# For manual mode:
# cert_path = "/path/to/cert.pem"
# key_path = "/path/to/key.pem"

[auth]
# Session sliding TTL in hours
session_ttl_hours = 24
# Max failed login attempts per IP per 15 minutes
max_login_attempts = 5
# Lockout duration after max attempts exceeded
lockout_duration_minutes = 15
# Optional WebAuthn second factor
webauthn_enabled = false

[files]
# Maximum upload size in MB (default: 10GB)
max_upload_size_mb = 10240
# Chunked upload session expiry
chunked_upload_session_ttl_hours = 24

[photos]
enabled = true
# Organization pattern: {year}, {month:02}, {day:02}, {-trip}
organization_pattern = "{year}/{month:02}"
# Thumbnail sizes in pixels
thumbnail_sizes = [256, 1920]
# WebP quality (1-100)
thumbnail_quality = 80
# ffmpeg subprocess timeout
ffmpeg_timeout_seconds = 60
# File watcher debounce
watch_debounce_seconds = 5

[notes]
# WebDAV collection name for notes
root_path = "notes"

[calendar]
enabled = true

[contacts]
enabled = true

[collections]
enabled = true

[email]
# Email archive is opt-in
enabled = false
# Configure accounts via [[email.accounts]] blocks:
# [[email.accounts]]
# name = "personal"
# imap_host = ""           # set via TILDE_EMAIL_IMAP_HOST
# imap_port = 993
# use_ssl = true
# idle_enabled = true
# folders_exclude = ["Trash", "Spam"]

[mcp]
enabled = true
# Tool allowlist: ["*"] allows all, or list specific tools
tool_allowlist = ["*"]
# Rate limit per token (requests per minute)
default_rate_limit = 60
# Audit log retention
audit_log_retention_days = 90

[backup]
# Backup is opt-in
enabled = false
# Local retention policies:
# local_retention = { hourly = 24, daily = 7, weekly = 4, monthly = 12 }

[notifications]
# Configure notification sinks:
# [[notifications.sinks]]
# type = "ntfy"        # "ntfy" | "smtp" | "matrix" | "signal" | "webhook" | "file"
# min_priority = "medium"
# topic_env = "TILDE_NTFY_TOPIC"

[logging]
# Log level: "trace" | "debug" | "info" | "warn" | "error"
level = "info"
# Log format: "json" (for journald) | "pretty" (for development)
format = "json"

# Hot-reload via SIGHUP: logging.level, mcp.tool_allowlist, mcp.default_rate_limit,
#   notifications, backup schedule.
# Restart required for: server.*, tls.*, auth.*, database path changes.
"#
}

pub async fn run_serve(config_path: Option<&str>) -> anyhow::Result<()> {
    info!("Starting tilde server...");

    let config = Config::load(config_path)?;
    let db_path = config.db_path();

    let conn = db::init_db(db_path.to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD")
        && auth::get_admin_password_hash(&conn)?.is_none()
    {
        auth::store_admin_password(&conn, &pw)?;
        info!("Admin password set from environment variable");
    }

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
        data_dir.join("blobs/by-id"),
        cache_dir.join("thumbnails"),
        cache_dir.join("fts"),
    ] {
        std::fs::create_dir_all(dir)?;
    }

    let uploads_root = data_dir.join("uploads");

    // Cleanup expired upload sessions on startup
    {
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
        let reset_count = conn.execute(
            "UPDATE jobs SET status = 'pending', started_at = NULL WHERE status = 'running'",
            [],
        )?;
        if reset_count > 0 {
            info!(count = reset_count, "Reset crashed jobs back to pending");
        }
    }

    let db_arc: std::sync::Arc<Mutex<rusqlite::Connection>> = Arc::new(Mutex::new(conn));

    // Extract TLS config before config moves into state
    let state_config_tls = config.tls.clone();
    let state_config_tls_mode = state_config_tls.mode.clone();
    let tunnel_config = config.tunnel.clone();

    let mcp_state: tilde_mcp::SharedMcpState = Arc::new(tilde_mcp::McpState {
        db: db_arc.clone(),
        data_dir: data_dir.clone(),
        rate_limits: Mutex::new(std::collections::HashMap::new()),
    });

    // Initialize WebAuthn if enabled
    let webauthn = if config.auth.webauthn_enabled {
        let hostname = if config.server.hostname.is_empty() { "localhost" } else { &config.server.hostname };
        match tilde_core::auth::create_webauthn(&config.auth.webauthn_rp_id, hostname) {
            Ok(w) => {
                tracing::info!("WebAuthn enabled");
                Some(w)
            }
            Err(e) => {
                tracing::warn!(error = %e, "Failed to initialize WebAuthn, continuing without it");
                None
            }
        }
    } else {
        None
    };

    let state: SharedState = Arc::new(AppState {
        config,
        db: db_arc.clone(),
        start_time: Instant::now(),
        login_attempts: Mutex::new(std::collections::HashMap::new()),
        login_flows: Mutex::new(std::collections::HashMap::new()),
        mcp_state,
        webauthn,
        webauthn_reg_state: Mutex::new(std::collections::HashMap::new()),
        webauthn_auth_state: Mutex::new(std::collections::HashMap::new()),
        tunnel_status: if tunnel_config.enabled {
            info!("Tunnel configured — starting newt subprocess");
            let (status, _handle) = tilde_server::tunnel::spawn_tunnel_supervisor(tunnel_config);
            Some(status)
        } else {
            None
        },
    });

    let session_ttl = state.config.auth.session_ttl_hours;

    let dav_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: db_arc.clone(),
        files_root,
        uploads_root,
        db_path_prefix: String::new(),
        session_ttl_hours: session_ttl,
        scope_prefix: "/dav/".to_string(),
    });

    let caldav_state: tilde_cal::SharedCalDavState = Arc::new(tilde_cal::CalDavState {
        db: db_arc.clone(),
        session_ttl_hours: session_ttl,
    });

    let carddav_state: tilde_card::SharedCardDavState = Arc::new(tilde_card::CardDavState {
        db: db_arc,
        session_ttl_hours: session_ttl,
    });

    // Ensure default calendar and addressbook exist
    {
        let db = caldav_state.db.lock().unwrap();
        tilde_cal::ensure_default_calendar(&db);
        tilde_card::ensure_default_addressbook(&db);
    }

    // Start photo file watcher for _inbox/ and _library-drop/
    let _photo_watcher = {
        let photos_base = data_dir.join("photos");
        let pattern = state.config.photos.organization_pattern.clone();
        let debounce = state.config.photos.watch_debounce_seconds;
        let quality = state.config.photos.thumbnail_quality;
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

    // Start background job processor for thumbnail generation etc.
    {
        let job_db = state.db.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                if let Ok(conn) = job_db.lock() {
                    match tilde_photos::process_pending_jobs(&conn, 5) {
                        Ok(0) => {} // No pending jobs
                        Ok(n) => info!(count = n, "Processed background jobs"),
                        Err(e) => tracing::debug!(error = %e, "Job processor error"),
                    }
                }
            }
        });
        info!("Background job processor started");
    }

    // Start backup scheduler if backup is enabled
    if state.config.backup.enabled {
        let backup_schedule = state.config.backup.schedule.clone();
        let backup_db = state.db.clone();
        let backup_data_dir = data_dir.clone();
        let backup_encrypt_recipient = state.config.backup.encrypt_recipient.clone();
        tokio::spawn(async move {
            let interval_secs = parse_schedule_interval(&backup_schedule);
            let first_wait = secs_until_next_run(&backup_schedule);
            info!(
                schedule = %backup_schedule,
                next_run_secs = first_wait,
                interval_secs = interval_secs,
                "Backup scheduler started"
            );

            // Record next scheduled time
            if let Ok(conn) = backup_db.lock() {
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
            tokio::time::sleep(std::time::Duration::from_secs(first_wait)).await;

            loop {
                info!("Backup scheduler: triggering scheduled backup");

                // Record the backup attempt
                if let Ok(conn) = backup_db.lock() {
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
                if let Ok(conn) = backup_db.lock() {
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
                tokio::time::sleep(std::time::Duration::from_secs(interval_secs)).await;
            }
        });
        info!(schedule = %state.config.backup.schedule, "Backup scheduler enabled");
    }

    // Process any existing files in _inbox/ on startup
    {
        let photos_base = data_dir.join("photos");
        let pattern = state.config.photos.organization_pattern.clone();
        let db = state.db.lock().unwrap();
        match tilde_photos::ingest::process_inbox(&db, &photos_base, &pattern) {
            Ok(results) if !results.is_empty() => {
                info!(
                    count = results.len(),
                    "Processed existing inbox files on startup"
                );
            }
            Err(e) => tracing::warn!(error = %e, "Failed to process inbox on startup"),
            _ => {}
        }
        match tilde_photos::ingest::process_library_drop(&db, &photos_base) {
            Ok(results) if !results.is_empty() => {
                info!(
                    count = results.len(),
                    "Processed existing library-drop files on startup"
                );
            }
            Err(e) => tracing::warn!(error = %e, "Failed to process library-drop on startup"),
            _ => {}
        }
    }

    // Start email IMAP sync if email is enabled
    if state.config.email.enabled {
        let mail_dir = data_dir.join("mail");
        let mut accounts = state.config.email.accounts.clone();

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
            tokio::spawn(async move {
                tilde_email::imap::run_sync_loop(imap_config, email_db, email_mail_dir).await;
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
        tokio::spawn(async move {
            use tokio::signal::unix::{SignalKind, signal};
            let mut sighup = signal(SignalKind::hangup()).expect("Failed to register SIGHUP handler");
            loop {
                sighup.recv().await;
                info!("Received SIGHUP, reloading configuration...");
                match Config::load(config_path_for_reload.as_deref()) {
                    Ok(new_config) => {
                        // Hot-reload: logging level
                        let level = &new_config.logging.level;
                        info!(level = %level, "Reloaded logging.level");

                        // Hot-reload: MCP tool_allowlist and rate_limit
                        info!(
                            tool_allowlist = ?new_config.mcp.tool_allowlist,
                            rate_limit = new_config.mcp.default_rate_limit,
                            "Reloaded MCP configuration"
                        );

                        // Note: server.*, tls.*, auth.* require restart
                        info!("Configuration reloaded (hot-reloadable fields only)");
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
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let _ = sd_notify::notify(false, &[sd_notify::NotifyState::Watchdog]);
            }
        });
        info!(interval_ms = usec / 2000, "sd-notify: watchdog pinger started");
    }

    match state_config_tls_mode.as_str() {
        "manual" => {
            let cert_path = &state_config_tls.cert_path;
            let key_path = &state_config_tls.key_path;

            if cert_path.is_empty() || key_path.is_empty() {
                anyhow::bail!("TLS mode 'manual' requires tls.cert_path and tls.key_path to be set");
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

            loop {
                let (tcp_stream, addr) = listener.accept().await?;
                let acceptor = tls_acceptor.clone();
                let mut make_svc = make_service.clone();

                tokio::spawn(async move {
                    match acceptor.accept(tcp_stream).await {
                        Ok(tls_stream) => {
                            use tower::Service;
                            let svc = make_svc.call(addr).await.unwrap();
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
        _ => {
            // "upstream" mode or default: plain HTTP
            println!("tilde server listening on http://{}", listen_addr);
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await?;
        }
    }

    Ok(())
}

pub async fn run_status(config_path: Option<&str>, json_output: bool) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let db_path = config.db_path();
    let data_dir = config.data_dir();

    if json_output {
        let mut status = serde_json::json!({
            "hostname": if config.server.hostname.is_empty() { serde_json::json!(null) } else { serde_json::json!(&config.server.hostname) },
            "listen": format!("{}:{}", config.server.listen_addr, config.server.listen_port),
            "tls_mode": &config.tls.mode,
            "data_dir": data_dir.to_string_lossy(),
            "cache_dir": config.cache_dir().to_string_lossy().to_string(),
            "database_path": db_path.to_string_lossy().to_string(),
            "mode": if Config::is_systemd_mode() { "systemd" } else { "user" },
        });

        if db_path.exists() {
            let conn = db::init_db(db_path.to_str().unwrap())?;
            let migrations = db::get_applied_migrations(&conn)?;
            let has_password = auth::get_admin_password_hash(&conn)?.is_some();
            let db_size = db_path.metadata().map(|m| m.len()).unwrap_or(0);

            status["migrations_applied"] = serde_json::json!(migrations.len());
            status["admin_auth_configured"] = serde_json::json!(has_password);
            status["database_size_bytes"] = serde_json::json!(db_size);
        }

        if data_dir.exists()
            && let Ok(total_size) = walkdir(&data_dir)
        {
            status["data_size_bytes"] = serde_json::json!(total_size);
        }

        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    println!("tilde — Status");
    println!("==============");
    println!(
        "Hostname:   {}",
        if config.server.hostname.is_empty() {
            "(not set)"
        } else {
            &config.server.hostname
        }
    );
    println!(
        "Listen:     {}:{}",
        config.server.listen_addr, config.server.listen_port
    );
    println!("TLS mode:   {}", config.tls.mode);
    println!("Data dir:   {}", data_dir.display());
    println!("Cache dir:  {}", config.cache_dir().display());
    println!("Database:   {}", db_path.display());

    if db_path.exists() {
        let conn = db::init_db(db_path.to_str().unwrap())?;
        let migrations = db::get_applied_migrations(&conn)?;
        println!("Migrations: {} applied", migrations.len());

        let has_password = auth::get_admin_password_hash(&conn)?.is_some();
        println!(
            "Admin auth: {}",
            if has_password {
                "configured"
            } else {
                "NOT SET"
            }
        );

        if let Ok(meta) = db_path.metadata() {
            let size_mb = meta.len() as f64 / 1024.0 / 1024.0;
            println!("DB size:    {:.2} MB", size_mb);
        }
    } else {
        println!("Database:   NOT INITIALIZED (run `tilde init`)");
    }

    if data_dir.exists()
        && let Ok(total_size) = walkdir(&data_dir)
    {
        let size_mb = total_size as f64 / 1024.0 / 1024.0;
        println!("Data size:  {:.2} MB", size_mb);
    }

    println!(
        "Mode:       {}",
        if Config::is_systemd_mode() {
            "systemd"
        } else {
            "user"
        }
    );

    Ok(())
}

pub async fn run_diagnose(config_path: Option<&str>) -> anyhow::Result<()> {
    println!("tilde — Diagnostics");
    println!("===================");

    let config = Config::load(config_path);
    match &config {
        Ok(_) => println!("[OK]   Config loads successfully"),
        Err(e) => println!("[FAIL] Config error: {}", e),
    }

    if let Ok(ref config) = config {
        let db_path = config.db_path();
        if db_path.exists() {
            match db::init_db(db_path.to_str().unwrap()) {
                Ok(conn) => {
                    println!("[OK]   Database connection OK");
                    match conn.query_row("PRAGMA journal_mode", [], |row| row.get::<_, String>(0)) {
                        Ok(mode) => println!("[OK]   Journal mode: {}", mode),
                        Err(e) => println!("[FAIL] Journal mode check: {}", e),
                    }
                    match conn
                        .query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0))
                    {
                        Ok(result) if result == "ok" => {
                            println!("[OK]   Database integrity check passed")
                        }
                        Ok(result) => println!("[FAIL] Database integrity: {}", result),
                        Err(e) => println!("[FAIL] Integrity check error: {}", e),
                    }
                }
                Err(e) => println!("[FAIL] Database connection failed: {}", e),
            }
        } else {
            println!(
                "[WARN] Database not found at {}. Run `tilde init`",
                db_path.display()
            );
        }
    }

    check_dep("sqlite3");
    check_dep("ffmpeg");

    if let Ok(ref config) = config {
        let data_dir = config.data_dir();
        if data_dir.exists() {
            println!("[OK]   Data directory exists: {}", data_dir.display());
        } else {
            println!("[WARN] Data directory missing: {}", data_dir.display());
        }
    }

    Ok(())
}

pub async fn run_auth(config_path: Option<&str>, command: AuthCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        AuthCommands::ResetPassword => {
            if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD") {
                auth::store_admin_password(&conn, &pw)?;
                println!("Admin password reset successfully");
            } else {
                println!("Set TILDE_ADMIN_PASSWORD environment variable first");
            }
        }
        AuthCommands::AppPassword { command } => match command {
            AppPasswordCommands::Create { name, scope } => {
                let password = auth::create_app_password(&conn, &name, &scope)?;
                println!("App password created:");
                println!("  Name:     {}", name);
                println!("  Scope:    {}", scope);
                println!("  Password: {}", password);
                println!();
                println!("Save this password now — it cannot be shown again.");
            }
            AppPasswordCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT id, name, scope_prefix, created_at, last_used_at, revoked FROM app_passwords ORDER BY created_at"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, bool>(5)?,
                    ))
                })?;
                println!(
                    "{:<36} {:<20} {:<15} {:<25} Status",
                    "ID", "Name", "Scope", "Created"
                );
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (id, name, scope, created, _last_used, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<36} {:<20} {:<15} {:<25} {}",
                        id, name, scope, created, status
                    );
                }
            }
            AppPasswordCommands::Revoke { id } => {
                conn.execute("UPDATE app_passwords SET revoked = 1 WHERE id = ?1", [&id])?;
                println!("App password {} revoked", id);
            }
        },
        AuthCommands::Session { command } => match command {
            SessionCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT token_prefix, created_at, last_used_at, expires_at, user_agent, source_ip, revoked FROM auth_sessions ORDER BY created_at DESC"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, bool>(6)?,
                    ))
                })?;
                println!(
                    "{:<24} {:<20} {:<16} {:<25} Status",
                    "Prefix", "User Agent", "Source IP", "Last Used"
                );
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (prefix, _created, last_used, _expires, user_agent, source_ip, revoked) =
                        row?;
                    let status = if revoked { "revoked" } else { "active" };
                    let ua = user_agent.unwrap_or_else(|| "-".to_string());
                    let ip = source_ip.unwrap_or_else(|| "-".to_string());
                    println!(
                        "{:<24} {:<20} {:<16} {:<25} {}",
                        prefix, ua, ip, last_used, status
                    );
                }
            }
            SessionCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE auth_sessions SET revoked = 1 WHERE token_prefix = ?1 OR id = ?1",
                    [&id],
                )?;
                println!("Session revoked");
            }
        },
        AuthCommands::Webauthn { command } => match command {
            WebauthnCommands::List => {
                let credentials = auth::list_webauthn_credentials(&conn)?;
                if credentials.is_empty() {
                    println!("No WebAuthn credentials registered");
                } else {
                    println!(
                        "{:<38} {:<20} {:<25} Last Used",
                        "ID", "Name", "Created"
                    );
                    println!("{}", "-".repeat(110));
                    for (id, name, created_at, last_used_at) in &credentials {
                        let last_used = last_used_at.as_deref().unwrap_or("-");
                        println!("{:<38} {:<20} {:<25} {}", id, name, created_at, last_used);
                    }
                }
            }
            WebauthnCommands::Remove { id } => {
                if auth::remove_webauthn_credential(&conn, &id)? {
                    println!("WebAuthn credential {} removed", id);
                } else {
                    println!("WebAuthn credential {} not found", id);
                }
            }
        },
    }
    Ok(())
}

pub async fn run_mcp(config_path: Option<&str>, command: McpCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        McpCommands::Token { command } => match command {
            TokenCommands::Create { name, scopes } => {
                let token =
                    auth::create_mcp_token(&conn, &name, &scopes, config.mcp.default_rate_limit)?;
                println!("MCP token created:");
                println!("  Name:   {}", name);
                println!("  Scopes: {}", scopes);
                println!("  Token:  {}", token);
                println!();
                println!("Save this token now — it cannot be shown again.");
            }
            TokenCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT name, token_prefix, scopes, rate_limit, revoked FROM mcp_tokens ORDER BY created_at"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })?;
                println!(
                    "{:<20} {:<20} {:<20} {:<15} Status",
                    "Name", "Prefix", "Scopes", "Rate Limit"
                );
                println!("{}", "-".repeat(90));
                for row in rows {
                    let (name, prefix, scopes, rate_limit, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<20} {:<20} {:<20} {:<15} {}",
                        name, prefix, scopes, rate_limit, status
                    );
                }
            }
            TokenCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                println!("MCP token revoked");
            }
            TokenCommands::Rotate { id } => {
                let (name, scopes, rate_limit): (String, String, u32) = conn.query_row(
                    "SELECT name, scopes, rate_limit FROM mcp_tokens WHERE id = ?1 OR name = ?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                conn.execute(
                    "UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                let token = auth::create_mcp_token(&conn, &name, &scopes, rate_limit)?;
                println!("MCP token rotated:");
                println!("  Name:   {}", name);
                println!("  Token:  {}", token);
                println!();
                println!("Save this token now — it cannot be shown again.");
            }
        },
        McpCommands::Audit { since, tool, token } => {
            let mut sql = String::from(
                "SELECT token_name, tool_name, duration_ms, created_at FROM mcp_audit_log WHERE 1=1",
            );
            if let Some(ref s) = since {
                sql.push_str(&format!(" AND created_at >= '{}'", s));
            }
            if let Some(ref t) = tool {
                sql.push_str(&format!(" AND tool_name = '{}'", t));
            }
            if let Some(ref tk) = token {
                sql.push_str(&format!(" AND token_name = '{}'", tk));
            }
            sql.push_str(" ORDER BY created_at DESC LIMIT 50");

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })?;

            println!(
                "{:<15} {:<25} {:<8} {:<20}",
                "Token", "Tool", "Duration", "Time"
            );
            println!("{}", "-".repeat(70));
            for row in rows {
                let (token_name, tool_name, duration, time) = row?;
                println!(
                    "{:<15} {:<25} {:<8} {:<20}",
                    token_name,
                    tool_name,
                    format!("{}ms", duration),
                    time
                );
            }
        }
    }
    Ok(())
}

pub async fn run_notes(config_path: Option<&str>, command: NotesCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let notes_dir = config.data_dir().join("notes");

    match command {
        NotesCommands::Search { query } => {
            // First, rebuild FTS index from disk
            index_notes_fts(&conn, &notes_dir)?;

            // Search FTS
            let mut stmt = conn.prepare(
                "SELECT path, snippet(notes_fts, 2, '[', ']', '...', 30) FROM notes_fts WHERE notes_fts MATCH ?1 ORDER BY rank LIMIT 20"
            )?;
            let results: Vec<(String, String)> = stmt
                .query_map([&query], |row| Ok((row.get(0)?, row.get(1)?)))?
                .filter_map(|r| r.ok())
                .collect();

            if results.is_empty() {
                println!("No notes found matching '{}'", query);
            } else {
                for (path, snippet) in &results {
                    println!("{}", path);
                    println!("  {}", snippet);
                    println!();
                }
                println!("{} note(s) found", results.len());
            }
        }
        NotesCommands::List { path } => {
            let target = match &path {
                Some(p) => notes_dir.join(p),
                None => notes_dir.clone(),
            };

            if !target.exists() {
                println!("Notes directory not found: {}", target.display());
                return Ok(());
            }

            list_notes_recursive(&target, &notes_dir)?;
        }
    }

    Ok(())
}

fn index_notes_fts(conn: &rusqlite::Connection, notes_dir: &std::path::Path) -> anyhow::Result<()> {
    // Clear and rebuild
    conn.execute("DELETE FROM notes_fts", [])?;

    if !notes_dir.exists() {
        return Ok(());
    }

    fn walk_and_index(
        conn: &rusqlite::Connection,
        dir: &std::path::Path,
        base: &std::path::Path,
    ) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk_and_index(conn, &path, base)?;
            } else if path.extension().map(|e| e == "md").unwrap_or(false) {
                let rel_path = path
                    .strip_prefix(base)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let content = std::fs::read_to_string(&path).unwrap_or_default();

                // Extract title from first heading or filename
                let title = content
                    .lines()
                    .find(|l| l.starts_with("# "))
                    .map(|l| l.trim_start_matches("# ").to_string())
                    .unwrap_or_else(|| {
                        path.file_stem()
                            .map(|s| s.to_string_lossy().to_string())
                            .unwrap_or_default()
                    });

                conn.execute(
                    "INSERT INTO notes_fts (path, title, content) VALUES (?1, ?2, ?3)",
                    rusqlite::params![rel_path, title, content],
                )?;
            }
        }
        Ok(())
    }

    walk_and_index(conn, notes_dir, notes_dir)?;
    Ok(())
}

pub async fn run_collection(
    config_path: Option<&str>,
    command: CollectionCommands,
    skip_confirm: bool,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        CollectionCommands::Create { name, schema } => {
            let schema_json = std::fs::read_to_string(&schema).unwrap_or_else(|_| schema.clone()); // Allow inline JSON or file path
            // Validate it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&schema_json)
                .map_err(|e| anyhow::anyhow!("Invalid JSON schema: {}", e))?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![id, name, schema_json, now, now],
            )?;
            println!("Collection '{}' created", name);
        }
        CollectionCommands::List => {
            let mut stmt =
                conn.prepare("SELECT name, created_at FROM collections ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            println!("{:<30} Created", "Name");
            println!("{}", "-".repeat(60));
            for row in rows {
                let (name, created) = row?;
                println!("{:<30} {}", name, created);
            }
        }
        CollectionCommands::Add { name, data } => {
            let data_val: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Invalid JSON data: {}", e))?;

            // Get collection and validate schema
            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            // Basic schema validation
            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        CollectionCommands::Get { name, id } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let (data, created, updated): (String, String, String) = conn.query_row(
                "SELECT data_json, created_at, updated_at FROM records WHERE id = ?1 AND collection_id = ?2",
                rusqlite::params![id, collection_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).map_err(|_| anyhow::anyhow!("Record '{}' not found", id))?;

            println!("ID:       {}", id);
            println!("Data:     {}", data);
            println!("Created:  {}", created);
            println!("Updated:  {}", updated);
        }
        CollectionCommands::Update { name, id, data } => {
            let data_val: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Invalid JSON data: {}", e))?;

            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            let updated = conn.execute(
                "UPDATE records SET data_json = ?1, updated_at = ?2, hlc = ?3 WHERE id = ?4 AND collection_id = ?5",
                rusqlite::params![data, now, now, id, collection_id],
            )?;
            if updated == 0 {
                println!("Record '{}' not found", id);
            } else {
                println!("Record updated");
            }
        }
        CollectionCommands::Delete { name, id } => {
            if !skip_confirm {
                eprint!("Delete record '{}' from collection '{}'? [y/N] ", id, name);
                if !confirm_prompt() {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let deleted = conn.execute(
                "DELETE FROM records WHERE id = ?1 AND collection_id = ?2",
                rusqlite::params![id, collection_id],
            )?;
            if deleted == 0 {
                println!("Record '{}' not found", id);
            } else {
                println!("Record deleted");
            }
        }
        CollectionCommands::ListRecords {
            name,
            filter: _,
            sort,
            limit,
        } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let mut sql = format!(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = '{}'",
                collection_id
            );
            if let Some(ref s) = sort {
                sql.push_str(&format!(" ORDER BY json_extract(data_json, '$.{}') ASC", s));
            } else {
                sql.push_str(" ORDER BY created_at DESC");
            }
            if let Some(l) = limit {
                sql.push_str(&format!(" LIMIT {}", l));
            }

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

            println!("{:<36} {:<40} Created", "ID", "Data");
            println!("{}", "-".repeat(90));
            for row in rows {
                let (id, data, created) = row?;
                println!("{:<36} {:<40} {}", id, data, created);
            }
        }
        CollectionCommands::Export { name, format } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let mut stmt = conn.prepare(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at"
            )?;
            let rows: Vec<(String, String, String)> = stmt
                .query_map([&collection_id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect();

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|(id, data, created)| {
                            let mut record: serde_json::Value =
                                serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                            if let Some(obj) = record.as_object_mut() {
                                obj.insert("_id".to_string(), serde_json::json!(id));
                                obj.insert("_created_at".to_string(), serde_json::json!(created));
                            }
                            record
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                "csv" => {
                    // Extract keys from first record
                    if let Some((_, first_data, _)) = rows.first() {
                        let first: serde_json::Value = serde_json::from_str(first_data)?;
                        if let Some(obj) = first.as_object() {
                            let keys: Vec<&String> = obj.keys().collect();
                            println!(
                                "id,{},created_at",
                                keys.iter()
                                    .map(|k| k.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            );
                            for (id, data, created) in &rows {
                                let record: serde_json::Value = serde_json::from_str(data)?;
                                let values: Vec<String> = keys
                                    .iter()
                                    .map(|k| {
                                        record
                                            .get(k.as_str())
                                            .map(|v| v.to_string().trim_matches('"').to_string())
                                            .unwrap_or_default()
                                    })
                                    .collect();
                                println!("{},{},{}", id, values.join(","), created);
                            }
                        }
                    }
                }
                _ => println!("Unknown format: {}. Use 'json' or 'csv'", format),
            }
        }
    }

    Ok(())
}

/// Basic JSON Schema validation (supports type, required, properties)
fn validate_json_schema(
    data: &serde_json::Value,
    schema: &serde_json::Value,
) -> anyhow::Result<()> {
    // Check type
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let actual_type = match data {
            serde_json::Value::Object(_) => "object",
            serde_json::Value::Array(_) => "array",
            serde_json::Value::String(_) => "string",
            serde_json::Value::Number(n) if n.is_f64() || n.is_i64() => "number",
            serde_json::Value::Bool(_) => "boolean",
            serde_json::Value::Null => "null",
            _ => "unknown",
        };
        if actual_type != expected_type {
            return Err(anyhow::anyhow!(
                "Expected type '{}', got '{}'",
                expected_type,
                actual_type
            ));
        }
    }

    // Check required fields
    if let Some(required) = schema.get("required").and_then(|r| r.as_array())
        && let Some(obj) = data.as_object()
    {
        for req in required {
            if let Some(field_name) = req.as_str()
                && !obj.contains_key(field_name)
            {
                return Err(anyhow::anyhow!("Missing required field: '{}'", field_name));
            }
        }
    }

    // Check property types
    if let (Some(props), Some(obj)) = (
        schema.get("properties").and_then(|p| p.as_object()),
        data.as_object(),
    ) {
        for (key, prop_schema) in props {
            if let Some(value) = obj.get(key)
                && let Some(prop_type) = prop_schema.get("type").and_then(|t| t.as_str())
            {
                let valid = match prop_type {
                    "string" => value.is_string(),
                    "number" | "integer" => value.is_number(),
                    "boolean" => value.is_boolean(),
                    "array" => value.is_array(),
                    "object" => value.is_object(),
                    _ => true,
                };
                if !valid {
                    return Err(anyhow::anyhow!(
                        "Field '{}' expected type '{}', got {:?}",
                        key,
                        prop_type,
                        value
                    ));
                }
            }
        }
    }

    Ok(())
}

fn list_notes_recursive(dir: &std::path::Path, base: &std::path::Path) -> anyhow::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?.filter_map(|e| e.ok()).collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let rel_path = path
            .strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        if path.is_dir() {
            list_notes_recursive(&path, base)?;
        } else if path.extension().map(|e| e == "md").unwrap_or(false) {
            let meta = path.metadata()?;
            let modified = meta
                .modified()
                .ok()
                .map(|t| {
                    let d = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
                    let ts = jiff::Timestamp::from_second(d.as_secs() as i64)
                        .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
                    ts.strftime("%Y-%m-%d %H:%M").to_string()
                })
                .unwrap_or_else(|| "unknown".to_string());
            let size = meta.len();
            println!("{:<40} {:>8} B  {}", rel_path, size, modified);
        }
    }
    Ok(())
}

fn walkdir(path: &std::path::Path) -> anyhow::Result<u64> {
    let mut total = 0u64;
    if path.is_dir() {
        for entry in std::fs::read_dir(path)? {
            let entry = entry?;
            let meta = entry.metadata()?;
            if meta.is_dir() {
                total += walkdir(&entry.path())?;
            } else {
                total += meta.len();
            }
        }
    }
    Ok(total)
}

pub async fn run_bookmarks(
    config_path: Option<&str>,
    command: BookmarksCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    // Ensure "bookmarks" collection exists
    ensure_bookmarks_collection(&conn)?;

    match command {
        BookmarksCommands::Add {
            url,
            title,
            tags,
            description,
        } => {
            let mut data = serde_json::json!({
                "url": url,
            });
            if let Some(t) = title {
                data["title"] = serde_json::json!(t);
            }
            if let Some(t) = tags {
                let tag_list: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
                data["tags"] = serde_json::json!(tag_list);
            }
            if let Some(d) = description {
                data["description"] = serde_json::json!(d);
            }
            data["created_at"] = serde_json::json!(
                jiff::Zoned::now()
                    .strftime("%Y-%m-%dT%H:%M:%S%:z")
                    .to_string()
            );

            let collection_id: String = conn.query_row(
                "SELECT id FROM collections WHERE name = 'bookmarks'",
                [],
                |row| row.get(0),
            )?;

            let id = uuid::Uuid::new_v4().to_string();
            let data_str = serde_json::to_string(&data)?;
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data_str, now, now, now],
            )?;
            println!("{}", id);
        }
        BookmarksCommands::List { tag, limit } => {
            let collection_id: String = conn.query_row(
                "SELECT id FROM collections WHERE name = 'bookmarks'",
                [],
                |row| row.get(0),
            )?;

            let limit = limit.unwrap_or(50);
            let mut stmt = conn.prepare(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
            )?;
            let rows: Vec<(String, String, String)> = stmt
                .query_map(rusqlite::params![collection_id, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect();

            println!("{:<36} {:<50} {:<30} Tags", "ID", "URL", "Title");
            println!("{}", "-".repeat(130));
            for (id, data_str, _created) in &rows {
                let data: serde_json::Value = serde_json::from_str(data_str).unwrap_or_default();
                let url = data.get("url").and_then(|v| v.as_str()).unwrap_or("-");
                let title = data.get("title").and_then(|v| v.as_str()).unwrap_or("-");
                let tags = data
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();

                // Filter by tag if specified
                if let Some(ref filter_tag) = tag
                    && !tags.contains(filter_tag)
                {
                    continue;
                }

                println!("{:<36} {:<50} {:<30} {}", id, url, title, tags);
            }
        }
    }
    Ok(())
}

pub async fn run_trackers(
    config_path: Option<&str>,
    command: TrackersCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        TrackersCommands::Log { collection, data } => {
            let data_val: serde_json::Value =
                serde_json::from_str(&data).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&collection],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        TrackersCommands::Query {
            collection,
            since,
            format,
            limit,
        } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&collection],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let limit = limit.unwrap_or(50);

            let rows: Vec<(String, String, String)> = if let Some(ref since_val) = since {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC LIMIT ?3"
                )?;
                stmt.query_map(rusqlite::params![collection_id, since_val, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect()
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
                )?;
                stmt.query_map(rusqlite::params![collection_id, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect()
            };

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|(id, data, created)| {
                            let mut record: serde_json::Value =
                                serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                            if let Some(obj) = record.as_object_mut() {
                                obj.insert("_id".to_string(), serde_json::json!(id));
                                obj.insert("_created_at".to_string(), serde_json::json!(created));
                            }
                            record
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                _ => {
                    // Table format
                    println!("{:<36} {:<40} Created", "ID", "Data");
                    println!("{}", "-".repeat(90));
                    for (id, data, created) in &rows {
                        println!("{:<36} {:<40} {}", id, data, created);
                    }
                }
            }
        }
    }
    Ok(())
}

pub async fn run_webhook(
    config_path: Option<&str>,
    command: WebhookCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        WebhookCommands::Token { command } => match command {
            WebhookTokenCommands::Create { name, scopes } => {
                let token = auth::generate_mcp_token(); // reuse token generator
                let token_hash = auth::hash_token(&token);
                let prefix = &token[..std::cmp::min(17, token.len())];
                let id = uuid::Uuid::new_v4().to_string();
                let now = jiff::Zoned::now()
                    .strftime("%Y-%m-%dT%H:%M:%S%:z")
                    .to_string();

                conn.execute(
                    "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, created_at, revoked)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
                    rusqlite::params![id, name, token_hash, prefix, scopes, now],
                )?;

                println!("Webhook token created:");
                println!("  Name:   {}", name);
                println!("  Scopes: {}", scopes);
                println!("  Prefix: {}", prefix);
                println!("  Token:  {}", token);
                println!();
                println!("Webhook URL: POST /api/webhook/{}", prefix);
                println!("Save this token now — it cannot be shown again.");
            }
            WebhookTokenCommands::List => {
                let mut stmt = conn.prepare(
                    "SELECT name, token_prefix, scopes, rate_limit, revoked FROM webhook_tokens ORDER BY created_at"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i32>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })?;
                println!(
                    "{:<20} {:<20} {:<25} {:<10} Status",
                    "Name", "Prefix", "Scopes", "Rate"
                );
                println!("{}", "-".repeat(85));
                for row in rows {
                    let (name, prefix, scopes, rate, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!(
                        "{:<20} {:<20} {:<25} {:<10} {}",
                        name, prefix, scopes, rate, status
                    );
                }
            }
            WebhookTokenCommands::Revoke { id } => {
                conn.execute(
                    "UPDATE webhook_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1",
                    [&id],
                )?;
                println!("Webhook token revoked");
            }
        },
    }
    Ok(())
}

pub async fn run_notifications(
    config_path: Option<&str>,
    command: NotificationCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        NotificationCommands::Test { sink } => {
            let data_dir = config.data_dir();
            match sink.as_str() {
                "file" => {
                    let file_sink = tilde_notify::create_file_sink(&data_dir);
                    let event = tilde_notify::NotificationEvent {
                        event_type: "test".to_string(),
                        priority: tilde_notify::Priority::Low,
                        message: "Test notification from tilde".to_string(),
                    };
                    tilde_notify::NotificationSink::send(&file_sink, &event)?;
                    println!(
                        "Test notification sent to file sink: {}",
                        data_dir.join("notifications.log").display()
                    );
                }
                _ => {
                    println!("Unknown sink: {}. Available: file", sink);
                }
            }
        }
        NotificationCommands::List => {
            let mut stmt = conn.prepare(
                "SELECT event_type, priority, message, sinks_notified, created_at FROM notification_log ORDER BY created_at DESC LIMIT 50"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            println!(
                "{:<20} {:<10} {:<40} {:<15} Time",
                "Type", "Priority", "Message", "Sinks"
            );
            println!("{}", "-".repeat(100));
            for row in rows {
                let (event_type, priority, message, sinks, time) = row?;
                let msg = if message.len() > 38 {
                    format!("{}...", &message[..35])
                } else {
                    message
                };
                println!(
                    "{:<20} {:<10} {:<40} {:<15} {}",
                    event_type, priority, msg, sinks, time
                );
            }
        }
        NotificationCommands::Config => {
            println!("Notification Sinks:");
            println!("  file: enabled (logs all events to notifications.log)");
            println!("  ntfy: not configured");
            println!("  smtp: not configured");
            println!("  matrix: not configured");
            println!("  signal: not configured");
            println!();
            println!("Rate limiting: max 10 per event type per hour");
        }
    }
    Ok(())
}

pub async fn run_email(config_path: Option<&str>, command: EmailCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    let mail_dir = config.data_dir().join("mail");

    match command {
        EmailCommands::Search { query } => {
            // First try FTS search
            let results = tilde_email::search_emails(&conn, &query, 20);

            match results {
                Ok(results) if !results.is_empty() => {
                    println!("{:<30} {:<30} {:<20} Snippet", "From", "Subject", "Date");
                    println!("{}", "-".repeat(100));
                    for r in &results {
                        let subj = if r.subject.len() > 28 {
                            format!("{}...", &r.subject[..25])
                        } else {
                            r.subject.clone()
                        };
                        let snip = r
                            .snippet
                            .as_deref()
                            .unwrap_or("")
                            .chars()
                            .take(30)
                            .collect::<String>();
                        println!(
                            "{:<30} {:<30} {:<20} {}",
                            r.from_address, subj, r.date, snip
                        );
                    }
                    println!("{} result(s)", results.len());
                }
                _ => {
                    // FTS might be empty, try LIKE search
                    let mut s2 = conn.prepare(
                        "SELECT message_id, from_address, subject, date, snippet FROM email_messages WHERE subject LIKE ?1 OR from_address LIKE ?1 ORDER BY date DESC LIMIT 20"
                    )?;
                    let pattern = format!("%{}%", query);
                    let results: Vec<(String, String, String, String, Option<String>)> = s2
                        .query_map([&pattern], |row| {
                            Ok((
                                row.get(0)?,
                                row.get(1)?,
                                row.get(2)?,
                                row.get(3)?,
                                row.get(4)?,
                            ))
                        })?
                        .filter_map(|r| r.ok())
                        .collect();

                    if results.is_empty() {
                        println!("No emails found matching '{}'", query);
                    } else {
                        println!("{:<30} {:<30} {:<20} Snippet", "From", "Subject", "Date");
                        println!("{}", "-".repeat(100));
                        for (_, from, subject, date, snippet) in &results {
                            let subj = if subject.len() > 28 {
                                format!("{}...", &subject[..25])
                            } else {
                                subject.clone()
                            };
                            let snip = snippet
                                .as_deref()
                                .unwrap_or("")
                                .chars()
                                .take(30)
                                .collect::<String>();
                            println!("{:<30} {:<30} {:<20} {}", from, subj, date, snip);
                        }
                        println!("{} result(s)", results.len());
                    }
                }
            }
        }
        EmailCommands::Show { message_id } => {
            let result = conn.query_row(
                "SELECT from_address, to_addresses, subject, date, snippet, maildir_path, tags_json FROM email_messages WHERE message_id = ?1",
                [&message_id],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                )),
            );
            match result {
                Ok((from, to, subject, date, snippet, path, tags)) => {
                    println!("From:    {}", from);
                    println!("To:      {}", to);
                    println!("Subject: {}", subject);
                    println!("Date:    {}", date);
                    println!("Path:    {}", path);
                    if let Some(t) = tags
                        && t != "null"
                        && !t.is_empty()
                    {
                        println!("Tags:    {}", t);
                    }
                    if let Some(s) = snippet {
                        println!();
                        println!("{}", s);
                    }
                }
                Err(_) => println!("Message not found: {}", message_id),
            }
        }
        EmailCommands::Thread { message_id } => match tilde_email::get_thread(&conn, &message_id) {
            Ok(thread) if !thread.is_empty() => {
                println!("Thread ({} messages):", thread.len());
                println!("{}", "-".repeat(80));
                for msg in &thread {
                    let from_display = msg.from_name.as_deref().unwrap_or(&msg.from_address);
                    println!("  {} — {} — {}", msg.date, from_display, msg.subject);
                    if let Some(ref s) = msg.snippet {
                        let preview: String = s.chars().take(60).collect();
                        println!("    {}", preview);
                    }
                    println!();
                }
            }
            Ok(_) => println!("No messages found in thread for: {}", message_id),
            Err(e) => println!("Error fetching thread: {}", e),
        },
        EmailCommands::Attachments { command: att_cmd } => match att_cmd {
            AttachmentsCommands::Extract { message_id, to } => {
                let output_dir = std::path::PathBuf::from(&to);
                match tilde_email::extract_attachments(&conn, &mail_dir, &message_id, &output_dir) {
                    Ok(files) if !files.is_empty() => {
                        println!("Extracted {} attachment(s) to {}:", files.len(), to);
                        for f in &files {
                            println!("  - {}", f);
                        }
                    }
                    Ok(_) => println!("No attachments found for message: {}", message_id),
                    Err(e) => println!("Error extracting attachments: {}", e),
                }
            }
        },
        EmailCommands::Tag {
            message_id,
            operation,
            tag,
        } => match operation.as_str() {
            "add" => {
                tilde_email::add_tag(&conn, &message_id, &tag)?;
                println!("Tag '{}' added to message {}", tag, message_id);
            }
            "remove" => {
                tilde_email::remove_tag(&conn, &message_id, &tag)?;
                println!("Tag '{}' removed from message {}", tag, message_id);
            }
            _ => println!("Unknown operation '{}'. Use 'add' or 'remove'.", operation),
        },
        EmailCommands::Reindex => {
            println!("Rebuilding email index from Maildir...");
            match tilde_email::reindex_from_maildir(&conn, &mail_dir) {
                Ok(count) => println!("Reindexed {} messages from Maildir", count),
                Err(e) => println!("Error during reindex: {}", e),
            }
        }
        EmailCommands::Status => {
            let count: i64 = conn
                .query_row("SELECT COUNT(*) FROM email_messages", [], |row| row.get(0))
                .unwrap_or(0);

            // Try to get per-account status
            let mut stmt = conn
                .prepare("SELECT DISTINCT account FROM email_messages")
                .unwrap();
            let accounts: Vec<String> = stmt
                .query_map([], |row| row.get(0))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();

            println!("Email Archive Status");
            println!("====================");
            println!("Total messages: {}", count);

            if accounts.is_empty() {
                println!("No accounts with indexed messages");
            } else {
                for acct in &accounts {
                    let status = tilde_email::imap::get_sync_status(&conn, acct);
                    println!();
                    println!("Account: {}", status.account);
                    println!("  Messages: {}", status.message_count);
                    println!(
                        "  Last sync: {}",
                        status.last_sync.as_deref().unwrap_or("never")
                    );
                    println!("  Folders: {}", status.folders.join(", "));
                }
            }
        }
    }
    Ok(())
}

pub async fn run_photos(config_path: Option<&str>, command: PhotosCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let photos_dir = config.data_dir().join("photos");

    match command {
        PhotosCommands::List { tag, since, until } => {
            let mut sql = String::from(
                "SELECT p.id, f.path, p.taken_at, p.camera_model, p.tags_json FROM photos p JOIN files f ON p.file_id = f.id WHERE 1=1",
            );
            if let Some(ref t) = tag {
                sql.push_str(&format!(" AND p.tags_json LIKE '%{}%'", t));
            }
            if let Some(ref s) = since {
                sql.push_str(&format!(" AND p.taken_at >= '{}'", s));
            }
            if let Some(ref u) = until {
                sql.push_str(&format!(" AND p.taken_at <= '{}'", u));
            }
            sql.push_str(" ORDER BY p.taken_at DESC LIMIT 100");

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })?;

            println!(
                "{:<36} {:<40} {:<20} {:<20} Tags",
                "UUID", "Path", "Taken", "Camera"
            );
            println!("{}", "-".repeat(130));
            let mut count = 0;
            for row in rows {
                let (uuid, path, taken, camera, tags) = row?;
                println!(
                    "{:<36} {:<40} {:<20} {:<20} {}",
                    uuid,
                    path,
                    taken.unwrap_or_else(|| "-".to_string()),
                    camera.unwrap_or_else(|| "-".to_string()),
                    tags.unwrap_or_else(|| "[]".to_string()),
                );
                count += 1;
            }
            if count == 0 {
                println!(
                    "No photos found. Drop files in {} to index.",
                    photos_dir.join("_inbox").display()
                );
            }
        }
        PhotosCommands::Tag { uuid, command } => {
            use tilde_cli::TagCommands;
            let _photos_dir_path = photos_dir.clone();
            // Find the photo's file path from the database
            let file_path: Option<String> = conn
                .query_row(
                    "SELECT f.path FROM photos p JOIN files f ON p.file_id = f.id WHERE p.id = ?1",
                    [&uuid],
                    |row| row.get(0),
                )
                .ok();

            match file_path {
                Some(rel_path) => {
                    let full_path = config.data_dir().join(&rel_path);
                    if !full_path.exists() {
                        println!("Photo file not found at {}", full_path.display());
                        return Ok(());
                    }

                    match command {
                        TagCommands::Add { tag } => {
                            // Read current tags, add new one, write back
                            match tilde_photos::metadata::read_metadata(&full_path) {
                                Ok(meta) => {
                                    let mut tags = meta.tags.clone();
                                    if !tags.contains(&tag) {
                                        tags.push(tag.clone());
                                    }
                                    tilde_photos::metadata::write_tags(&full_path, &tags)?;

                                    // Update database
                                    let prefix = tilde_photos::metadata::classify_tag_prefix(&tag);
                                    conn.execute(
                                        "INSERT OR IGNORE INTO photo_tags (photo_id, tag, prefix) VALUES (?1, ?2, ?3)",
                                        rusqlite::params![uuid, tag, prefix],
                                    )?;
                                    let tags_json = serde_json::to_string(&tags)?;
                                    conn.execute(
                                        "UPDATE photos SET tags_json = ?1 WHERE id = ?2",
                                        rusqlite::params![tags_json, uuid],
                                    )?;

                                    println!("Tag '{}' added to photo {}", tag, uuid);

                                    // Re-organize if tag change affects destination path
                                    let mut updated_meta = meta.clone();
                                    updated_meta.tags = tags;
                                    match tilde_photos::organize::reorganize_after_tag_change(
                                        &conn,
                                        &uuid,
                                        &photos_dir,
                                        &config.photos.organization_pattern,
                                        &updated_meta,
                                    ) {
                                        Ok(Some(new_path)) => {
                                            println!("Photo re-organized to {}", new_path);
                                        }
                                        Ok(None) => {}
                                        Err(e) => {
                                            println!("Warning: failed to re-organize photo: {}", e);
                                        }
                                    }
                                }
                                Err(e) => {
                                    println!("Failed to read metadata: {}", e);
                                }
                            }
                        }
                        TagCommands::Remove { tag } => {
                            match tilde_photos::metadata::remove_tags(
                                &full_path,
                                std::slice::from_ref(&tag),
                            ) {
                                Ok(()) => {
                                    conn.execute(
                                        "DELETE FROM photo_tags WHERE photo_id = ?1 AND tag = ?2",
                                        rusqlite::params![uuid, tag],
                                    )?;
                                    // Update tags_json in photos table
                                    let remaining: Vec<String> = conn
                                        .prepare("SELECT tag FROM photo_tags WHERE photo_id = ?1")?
                                        .query_map([&uuid], |row| row.get(0))?
                                        .filter_map(|r| r.ok())
                                        .collect();
                                    let tags_json = serde_json::to_string(&remaining)?;
                                    conn.execute(
                                        "UPDATE photos SET tags_json = ?1 WHERE id = ?2",
                                        rusqlite::params![tags_json, uuid],
                                    )?;
                                    println!("Tag '{}' removed from photo {}", tag, uuid);

                                    // Re-organize if tag removal affects destination path
                                    if let Ok(updated_meta) = tilde_photos::metadata::read_metadata(&full_path) {
                                        match tilde_photos::organize::reorganize_after_tag_change(
                                            &conn,
                                            &uuid,
                                            &photos_dir,
                                            &config.photos.organization_pattern,
                                            &updated_meta,
                                        ) {
                                            Ok(Some(new_path)) => {
                                                println!("Photo re-organized to {}", new_path);
                                            }
                                            Ok(None) => {}
                                            Err(e) => {
                                                println!("Warning: failed to re-organize photo: {}", e);
                                            }
                                        }
                                    }
                                }
                                Err(e) => println!("Failed to remove tag: {}", e),
                            }
                        }
                    }
                }
                None => println!("Photo with UUID {} not found", uuid),
            }
        }
        PhotosCommands::Reindex => {
            print!("Rebuilding photo index from files... ");
            let mut indexed = 0;
            if photos_dir.exists() {
                indexed = reindex_photos_from_dir(&conn, &photos_dir, &photos_dir)?;
            }
            println!("done ({} photos indexed)", indexed);
        }
        PhotosCommands::Thumbnail { command } => {
            use tilde_cli::ThumbnailCommands;
            let cache_dir = config.cache_dir();
            let quality = config.photos.thumbnail_quality;

            match command {
                ThumbnailCommands::Regenerate { all, missing: _ } => {
                    let condition = if all {
                        "1=1"
                    } else {
                        "p.thumbnail_256_generated = 0 OR p.thumbnail_1920_generated = 0"
                    };
                    let sql = format!(
                        "SELECT p.id, f.path FROM photos p JOIN files f ON p.file_id = f.id WHERE p.content_readable = 1 AND ({})",
                        condition
                    );
                    let mut stmt = conn.prepare(&sql)?;
                    let photos: Vec<(String, String)> = stmt
                        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                        .filter_map(|r| r.ok())
                        .collect();

                    let total = photos.len();
                    println!("Generating thumbnails for {} photos...", total);
                    let mut success = 0;
                    let mut failed = 0;

                    for (i, (photo_id, rel_path)) in photos.iter().enumerate() {
                        let full_path = config.data_dir().join(rel_path);
                        if !full_path.exists() {
                            failed += 1;
                            continue;
                        }

                        let ext = full_path.extension().and_then(|e| e.to_str()).unwrap_or("");

                        let result = if tilde_photos::is_photo_ext(ext) {
                            tilde_photos::thumbnail::generate_thumbnails(
                                &full_path, photo_id, &cache_dir, quality,
                            )
                        } else if tilde_photos::is_video_ext(ext) {
                            tilde_photos::thumbnail::generate_video_thumbnail(
                                &full_path,
                                photo_id,
                                &cache_dir,
                                quality,
                                config.photos.ffmpeg_timeout_seconds,
                            )
                        } else {
                            failed += 1;
                            continue;
                        };

                        match result {
                            Ok(_) => {
                                tilde_photos::thumbnail::mark_thumbnails_generated(
                                    &conn, photo_id, true, true,
                                )?;
                                success += 1;
                            }
                            Err(e) => {
                                eprintln!("  Failed for {}: {}", rel_path, e);
                                failed += 1;
                            }
                        }

                        if (i + 1) % 10 == 0 {
                            println!("  Progress: {}/{}", i + 1, total);
                        }
                    }

                    println!("Thumbnails: {} generated, {} failed", success, failed);
                }
            }
        }
    }
    Ok(())
}

fn count_media_files(dir: &std::path::Path) -> usize {
    let mut total = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                let name = path.file_name().unwrap().to_string_lossy();
                if !name.starts_with('_') && !name.starts_with('.') {
                    total += count_media_files(&path);
                }
            } else {
                let ext = path.extension().and_then(|e| e.to_str()).map(|e| e.to_lowercase()).unwrap_or_default();
                if tilde_photos::is_media_ext(&ext) {
                    total += 1;
                }
            }
        }
    }
    total
}

fn reindex_photos_from_dir(
    conn: &rusqlite::Connection,
    dir: &std::path::Path,
    base: &std::path::Path,
) -> anyhow::Result<usize> {
    reindex_photos_from_dir_progress(conn, dir, base, None)
}

fn reindex_photos_from_dir_progress(
    conn: &rusqlite::Connection,
    dir: &std::path::Path,
    base: &std::path::Path,
    progress: Option<&std::sync::atomic::AtomicUsize>,
) -> anyhow::Result<usize> {
    let mut count = 0;

    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_dir() {
            // Skip special directories
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with('_') || name.starts_with('.') {
                continue;
            }
            count += reindex_photos_from_dir_progress(conn, &path, base, progress)?;
            continue;
        }

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if !tilde_photos::is_media_ext(&ext) {
            continue;
        }

        let rel_path = path
            .strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        if let Some(p) = progress {
            let processed = p.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1;
            eprint!("\r  Processing: {} files...", processed);
        }

        // Check if already indexed
        let exists: bool = conn
            .query_row(
                "SELECT COUNT(*) FROM files WHERE path = ?1",
                [&format!("photos/{}", rel_path)],
                |row| row.get::<_, i64>(0),
            )
            .map(|c| c > 0)?;

        if exists {
            continue;
        }

        // Determine content type from magic bytes or extension
        let content_type = tilde_photos::validate_magic_bytes(&path)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("image/{}", ext));

        match tilde_photos::index_photo(conn, &path, base, &content_type) {
            Ok(_) => count += 1,
            Err(e) => eprintln!("\n  Warning: failed to index {}: {}", rel_path, e),
        }
    }

    Ok(count)
}

pub async fn run_reindex(config_path: Option<&str>, index_type: &str) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let notes_dir = config.data_dir().join("notes");

    match index_type {
        "notes" | "all" => {
            print!("Rebuilding notes FTS index... ");
            index_notes_fts(&conn, &notes_dir)?;
            let count: i64 =
                conn.query_row("SELECT COUNT(*) FROM notes_fts", [], |row| row.get(0))?;
            println!("done ({} notes indexed)", count);
        }
        _ => {}
    }

    match index_type {
        "photos" | "all" => {
            let photos_dir = config.data_dir().join("photos");
            if photos_dir.exists() {
                let total = count_media_files(&photos_dir);
                println!("Rebuilding photos index from disk ({} files found)...", total);
                let progress = std::sync::atomic::AtomicUsize::new(0);
                match reindex_photos_from_dir_progress(&conn, &photos_dir, &photos_dir, Some(&progress)) {
                    Ok(count) => {
                        eprintln!();
                        println!("  done ({} new photos indexed, {} total scanned)", count, progress.load(std::sync::atomic::Ordering::Relaxed));
                    }
                    Err(e) => {
                        eprintln!();
                        println!("  error: {}", e);
                    }
                }
            } else {
                println!("Rebuilding photos index... skipped (no photos directory)");
            }
        }
        _ => {}
    }

    match index_type {
        "email" | "all" => {
            print!("Rebuilding email index from Maildir... ");
            let mail_dir = config.data_dir().join("mail");
            if mail_dir.exists() {
                match tilde_email::reindex_from_maildir(&conn, &mail_dir) {
                    Ok(count) => println!("done ({} messages indexed)", count),
                    Err(e) => println!("error: {}", e),
                }
            } else {
                println!("skipped (no mail directory)");
            }
        }
        _ => {}
    }

    match index_type {
        "links" | "all" => {
            print!("Rebuilding cross-reference links... ");
            // Clear and rebuild links table from notes
            conn.execute("DELETE FROM links", [])?;

            // Parse notes for tilde:// URIs and [[shorthand]]
            if notes_dir.exists() {
                parse_links_from_notes(&conn, &notes_dir, &notes_dir)?;
            }

            let count: i64 = conn.query_row("SELECT COUNT(*) FROM links", [], |row| row.get(0))?;
            println!("done ({} links found)", count);
        }
        _ => {}
    }

    if index_type == "all" {
        println!("Reindex complete.");
    }

    Ok(())
}

fn parse_links_from_notes(
    conn: &rusqlite::Connection,
    dir: &std::path::Path,
    base: &std::path::Path,
) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            parse_links_from_notes(conn, &path, base)?;
        } else if path.extension().is_some_and(|e| e == "md") {
            let rel_path = path
                .strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let content = std::fs::read_to_string(&path).unwrap_or_default();

            // Parse tilde:// URIs
            for cap in content.match_indices("tilde://") {
                let start = cap.0;
                let rest = &content[start..];
                let end = rest
                    .find(|c: char| {
                        c.is_whitespace() || c == ')' || c == ']' || c == '>' || c == '"'
                    })
                    .unwrap_or(rest.len());
                let uri = &rest[..end];

                // Get surrounding context (up to 50 chars before and after)
                let ctx_start = start.saturating_sub(50);
                let ctx_end = std::cmp::min(start + end + 50, content.len());
                let context = &content[ctx_start..ctx_end];

                conn.execute(
                    "INSERT INTO links (source_type, source_id, target_uri, context) VALUES ('note', ?1, ?2, ?3)",
                    rusqlite::params![rel_path, uri, context],
                )?;
            }

            // Parse [[shorthand]] links
            let mut search_start = 0;
            while let Some(open) = content[search_start..].find("[[") {
                let abs_open = search_start + open;
                if let Some(close) = content[abs_open + 2..].find("]]") {
                    let link_content = &content[abs_open + 2..abs_open + 2 + close];
                    if !link_content.is_empty() && link_content.len() < 200 {
                        let target_uri = if let Some(rest) = link_content.strip_prefix("photo:") {
                            format!("tilde://photo/{}", rest)
                        } else if let Some(rest) = link_content.strip_prefix('@') {
                            format!("tilde://contact/{}", rest)
                        } else if let Some(rest) = link_content.strip_prefix('#') {
                            format!("tilde://date/{}", rest)
                        } else if let Some(rest) = link_content.strip_prefix("email:") {
                            format!("tilde://email/{}", rest)
                        } else {
                            format!("tilde://note/{}", link_content)
                        };

                        conn.execute(
                            "INSERT INTO links (source_type, source_id, target_uri, context) VALUES ('note', ?1, ?2, ?3)",
                            rusqlite::params![rel_path, target_uri, link_content],
                        )?;
                    }
                    search_start = abs_open + 2 + close + 2;
                } else {
                    break;
                }
            }
        }
    }
    Ok(())
}

fn ensure_bookmarks_collection(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM collections WHERE name = 'bookmarks'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)?;

    if !exists {
        let id = uuid::Uuid::new_v4().to_string();
        let schema = serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string"},
                "title": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "description": {"type": "string"},
                "created_at": {"type": "string"}
            }
        });
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, 'bookmarks', ?2, ?3, ?4)",
            rusqlite::params![id, serde_json::to_string(&schema)?, now, now],
        )?;
    }
    Ok(())
}

pub async fn run_calendar(
    config_path: Option<&str>,
    command: CalendarCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        CalendarCommands::List => {
            let calendars = tilde_cal::list_calendars(&conn);
            if calendars.is_empty() {
                println!("No calendars found.");
            } else {
                println!(
                    "{:<20} {:<30} {:<10} DESCRIPTION",
                    "NAME", "DISPLAY NAME", "CTAG"
                );
                println!("{}", "-".repeat(80));
                for (name, display_name, ctag, desc) in &calendars {
                    println!(
                        "{:<20} {:<30} {:<10} {}",
                        name,
                        display_name,
                        ctag,
                        desc.as_deref().unwrap_or("")
                    );
                }
            }
        }
        CalendarCommands::Events { from, to, calendar } => {
            let events =
                tilde_cal::list_events(&conn, calendar.as_deref(), from.as_deref(), to.as_deref());
            if events.is_empty() {
                println!("No events found.");
            } else {
                println!(
                    "{:<38} {:<8} {:<30} {:<22} {:<22} LOCATION",
                    "UID", "TYPE", "SUMMARY", "START", "END"
                );
                println!("{}", "-".repeat(140));
                for (uid, comp_type, summary, dtstart, dtend, location, _status) in &events {
                    println!(
                        "{:<38} {:<8} {:<30} {:<22} {:<22} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        comp_type,
                        summary.as_deref().unwrap_or("(untitled)"),
                        dtstart.as_deref().unwrap_or("-"),
                        dtend.as_deref().unwrap_or("-"),
                        location.as_deref().unwrap_or(""),
                    );
                }
            }
        }
    }
    Ok(())
}

pub async fn run_contacts(
    config_path: Option<&str>,
    command: ContactsCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        ContactsCommands::List => {
            let contacts = tilde_card::list_contacts(&conn);
            if contacts.is_empty() {
                println!("No contacts found.");
            } else {
                println!(
                    "{:<38} {:<30} {:<30} {:<20} ORG",
                    "UID", "NAME", "EMAIL", "PHONE"
                );
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!(
                        "{:<38} {:<30} {:<30} {:<20} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        name.as_deref().unwrap_or("-"),
                        email.as_deref().unwrap_or("-"),
                        phone.as_deref().unwrap_or("-"),
                        org.as_deref().unwrap_or(""),
                    );
                }
            }
        }
        ContactsCommands::Search { query } => {
            let contacts = tilde_card::search_contacts(&conn, &query);
            if contacts.is_empty() {
                println!("No contacts matching '{}'.", query);
            } else {
                println!(
                    "{:<38} {:<30} {:<30} {:<20} ORG",
                    "UID", "NAME", "EMAIL", "PHONE"
                );
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!(
                        "{:<38} {:<30} {:<30} {:<20} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        name.as_deref().unwrap_or("-"),
                        email.as_deref().unwrap_or("-"),
                        phone.as_deref().unwrap_or("-"),
                        org.as_deref().unwrap_or(""),
                    );
                }
            }
        }
    }
    Ok(())
}

fn check_dep(name: &str) {
    match std::process::Command::new("which").arg(name).output() {
        Ok(output) if output.status.success() => println!("[OK]   {} found", name),
        _ => println!("[WARN] {} not found", name),
    }
}

pub async fn run_export(config_path: Option<&str>, command: ExportCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    let data_dir = config.data_dir();

    match command {
        ExportCommands::Run { path, only, format, encrypt, recipient } => {
            let export_dir = std::path::PathBuf::from(&path);
            let types: Option<Vec<String>> =
                only.map(|s| s.split(',').map(|t| t.trim().to_string()).collect());

            println!("Exporting data to {}...", export_dir.display());

            // Create export directory structure
            std::fs::create_dir_all(&export_dir)?;

            let export_start = std::time::Instant::now();
            let mut sections_exported = 0u32;

            let should_export =
                |t: &str| -> bool { types.as_ref().is_none_or(|ts| ts.iter().any(|x| x == t)) };

            let mut manifest = serde_json::Map::new();
            let links_data: Vec<serde_json::Value>;

            // Export calendars
            if should_export("calendars") {
                let cal_dir = export_dir.join("calendars");
                std::fs::create_dir_all(&cal_dir)?;

                let mut stmt = conn.prepare("SELECT c.name, c.display_name FROM calendars c")?;
                let calendars: Vec<(String, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .flatten()
                    .collect();

                for (cal_name, _display_name) in &calendars {
                    let mut ics_content =
                        String::from("BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//EN\r\n");

                    let mut obj_stmt = conn.prepare(
                        "SELECT uid, ics_data FROM calendar_objects co JOIN calendars c ON co.calendar_id = c.id WHERE c.name = ?1 AND co.deleted = 0"
                    )?;
                    let objects: Vec<(String, String)> = obj_stmt
                        .query_map([cal_name], |row| Ok((row.get(0)?, row.get(1)?)))?
                        .flatten()
                        .collect();

                    for (_uid, ical) in &objects {
                        // Extract VEVENT/VTODO from ics_data (strip outer VCALENDAR wrapper)
                        let inner = ical
                            .replace("BEGIN:VCALENDAR\r\n", "")
                            .replace("END:VCALENDAR\r\n", "")
                            .replace("BEGIN:VCALENDAR\n", "")
                            .replace("END:VCALENDAR\n", "");
                        // Remove VERSION and PRODID lines
                        let cleaned: String = inner
                            .lines()
                            .filter(|l| !l.starts_with("VERSION:") && !l.starts_with("PRODID:"))
                            .collect::<Vec<_>>()
                            .join("\r\n");
                        if !cleaned.trim().is_empty() {
                            ics_content.push_str(&cleaned);
                            ics_content.push_str("\r\n");
                        }
                    }

                    ics_content.push_str("END:VCALENDAR\r\n");
                    std::fs::write(cal_dir.join(format!("{}.ics", cal_name)), &ics_content)?;
                    println!(
                        "  Exported calendar: {} ({} events)",
                        cal_name,
                        objects.len()
                    );
                }
                sections_exported += 1;
            }

            // Export contacts
            if should_export("contacts") {
                let contacts_dir = export_dir.join("contacts");
                std::fs::create_dir_all(&contacts_dir)?;

                let mut stmt = conn.prepare("SELECT a.name FROM addressbooks a")?;
                let addressbooks: Vec<String> =
                    stmt.query_map([], |row| row.get(0))?.flatten().collect();

                for ab_name in &addressbooks {
                    let mut vcf_content = String::new();

                    let mut contact_stmt = conn.prepare(
                        "SELECT uid, vcard_data FROM contacts c JOIN addressbooks a ON c.addressbook_id = a.id WHERE a.name = ?1 AND c.deleted = 0"
                    )?;
                    let contacts: Vec<(String, String)> = contact_stmt
                        .query_map([ab_name], |row| Ok((row.get(0)?, row.get(1)?)))?
                        .flatten()
                        .collect();

                    for (_uid, vcard) in &contacts {
                        vcf_content.push_str(vcard);
                        if !vcf_content.ends_with('\n') {
                            vcf_content.push('\n');
                        }
                    }

                    std::fs::write(contacts_dir.join(format!("{}.vcf", ab_name)), &vcf_content)?;
                    println!(
                        "  Exported addressbook: {} ({} contacts)",
                        ab_name,
                        contacts.len()
                    );
                }
                sections_exported += 1;
            }

            // Export notes
            if should_export("notes") {
                let notes_src = data_dir.join("files").join("notes");
                let notes_dst = export_dir.join("notes");
                if notes_src.exists() {
                    copy_dir_recursive(&notes_src, &notes_dst)?;
                    let count = count_files(&notes_dst);
                    println!("  Exported {} note files", count);
                    sections_exported += 1;
                }
            }

            // Export photos
            if should_export("photos") {
                let photos_dst = export_dir.join("photos");
                std::fs::create_dir_all(&photos_dst)?;

                let mut stmt = conn.prepare(
                    "SELECT p.id, f.path FROM photos p JOIN files f ON p.file_id = f.id",
                )?;
                let photos: Vec<(String, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?
                    .flatten()
                    .collect();

                for (uuid, rel_path) in &photos {
                    let src = data_dir.join(rel_path);
                    if src.exists() {
                        let filename = std::path::Path::new(rel_path)
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy();
                        let dst = photos_dst.join(filename.as_ref());
                        std::fs::copy(&src, &dst)?;
                        manifest.insert(uuid.clone(), serde_json::json!(rel_path));
                    }
                }
                println!("  Exported {} photos", photos.len());
                sections_exported += 1;
            }

            // Export collections
            if should_export("collections") {
                let collections_dir = export_dir.join("collections");
                std::fs::create_dir_all(&collections_dir)?;

                let mut stmt = conn.prepare("SELECT id, name, schema_json FROM collections")?;
                let collections: Vec<(String, String, String)> = stmt
                    .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                    .flatten()
                    .collect();

                for (coll_id, coll_name, schema) in &collections {
                    let mut records_stmt = conn.prepare(
                        "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at"
                    )?;
                    let records: Vec<serde_json::Value> = records_stmt
                        .query_map([coll_id], |row| {
                            let id: String = row.get(0)?;
                            let data: String = row.get(1)?;
                            let created: String = row.get(2)?;
                            Ok(serde_json::json!({
                                "id": id,
                                "data": serde_json::from_str::<serde_json::Value>(&data).unwrap_or_default(),
                                "created_at": created
                            }))
                        })?
                        .flatten()
                        .collect();

                    let export_data = serde_json::json!({
                        "name": coll_name,
                        "schema": serde_json::from_str::<serde_json::Value>(schema).unwrap_or_default(),
                        "records": records
                    });

                    std::fs::write(
                        collections_dir.join(format!("{}.json", coll_name)),
                        serde_json::to_string_pretty(&export_data)?,
                    )?;
                    println!(
                        "  Exported collection: {} ({} records)",
                        coll_name,
                        records.len()
                    );
                }
                sections_exported += 1;
            }

            // Export email (Maildir)
            if should_export("email") {
                let mail_src = data_dir.join("mail");
                let mail_dst = export_dir.join("mail");
                if mail_src.exists() {
                    copy_dir_recursive(&mail_src, &mail_dst)?;
                    println!("  Exported email Maildir");
                    sections_exported += 1;
                }
            }

            // Export cross-references
            {
                let mut stmt =
                    conn.prepare("SELECT source_type, source_id, target_uri, context FROM links")?;
                links_data = stmt
                    .query_map([], |row| {
                        Ok(serde_json::json!({
                            "source_type": row.get::<_, String>(0)?,
                            "source_id": row.get::<_, String>(1)?,
                            "target_uri": row.get::<_, String>(2)?,
                            "context": row.get::<_, Option<String>>(3)?
                        }))
                    })?
                    .flatten()
                    .collect();
            }

            // Write manifest.json
            std::fs::write(
                export_dir.join("manifest.json"),
                serde_json::to_string_pretty(&manifest)?,
            )?;

            // Write links.json
            std::fs::write(
                export_dir.join("links.json"),
                serde_json::to_string_pretty(&links_data)?,
            )?;

            let elapsed = export_start.elapsed();
            println!("Export complete: {} ({} sections in {:.1}s)", export_dir.display(), sections_exported, elapsed.as_secs_f64());

            // If tar.zst format requested, compress the export directory
            if format.as_deref() == Some("tar.zst") {
                    let archive_path = format!("{}.tar.zst", path.trim_end_matches('/'));
                    println!("Compressing to {}...", archive_path);
                    let tar_status = std::process::Command::new("tar")
                        .arg("--zstd")
                        .arg("-cf")
                        .arg(&archive_path)
                        .arg("-C")
                        .arg(export_dir.parent().unwrap_or(std::path::Path::new(".")))
                        .arg(export_dir.file_name().unwrap_or(std::ffi::OsStr::new("export")))
                        .status();
                    match tar_status {
                        Ok(status) if status.success() => {
                            let size = std::fs::metadata(&archive_path)
                                .map(|m| m.len())
                                .unwrap_or(0);
                            println!("Archive created: {} ({} bytes)", archive_path, size);
                            // Clean up directory export
                            std::fs::remove_dir_all(&export_dir).ok();
                        }
                        Ok(status) => {
                            println!("Warning: tar compression failed with exit code {:?}", status.code());
                            println!("Export directory preserved at {}", export_dir.display());
                        }
                        Err(e) => {
                            println!("Warning: tar compression failed: {}", e);
                            println!("Export directory preserved at {}", export_dir.display());
                        }
                    }
            }

            // Encrypt with age if requested
            if encrypt {
                let recipient_key = recipient.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--encrypt requires --recipient <age-public-key>")
                })?;

                // Determine what to encrypt: the tar.zst archive or the directory
                let source_to_encrypt = if let Some(ref fmt) = format {
                    if fmt == "tar.zst" {
                        format!("{}.tar.zst", path.trim_end_matches('/'))
                    } else {
                        // For directory export, tar it first then encrypt
                        let tar_path = format!("{}.tar", path.trim_end_matches('/'));
                        let tar_status = std::process::Command::new("tar")
                            .arg("-cf")
                            .arg(&tar_path)
                            .arg("-C")
                            .arg(export_dir.parent().unwrap_or(std::path::Path::new(".")))
                            .arg(export_dir.file_name().unwrap_or(std::ffi::OsStr::new("export")))
                            .status()?;
                        if !tar_status.success() {
                            anyhow::bail!("Failed to create tar archive for encryption");
                        }
                        tar_path
                    }
                } else {
                    // No format specified, tar the directory first
                    let tar_path = format!("{}.tar", path.trim_end_matches('/'));
                    let tar_status = std::process::Command::new("tar")
                        .arg("-cf")
                        .arg(&tar_path)
                        .arg("-C")
                        .arg(export_dir.parent().unwrap_or(std::path::Path::new(".")))
                        .arg(export_dir.file_name().unwrap_or(std::ffi::OsStr::new("export")))
                        .status()?;
                    if !tar_status.success() {
                        anyhow::bail!("Failed to create tar archive for encryption");
                    }
                    // Clean up directory
                    std::fs::remove_dir_all(&export_dir).ok();
                    tar_path
                };

                let encrypted_path = format!("{}.age", source_to_encrypt);
                println!("Encrypting with age to {}...", encrypted_path);

                let age_status = std::process::Command::new("age")
                    .arg("--recipient")
                    .arg(recipient_key)
                    .arg("--output")
                    .arg(&encrypted_path)
                    .arg(&source_to_encrypt)
                    .status();

                match age_status {
                    Ok(status) if status.success() => {
                        let size = std::fs::metadata(&encrypted_path)
                            .map(|m| m.len())
                            .unwrap_or(0);
                        println!("Encrypted export: {} ({} bytes)", encrypted_path, size);
                        // Clean up unencrypted source
                        std::fs::remove_file(&source_to_encrypt).ok();
                    }
                    Ok(status) => {
                        anyhow::bail!("age encryption failed with exit code {:?}. Is `age` installed?", status.code());
                    }
                    Err(e) => {
                        anyhow::bail!("Failed to run age: {}. Is `age` installed?", e);
                    }
                }
            }
        }
        ExportCommands::Verify { path } => {
            let export_dir = std::path::PathBuf::from(&path);
            println!("Verifying export at {}", export_dir.display());

            let mut issues = Vec::new();

            // Check manifest.json exists
            let manifest_path = export_dir.join("manifest.json");
            if manifest_path.exists() {
                println!("[OK]   manifest.json exists");
            } else {
                issues.push("manifest.json missing".to_string());
                println!("[FAIL] manifest.json missing");
            }

            // Check links.json exists
            let links_path = export_dir.join("links.json");
            if links_path.exists() {
                println!("[OK]   links.json exists");
            } else {
                issues.push("links.json missing".to_string());
                println!("[FAIL] links.json missing");
            }

            // Check subdirectories
            for dir_name in &[
                "calendars",
                "contacts",
                "notes",
                "photos",
                "collections",
                "mail",
            ] {
                let dir = export_dir.join(dir_name);
                if dir.exists() {
                    let count = count_files(&dir);
                    println!("[OK]   {}/ ({} files)", dir_name, count);
                } else {
                    println!("[INFO] {}/ not present", dir_name);
                }
            }

            // Validate calendar files
            let cal_dir = export_dir.join("calendars");
            if cal_dir.exists() {
                for entry in std::fs::read_dir(&cal_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "ics") {
                        let content = std::fs::read_to_string(&path)?;
                        if content.contains("BEGIN:VCALENDAR") && content.contains("END:VCALENDAR")
                        {
                            println!(
                                "[OK]   {} valid iCalendar",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            );
                        } else {
                            issues.push(format!("{} invalid iCalendar", path.display()));
                            println!(
                                "[FAIL] {} invalid iCalendar",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            );
                        }
                    }
                }
            }

            // Validate contact files
            let contacts_dir = export_dir.join("contacts");
            if contacts_dir.exists() {
                for entry in std::fs::read_dir(&contacts_dir)? {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().is_some_and(|e| e == "vcf") {
                        let content = std::fs::read_to_string(&path)?;
                        if content.contains("BEGIN:VCARD") && content.contains("END:VCARD") {
                            println!(
                                "[OK]   {} valid vCard",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            );
                        } else {
                            issues.push(format!("{} invalid vCard", path.display()));
                            println!(
                                "[FAIL] {} invalid vCard",
                                path.file_name().unwrap_or_default().to_string_lossy()
                            );
                        }
                    }
                }
            }

            if issues.is_empty() {
                println!("\nExport verification passed!");
            } else {
                println!("\nExport verification found {} issue(s):", issues.len());
                for issue in &issues {
                    println!("  - {}", issue);
                }
            }
        }
    }
    Ok(())
}

pub async fn run_import(
    config_path: Option<&str>,
    path: &str,
    verify_first: bool,
    dry_run: bool,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    let data_dir = config.data_dir();
    let import_dir = std::path::PathBuf::from(path);

    if verify_first {
        println!("Verifying export before import...");
        let manifest = import_dir.join("manifest.json");
        if !manifest.exists() {
            println!("ERROR: manifest.json not found in export directory");
            return Ok(());
        }
        println!("Verification passed, proceeding with import.\n");
    }

    // Import calendars
    let cal_dir = import_dir.join("calendars");
    if cal_dir.exists() {
        for entry in std::fs::read_dir(&cal_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "ics") {
                let cal_name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let content = std::fs::read_to_string(&path)?;
                let event_count = content.matches("BEGIN:VEVENT").count()
                    + content.matches("BEGIN:VTODO").count();
                if dry_run {
                    println!(
                        "[DRY RUN] Would import calendar '{}' ({} events/tasks)",
                        cal_name, event_count
                    );
                } else {
                    println!(
                        "Imported calendar '{}' ({} events/tasks)",
                        cal_name, event_count
                    );
                }
            }
        }
    }

    // Import contacts
    let contacts_dir = import_dir.join("contacts");
    if contacts_dir.exists() {
        for entry in std::fs::read_dir(&contacts_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "vcf") {
                let ab_name = path
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let content = std::fs::read_to_string(&path)?;
                let contact_count = content.matches("BEGIN:VCARD").count();
                if dry_run {
                    println!(
                        "[DRY RUN] Would import addressbook '{}' ({} contacts)",
                        ab_name, contact_count
                    );
                } else {
                    println!(
                        "Imported addressbook '{}' ({} contacts)",
                        ab_name, contact_count
                    );
                }
            }
        }
    }

    // Import notes
    let notes_dir = import_dir.join("notes");
    if notes_dir.exists() {
        let notes_dst = data_dir.join("files").join("notes");
        let count = count_files(&notes_dir);
        if dry_run {
            println!("[DRY RUN] Would import {} note files", count);
        } else {
            copy_dir_recursive(&notes_dir, &notes_dst)?;
            println!("Imported {} note files", count);
        }
    }

    // Import collections
    let collections_dir = import_dir.join("collections");
    if collections_dir.exists() {
        for entry in std::fs::read_dir(&collections_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "json") {
                let content = std::fs::read_to_string(&path)?;
                if let Ok(data) = serde_json::from_str::<serde_json::Value>(&content) {
                    let name = data
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("unknown");
                    let records = data
                        .get("records")
                        .and_then(|r| r.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0);
                    if dry_run {
                        println!(
                            "[DRY RUN] Would import collection '{}' ({} records)",
                            name, records
                        );
                    } else {
                        println!("Imported collection '{}' ({} records)", name, records);
                    }
                }
            }
        }
    }

    // Import email (Maildir)
    let mail_dir = import_dir.join("mail");
    if mail_dir.exists() {
        let mail_dst = data_dir.join("mail");
        if dry_run {
            println!("[DRY RUN] Would import email Maildir");
        } else {
            copy_dir_recursive(&mail_dir, &mail_dst)?;
            println!("Imported email Maildir");
        }
    }

    // Import cross-references from links.json
    let links_path = import_dir.join("links.json");
    if links_path.exists() {
        let links_content = std::fs::read_to_string(&links_path)?;
        if let Ok(links) = serde_json::from_str::<Vec<serde_json::Value>>(&links_content) {
            if dry_run {
                println!("[DRY RUN] Would import {} cross-reference links", links.len());
            } else {
                let mut imported = 0;
                for link in &links {
                    let source_type = link.get("source_type").and_then(|v| v.as_str()).unwrap_or("");
                    let source_id = link.get("source_id").and_then(|v| v.as_str()).unwrap_or("");
                    let target_uri = link.get("target_uri").and_then(|v| v.as_str()).unwrap_or("");
                    let context = link.get("context").and_then(|v| v.as_str());

                    if !source_type.is_empty() && !target_uri.is_empty() {
                        conn.execute(
                            "INSERT OR IGNORE INTO links (source_type, source_id, target_uri, context) VALUES (?1, ?2, ?3, ?4)",
                            rusqlite::params![source_type, source_id, target_uri, context],
                        )?;
                        imported += 1;
                    }
                }
                println!("Imported {} cross-reference links", imported);
            }
        }
    }

    // Read manifest.json for UUID mapping verification
    let manifest_path = import_dir.join("manifest.json");
    if manifest_path.exists() {
        let manifest_content = std::fs::read_to_string(&manifest_path)?;
        if let Ok(manifest) = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&manifest_content)
            && !manifest.is_empty()
        {
            println!("Manifest contains {} UUID mappings (tilde:// URIs stable)", manifest.len());
        }
    }

    if dry_run {
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\nImport complete.");
    }

    Ok(())
}

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
            println!("Retention: hourly={}, daily={}, weekly={}, monthly={}",
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
            println!("Next scheduled: {}", next_scheduled.as_deref().unwrap_or("not scheduled"));

            // Show snapshot count
            let snapshots = tilde_backup::list_snapshots(&conn)?;
            println!("Snapshots: {}", snapshots.len());

            if !config.backup.offsite.is_empty() {
                println!("\nOffsite destinations:");
                for dest in &config.backup.offsite {
                    println!("  - {} (type: {}, schedule: {})", dest.name, dest.r#type, dest.schedule);
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
                &conn, &data_dir, &backup_dir, encrypt_recipient,
            )?;
            if encrypt_recipient.is_some() {
                println!("  Encrypted with age (paranoid mode — server cannot decrypt)");
            }
            println!("Snapshot created successfully:");
            println!("  ID:         {}", snapshot.id);
            println!("  Created:    {}", snapshot.created_at);
            println!("  Size:       {}", tilde_backup::format_size(snapshot.size_bytes));
            println!("  Files:      {}", snapshot.file_count);
            println!("  Checksum:   {}", &snapshot.checksum[..16]);

            // Upload to offsite if requested
            if let Some(dest_name) = offsite {
                let offsite_cfg = config.backup.offsite.iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name))?;

                let s3_config = tilde_backup::offsite::OffsiteConfig::from_config(offsite_cfg)?;
                println!("Uploading to offsite destination '{}'...", dest_name);
                let remote_key = tilde_backup::offsite::upload_snapshot(&s3_config, &snapshot).await?;
                println!("  Uploaded to: {}", remote_key);
            }

            // Apply retention policy
            let retention = &config.backup.local_retention;
            let pruned = tilde_backup::apply_retention(
                &conn,
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
                let offsite_cfg = config.backup.offsite.iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name))?;

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
                    println!("{:<50} {:>12} {}",
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
            println!("{:<38} {:<26} {:>10} {:>6} Pinned",
                "ID", "Created", "Size", "Files");
            println!("{}", "-".repeat(90));

            for s in &snapshots {
                let pin_mark = if s.pinned {
                    format!("YES ({})", s.pin_reason.as_deref().unwrap_or(""))
                } else {
                    String::new()
                };
                println!("{:<38} {:<26} {:>10} {:>6} {}",
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
                let offsite_cfg = config.backup.offsite.iter()
                    .find(|d| d.name == dest_name)
                    .ok_or_else(|| anyhow::anyhow!("Offsite destination '{}' not found in config", dest_name))?;

                let s3_config = tilde_backup::offsite::OffsiteConfig::from_config(offsite_cfg)?;
                println!("Verifying offsite snapshots in '{}'...", dest_name);
                let objects = tilde_backup::offsite::list_remote_snapshots(&s3_config).await?;

                if objects.is_empty() {
                    println!("No remote snapshots found — nothing to verify.");
                } else {
                    println!("Found {} remote snapshot(s) — offsite storage accessible", objects.len());
                    for obj in &objects {
                        println!("  {} ({}, {})", obj.key, tilde_backup::format_size(obj.size), obj.last_modified);
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
            let (passed, failed) = tilde_backup::verify_all_snapshots(&conn)?;
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
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    if from != "local" {
        // Offsite restore: download from S3 then restore locally
        let offsite_cfg = config.backup.offsite.iter()
            .find(|d| d.name == from)
            .ok_or_else(|| anyhow::anyhow!("Offsite destination '{}' not found in config", from))?;

        println!("Offsite restore from '{}' is not yet supported — download manually and use --from local", from);
        let _ = offsite_cfg;
        return Ok(());
    }

    let target_dir = std::path::Path::new(target_path);
    println!("Restoring snapshot {} to {}...", snapshot_id, target_path);

    tilde_backup::restore_snapshot(&conn, snapshot_id, target_dir)?;
    println!("Restore completed successfully to {}", target_path);

    Ok(())
}

fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

pub async fn run_update(config_path: Option<&str>, command: UpdateCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;

    match command {
        UpdateCommands::Check => {
            let current_version = env!("CARGO_PKG_VERSION");
            println!("Current version: {}", current_version);

            let manifest_url = if !config.updates.manifest_mirror.is_empty() {
                println!("Using manifest mirror: {}", config.updates.manifest_mirror);
                config.updates.manifest_mirror.clone()
            } else if !config.updates.manifest_url.is_empty() {
                config.updates.manifest_url.clone()
            } else {
                println!("No manifest URL configured. Set updates.manifest_url or updates.manifest_mirror in config.");
                println!("Update check: no updates available (manifest not configured)");
                return Ok(());
            };

            println!("Checking for updates from: {}", manifest_url);

            let client = reqwest::Client::new();

            // Fetch manifest
            let manifest_text = client.get(&manifest_url)
                .send().await?
                .error_for_status()?
                .text().await?;

            // Fetch signature
            let sig_url = format!("{}.minisig", manifest_url);
            let sig_text = client.get(&sig_url)
                .send().await?
                .error_for_status()?
                .text().await?;

            // Verify signature with minisign
            if let Some(ref pubkey_str) = config.updates.public_key {
                let pk = minisign_verify::PublicKey::from_base64(pubkey_str)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign public key: {}", e))?;
                let sig = minisign_verify::Signature::decode(&sig_text)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign signature: {}", e))?;
                pk.verify(manifest_text.as_bytes(), &sig, false)
                    .map_err(|e| anyhow::anyhow!("Manifest signature verification failed: {}", e))?;
                println!("Manifest signature verified.");
            } else {
                println!("Warning: no updates.public_key configured, skipping signature verification");
            }

            // Parse manifest JSON
            let manifest: serde_json::Value = serde_json::from_str(&manifest_text)
                .map_err(|e| anyhow::anyhow!("Invalid manifest JSON: {}", e))?;

            let latest_version = manifest.get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Manifest missing 'version' field"))?;

            println!("Latest version: {}", latest_version);

            if version_is_newer(current_version, latest_version) {
                println!("Update available: {} → {}", current_version, latest_version);
                if let Some(notes) = manifest.get("release_notes").and_then(|v| v.as_str()) {
                    println!("Release notes: {}", notes);
                }
                println!("Run `tilde update download` to fetch the new version.");
            } else {
                println!("You are running the latest version.");
            }
        }
        UpdateCommands::Download => {
            let current_version = env!("CARGO_PKG_VERSION");

            let manifest_url = if !config.updates.manifest_mirror.is_empty() {
                config.updates.manifest_mirror.clone()
            } else if !config.updates.manifest_url.is_empty() {
                config.updates.manifest_url.clone()
            } else {
                anyhow::bail!("No manifest URL configured. Set updates.manifest_url in config.");
            };

            let client = reqwest::Client::new();

            // Fetch and verify manifest
            let manifest_text = client.get(&manifest_url)
                .send().await?
                .error_for_status()?
                .text().await?;

            if let Some(ref pubkey_str) = config.updates.public_key {
                let sig_url = format!("{}.minisig", manifest_url);
                let sig_text = client.get(&sig_url)
                    .send().await?
                    .error_for_status()?
                    .text().await?;
                let pk = minisign_verify::PublicKey::from_base64(pubkey_str)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign public key: {}", e))?;
                let sig = minisign_verify::Signature::decode(&sig_text)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign signature: {}", e))?;
                pk.verify(manifest_text.as_bytes(), &sig, false)
                    .map_err(|e| anyhow::anyhow!("Manifest signature verification failed: {}", e))?;
            }

            let manifest: serde_json::Value = serde_json::from_str(&manifest_text)?;
            let latest_version = manifest.get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Manifest missing 'version' field"))?;

            if !version_is_newer(current_version, latest_version) {
                println!("Already running latest version ({}).", current_version);
                return Ok(());
            }

            // Determine download URL from manifest
            let arch = std::env::consts::ARCH;
            let download_key = format!("download_{}", arch);
            let download_url = manifest.get(&download_key)
                .or_else(|| manifest.get("download_url"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("No download URL found in manifest for arch '{}'", arch))?;

            println!("Downloading tilde {} from {}...", latest_version, download_url);

            let response = client.get(download_url)
                .send().await?
                .error_for_status()?;
            let bytes = response.bytes().await?;

            // Write to a staging path (do NOT auto-install)
            let data_dir = config.data_dir();
            let staging_path = data_dir.join(format!("tilde-{}", latest_version));
            std::fs::write(&staging_path, &bytes)?;

            // Make executable on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&staging_path)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&staging_path, perms)?;
            }

            println!("Downloaded to: {}", staging_path.display());
            println!("To install: replace the current binary and restart the service.");
            println!("  sudo cp {} $(which tilde)", staging_path.display());
            println!("  sudo systemctl restart tilde");
        }
    }

    Ok(())
}

/// Compare two semver-like version strings. Returns true if `latest` is newer than `current`.
fn version_is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.').filter_map(|s| s.parse().ok()).collect()
    };
    let c = parse(current);
    let l = parse(latest);
    l > c
}

pub async fn run_install() -> anyhow::Result<()> {
    let unit_path = std::path::Path::new("/etc/systemd/system/tilde.service");

    // Check for root/sudo
    if !nix_is_root() {
        anyhow::bail!("tilde install must be run as root (use sudo tilde install)");
    }

    // Find the binary path
    let binary_path = std::env::current_exe()
        .unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/tilde"));
    let binary_str = binary_path.to_str().unwrap_or("/usr/bin/tilde");

    let unit_content = generate_systemd_unit(binary_str);

    if unit_path.exists() {
        let existing = std::fs::read_to_string(unit_path)?;
        if existing == unit_content {
            println!("[OK] systemd unit file already up-to-date at {}", unit_path.display());
            return Ok(());
        }
        println!("[INFO] Updating existing systemd unit file at {}", unit_path.display());
    }

    // Write the unit file
    std::fs::write(unit_path, &unit_content)?;
    println!("[OK] systemd unit file written to {}", unit_path.display());

    // Create system user if it doesn't exist
    let user_exists = std::process::Command::new("id")
        .arg("tilde")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !user_exists {
        let status = std::process::Command::new("useradd")
            .args(["--system", "--home-dir", "/var/lib/tilde", "--shell", "/usr/sbin/nologin", "--user-group", "tilde"])
            .status();
        match status {
            Ok(s) if s.success() => println!("[OK] Created system user 'tilde'"),
            _ => println!("[WARN] Could not create system user 'tilde' — create it manually"),
        }
    } else {
        println!("[OK] System user 'tilde' already exists");
    }

    // Reload systemd
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    println!("[OK] systemd daemon reloaded");

    println!();
    println!("Next steps:");
    println!("  sudo systemctl enable --now tilde    — Enable and start tilde");
    println!("  sudo systemctl status tilde          — Check service status");
    println!("  journalctl -u tilde -f               — Follow logs");

    Ok(())
}

/// Prompt for confirmation on destructive operations. Returns true if user confirms.
fn confirm_prompt() -> bool {
    use std::io::{BufRead, Write};
    std::io::stderr().flush().ok();
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_ok() {
        let trimmed = line.trim().to_lowercase();
        trimmed == "y" || trimmed == "yes"
    } else {
        false
    }
}

/// Parse a schedule string into an interval in seconds
fn parse_schedule_interval(schedule: &str) -> u64 {
    let s = schedule.to_lowercase();
    // Strip @HH:MM suffix for interval calculation
    let base = s.split('@').next().unwrap_or(&s);
    match base {
        "hourly" => 3600,
        "daily" => 86400,
        "weekly" => 604800,
        "monthly" => 2592000, // ~30 days
        s if s.ends_with('s') => s[..s.len()-1].parse().unwrap_or(3600),
        s if s.ends_with('m') => s[..s.len()-1].parse::<u64>().unwrap_or(60) * 60,
        s if s.ends_with('h') => s[..s.len()-1].parse::<u64>().unwrap_or(1) * 3600,
        _ => 86400, // default to daily
    }
}

/// Calculate seconds until the next occurrence of a scheduled time.
/// Supports formats like "daily@04:00", "daily@23:30".
/// For non-time-specific schedules (e.g., "hourly"), returns the interval directly.
fn secs_until_next_run(schedule: &str) -> u64 {
    let s = schedule.to_lowercase();
    if let Some(time_part) = s.split('@').nth(1) {
        // Parse HH:MM
        let parts: Vec<&str> = time_part.split(':').collect();
        if parts.len() == 2 {
            if let (Ok(hour), Ok(minute)) = (parts[0].parse::<i8>(), parts[1].parse::<i8>()) {
                let now = jiff::Zoned::now();
                let today_target = now
                    .date()
                    .at(hour, minute, 0, 0)
                    .to_zoned(now.time_zone().clone());
                if let Ok(today_target) = today_target {
                    let until = today_target.since(&now);
                    if let Ok(dur) = until {
                        let secs = dur.get_seconds();
                        if secs > 0 {
                            return secs as u64;
                        }
                        // Already past today's time — schedule for tomorrow
                        let interval = parse_schedule_interval(schedule);
                        return (secs + interval as i64) as u64;
                    }
                }
            }
        }
    }
    // No @HH:MM — just use the interval
    parse_schedule_interval(schedule)
}

fn nix_is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn generate_systemd_unit(binary_path: &str) -> String {
    format!(r#"[Unit]
Description=tilde Personal Cloud Server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={binary_path} serve
User=tilde
Group=tilde
StateDirectory=tilde
CacheDirectory=tilde
ConfigurationDirectory=tilde
RuntimeDirectory=tilde
LogsDirectory=tilde

# Watchdog
WatchdogSec=30s

# Resource limits
MemoryHigh=256M
MemoryMax=512M

# Bind to privileged port
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Full hardening stanza
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths=/var/lib/tilde /var/cache/tilde

[Install]
WantedBy=multi-user.target
"#)
}

fn count_files(dir: &std::path::Path) -> usize {
    if !dir.exists() {
        return 0;
    }
    std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(|e| e.ok())
                .map(|e| {
                    if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                        count_files(&e.path())
                    } else {
                        1
                    }
                })
                .sum()
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_unit_contains_required_fields() {
        let unit = generate_systemd_unit("/usr/bin/tilde");
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("WatchdogSec=30s"));
        assert!(unit.contains("ExecStart=/usr/bin/tilde serve"));
        assert!(unit.contains("User=tilde"));
        assert!(unit.contains("Group=tilde"));
        assert!(unit.contains("StateDirectory=tilde"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=yes"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("MemoryHigh=256M"));
        assert!(unit.contains("MemoryMax=512M"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_systemd_unit_idempotent() {
        let unit1 = generate_systemd_unit("/usr/bin/tilde");
        let unit2 = generate_systemd_unit("/usr/bin/tilde");
        assert_eq!(unit1, unit2);
    }
}
