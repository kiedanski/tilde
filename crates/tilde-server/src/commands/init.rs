use tilde_core::{auth, config::Config, db};

use super::{generate_recovery_code, prompt_with_default};

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
        println!(
            "[OK] Config file already exists at {}",
            config_file.display()
        );
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
        cache_dir.join("thumbnails"),
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
        println!(
            "[WARN] No admin password set. Set TILDE_ADMIN_PASSWORD env var or run init again."
        );
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
        std::fs::write(
            &backup_key_path,
            format!(
                "# tilde backup key (recovery code hash: {})\n",
                &code_hash[..16]
            ),
        )?;
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
