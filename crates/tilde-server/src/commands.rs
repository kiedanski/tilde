//! CLI command implementations

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;
use tilde_cli::{AuthCommands, AppPasswordCommands, SessionCommands, McpCommands, TokenCommands};
use tilde_core::{config::Config, db, auth};
use tilde_server::{AppState, build_router, SharedState};

pub async fn run_init(config_path: Option<&str>) -> anyhow::Result<()> {
    println!("tilde init — Interactive Setup Wizard");
    println!("=====================================");

    let config = Config::load(config_path)?;
    let data_dir = config.data_dir();
    let cache_dir = config.cache_dir();

    let dirs = [
        data_dir.join("files/notes"),
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

    let db_path = config.db_path();
    let conn = db::init_db(db_path.to_str().unwrap())?;
    println!("[OK] Database initialized at {}", db_path.display());

    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    println!("[OK] Database migrations applied");

    let admin_password = config.auth.admin_password.clone();
    if admin_password.is_empty() {
        if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD") {
            auth::store_admin_password(&conn, &pw)?;
            println!("[OK] Admin password set from TILDE_ADMIN_PASSWORD");
        } else {
            println!("[WARN] No admin password set. Set TILDE_ADMIN_PASSWORD env var.");
        }
    } else {
        auth::store_admin_password(&conn, &admin_password)?;
        println!("[OK] Admin password set from config");
    }

    println!();
    println!("Setup complete! Next steps:");
    println!("  tilde serve          — Start the server");
    println!("  tilde status         — Check server status");
    println!("  tilde --help         — See all commands");

    Ok(())
}

pub async fn run_serve(config_path: Option<&str>) -> anyhow::Result<()> {
    info!("Starting tilde server...");

    let config = Config::load(config_path)?;
    let db_path = config.db_path();

    let conn = db::init_db(db_path.to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    if let Ok(pw) = std::env::var("TILDE_ADMIN_PASSWORD") {
        if auth::get_admin_password_hash(&conn)?.is_none() {
            auth::store_admin_password(&conn, &pw)?;
            info!("Admin password set from environment variable");
        }
    }

    let listen_addr = format!("{}:{}", config.server.listen_addr, config.server.listen_port);

    let state: SharedState = Arc::new(AppState {
        config,
        db: Mutex::new(conn),
        start_time: Instant::now(),
    });

    let app = build_router(state);

    println!("tilde server listening on http://{}", listen_addr);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

pub async fn run_status(config_path: Option<&str>) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let db_path = config.db_path();
    let data_dir = config.data_dir();

    println!("tilde — Status");
    println!("==============");
    println!("Hostname:   {}", if config.server.hostname.is_empty() { "(not set)" } else { &config.server.hostname });
    println!("Listen:     {}:{}", config.server.listen_addr, config.server.listen_port);
    println!("TLS mode:   {}", config.tls.mode);
    println!("Data dir:   {}", data_dir.display());
    println!("Cache dir:  {}", config.cache_dir().display());
    println!("Database:   {}", db_path.display());

    if db_path.exists() {
        let conn = db::init_db(db_path.to_str().unwrap())?;
        let migrations = db::get_applied_migrations(&conn)?;
        println!("Migrations: {} applied", migrations.len());

        let has_password = auth::get_admin_password_hash(&conn)?.is_some();
        println!("Admin auth: {}", if has_password { "configured" } else { "NOT SET" });

        if let Ok(meta) = db_path.metadata() {
            let size_mb = meta.len() as f64 / 1024.0 / 1024.0;
            println!("DB size:    {:.2} MB", size_mb);
        }
    } else {
        println!("Database:   NOT INITIALIZED (run `tilde init`)");
    }

    if data_dir.exists() {
        if let Ok(total_size) = walkdir(&data_dir) {
            let size_mb = total_size as f64 / 1024.0 / 1024.0;
            println!("Data size:  {:.2} MB", size_mb);
        }
    }

    println!("Mode:       {}", if Config::is_systemd_mode() { "systemd" } else { "user" });

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
                    match conn.query_row("PRAGMA integrity_check", [], |row| row.get::<_, String>(0)) {
                        Ok(result) if result == "ok" => println!("[OK]   Database integrity check passed"),
                        Ok(result) => println!("[FAIL] Database integrity: {}", result),
                        Err(e) => println!("[FAIL] Integrity check error: {}", e),
                    }
                }
                Err(e) => println!("[FAIL] Database connection failed: {}", e),
            }
        } else {
            println!("[WARN] Database not found at {}. Run `tilde init`", db_path.display());
        }
    }

    check_dep("sqlite3");
    check_dep("exiftool");
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
                println!("{:<36} {:<20} {:<15} {:<25} {}", "ID", "Name", "Scope", "Created", "Status");
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (id, name, scope, created, _last_used, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!("{:<36} {:<20} {:<15} {:<25} {}", id, name, scope, created, status);
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
                    "SELECT token_prefix, created_at, last_used_at, expires_at, revoked FROM auth_sessions ORDER BY created_at DESC"
                )?;
                let rows = stmt.query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                })?;
                println!("{:<24} {:<25} {:<25} {}", "Prefix", "Created", "Last Used", "Status");
                println!("{}", "-".repeat(100));
                for row in rows {
                    let (prefix, created, last_used, _expires, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!("{:<24} {:<25} {:<25} {}", prefix, created, last_used, status);
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
    }
    Ok(())
}

pub async fn run_mcp(config_path: Option<&str>, command: McpCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        McpCommands::Token { command } => match command {
            TokenCommands::Create { name, scopes } => {
                let token = auth::create_mcp_token(&conn, &name, &scopes, config.mcp.default_rate_limit)?;
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
                println!("{:<20} {:<20} {:<20} {:<15} {}", "Name", "Prefix", "Scopes", "Rate Limit", "Status");
                println!("{}", "-".repeat(90));
                for row in rows {
                    let (name, prefix, scopes, rate_limit, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!("{:<20} {:<20} {:<20} {:<15} {}", name, prefix, scopes, rate_limit, status);
                }
            }
            TokenCommands::Revoke { id } => {
                conn.execute("UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1", [&id])?;
                println!("MCP token revoked");
            }
            TokenCommands::Rotate { id } => {
                let (name, scopes, rate_limit): (String, String, u32) = conn.query_row(
                    "SELECT name, scopes, rate_limit FROM mcp_tokens WHERE id = ?1 OR name = ?1",
                    [&id],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )?;
                conn.execute("UPDATE mcp_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1", [&id])?;
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
                "SELECT token_name, tool_name, duration_ms, created_at FROM mcp_audit_log WHERE 1=1"
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

            println!("{:<15} {:<25} {:<8} {:<20}", "Token", "Tool", "Duration", "Time");
            println!("{}", "-".repeat(70));
            for row in rows {
                let (token_name, tool_name, duration, time) = row?;
                println!("{:<15} {:<25} {:<8} {:<20}", token_name, tool_name, format!("{}ms", duration), time);
            }
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

fn check_dep(name: &str) {
    match std::process::Command::new("which").arg(name).output() {
        Ok(output) if output.status.success() => println!("[OK]   {} found", name),
        _ => println!("[WARN] {} not found", name),
    }
}
