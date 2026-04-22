//! CLI command implementations

use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::info;
use tilde_cli::{AuthCommands, AppPasswordCommands, SessionCommands, McpCommands, TokenCommands, NotesCommands, CollectionCommands, BookmarksCommands, TrackersCommands, WebhookCommands, WebhookTokenCommands, NotificationCommands, PhotosCommands, EmailCommands, CalendarCommands, ContactsCommands};
use tilde_core::{config::Config, db, auth};
use tilde_server::{AppState, build_router, SharedState};
use tilde_dav;
use tilde_cal;
use tilde_card;

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

    let data_dir = config.data_dir();
    let cache_dir = config.cache_dir();
    let files_root = data_dir.join("files");

    // Ensure all data directories exist
    for dir in &[
        files_root.clone(),
        files_root.join("notes"),
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
        let now_str = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
        let mut stmt = conn.prepare(
            "SELECT session_id, staging_dir FROM chunked_uploads WHERE expires_at < ?1"
        )?;
        let expired: Vec<(String, String)> = stmt.query_map([&now_str], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?.filter_map(|r| r.ok()).collect();

        for (session_id, staging_dir) in &expired {
            let _ = std::fs::remove_dir_all(staging_dir);
            info!(session = %session_id, "Cleaned up expired upload session");
        }
        if !expired.is_empty() {
            conn.execute("DELETE FROM chunked_uploads WHERE expires_at < ?1", [&now_str])?;
            info!(count = expired.len(), "Expired upload sessions cleaned up");
        }
    }

    let db_arc: std::sync::Arc<Mutex<rusqlite::Connection>> = Arc::new(Mutex::new(conn));

    let mcp_state: tilde_mcp::SharedMcpState = Arc::new(tilde_mcp::McpState {
        db: db_arc.clone(),
        data_dir: data_dir.clone(),
        rate_limits: Mutex::new(std::collections::HashMap::new()),
    });

    let state: SharedState = Arc::new(AppState {
        config,
        db: db_arc.clone(),
        start_time: Instant::now(),
        login_attempts: Mutex::new(std::collections::HashMap::new()),
        login_flows: Mutex::new(std::collections::HashMap::new()),
        mcp_state,
    });

    let dav_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: db_arc.clone(),
        files_root,
        uploads_root,
    });

    let session_ttl = state.config.auth.session_ttl_hours;

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

    // Process any existing files in _inbox/ on startup
    {
        let photos_base = data_dir.join("photos");
        let pattern = state.config.photos.organization_pattern.clone();
        let db = state.db.lock().unwrap();
        match tilde_photos::ingest::process_inbox(&db, &photos_base, &pattern) {
            Ok(results) if !results.is_empty() => {
                info!(count = results.len(), "Processed existing inbox files on startup");
            }
            Err(e) => tracing::warn!(error = %e, "Failed to process inbox on startup"),
            _ => {}
        }
        match tilde_photos::ingest::process_library_drop(&db, &photos_base) {
            Ok(results) if !results.is_empty() => {
                info!(count = results.len(), "Processed existing library-drop files on startup");
            }
            Err(e) => tracing::warn!(error = %e, "Failed to process library-drop on startup"),
            _ => {}
        }
    }

    let app = build_router(state, dav_state, caldav_state, carddav_state);

    println!("tilde server listening on http://{}", listen_addr);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    axum::serve(listener, app.into_make_service_with_connect_info::<std::net::SocketAddr>()).await?;

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

        if data_dir.exists() {
            if let Ok(total_size) = walkdir(&data_dir) {
                status["data_size_bytes"] = serde_json::json!(total_size);
            }
        }

        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

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
                println!("{:<24} {:<20} {:<16} {:<25} {}", "Prefix", "User Agent", "Source IP", "Last Used", "Status");
                println!("{}", "-".repeat(110));
                for row in rows {
                    let (prefix, _created, last_used, _expires, user_agent, source_ip, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    let ua = user_agent.unwrap_or_else(|| "-".to_string());
                    let ip = source_ip.unwrap_or_else(|| "-".to_string());
                    println!("{:<24} {:<20} {:<16} {:<25} {}", prefix, ua, ip, last_used, status);
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

pub async fn run_notes(config_path: Option<&str>, command: NotesCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let notes_dir = config.data_dir().join("files/notes");

    match command {
        NotesCommands::Search { query } => {
            // First, rebuild FTS index from disk
            index_notes_fts(&conn, &notes_dir)?;

            // Search FTS
            let mut stmt = conn.prepare(
                "SELECT path, snippet(notes_fts, 2, '[', ']', '...', 30) FROM notes_fts WHERE notes_fts MATCH ?1 ORDER BY rank LIMIT 20"
            )?;
            let results: Vec<(String, String)> = stmt.query_map([&query], |row| {
                Ok((row.get(0)?, row.get(1)?))
            })?.filter_map(|r| r.ok()).collect();

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

    fn walk_and_index(conn: &rusqlite::Connection, dir: &std::path::Path, base: &std::path::Path) -> anyhow::Result<()> {
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                walk_and_index(conn, &path, base)?;
            } else if path.extension().map(|e| e == "md").unwrap_or(false) {
                let rel_path = path.strip_prefix(base)
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let content = std::fs::read_to_string(&path).unwrap_or_default();

                // Extract title from first heading or filename
                let title = content.lines()
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

pub async fn run_collection(config_path: Option<&str>, command: CollectionCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        CollectionCommands::Create { name, schema } => {
            let schema_json = std::fs::read_to_string(&schema)
                .unwrap_or_else(|_| schema.clone()); // Allow inline JSON or file path
            // Validate it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&schema_json)
                .map_err(|e| anyhow::anyhow!("Invalid JSON schema: {}", e))?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            conn.execute(
                "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![id, name, schema_json, now, now],
            )?;
            println!("Collection '{}' created", name);
        }
        CollectionCommands::List => {
            let mut stmt = conn.prepare("SELECT name, created_at FROM collections ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            println!("{:<30} {}", "Name", "Created");
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
            let (collection_id, schema_json): (String, String) = conn.query_row(
                "SELECT id, schema_json FROM collections WHERE name = ?1",
                [&name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            // Basic schema validation
            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        CollectionCommands::Get { name, id } => {
            let (collection_id,): (String,) = conn.query_row(
                "SELECT id FROM collections WHERE name = ?1", [&name],
                |row| Ok((row.get(0)?,)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

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

            let (collection_id, schema_json): (String, String) = conn.query_row(
                "SELECT id, schema_json FROM collections WHERE name = ?1", [&name],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
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
            let (collection_id,): (String,) = conn.query_row(
                "SELECT id FROM collections WHERE name = ?1", [&name],
                |row| Ok((row.get(0)?,)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

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
        CollectionCommands::ListRecords { name, filter: _, sort, limit } => {
            let (collection_id,): (String,) = conn.query_row(
                "SELECT id FROM collections WHERE name = ?1", [&name],
                |row| Ok((row.get(0)?,)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

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
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?))
            })?;

            println!("{:<36} {:<40} {}", "ID", "Data", "Created");
            println!("{}", "-".repeat(90));
            for row in rows {
                let (id, data, created) = row?;
                println!("{:<36} {:<40} {}", id, data, created);
            }
        }
        CollectionCommands::Export { name, format } => {
            let (collection_id,): (String,) = conn.query_row(
                "SELECT id FROM collections WHERE name = ?1", [&name],
                |row| Ok((row.get(0)?,)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let mut stmt = conn.prepare(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at"
            )?;
            let rows: Vec<(String, String, String)> = stmt.query_map([&collection_id], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })?.filter_map(|r| r.ok()).collect();

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows.iter().map(|(id, data, created)| {
                        let mut record: serde_json::Value = serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                        if let Some(obj) = record.as_object_mut() {
                            obj.insert("_id".to_string(), serde_json::json!(id));
                            obj.insert("_created_at".to_string(), serde_json::json!(created));
                        }
                        record
                    }).collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                "csv" => {
                    // Extract keys from first record
                    if let Some((_, first_data, _)) = rows.first() {
                        let first: serde_json::Value = serde_json::from_str(first_data)?;
                        if let Some(obj) = first.as_object() {
                            let keys: Vec<&String> = obj.keys().collect();
                            println!("id,{},created_at", keys.iter().map(|k| k.as_str()).collect::<Vec<_>>().join(","));
                            for (id, data, created) in &rows {
                                let record: serde_json::Value = serde_json::from_str(data)?;
                                let values: Vec<String> = keys.iter().map(|k| {
                                    record.get(k.as_str()).map(|v| v.to_string().trim_matches('"').to_string()).unwrap_or_default()
                                }).collect();
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
fn validate_json_schema(data: &serde_json::Value, schema: &serde_json::Value) -> anyhow::Result<()> {
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
            return Err(anyhow::anyhow!("Expected type '{}', got '{}'", expected_type, actual_type));
        }
    }

    // Check required fields
    if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
        if let Some(obj) = data.as_object() {
            for req in required {
                if let Some(field_name) = req.as_str() {
                    if !obj.contains_key(field_name) {
                        return Err(anyhow::anyhow!("Missing required field: '{}'", field_name));
                    }
                }
            }
        }
    }

    // Check property types
    if let (Some(props), Some(obj)) = (schema.get("properties").and_then(|p| p.as_object()), data.as_object()) {
        for (key, prop_schema) in props {
            if let Some(value) = obj.get(key) {
                if let Some(prop_type) = prop_schema.get("type").and_then(|t| t.as_str()) {
                    let valid = match prop_type {
                        "string" => value.is_string(),
                        "number" | "integer" => value.is_number(),
                        "boolean" => value.is_boolean(),
                        "array" => value.is_array(),
                        "object" => value.is_object(),
                        _ => true,
                    };
                    if !valid {
                        return Err(anyhow::anyhow!("Field '{}' expected type '{}', got {:?}", key, prop_type, value));
                    }
                }
            }
        }
    }

    Ok(())
}

fn list_notes_recursive(dir: &std::path::Path, base: &std::path::Path) -> anyhow::Result<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let rel_path = path.strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());

        if path.is_dir() {
            list_notes_recursive(&path, base)?;
        } else if path.extension().map(|e| e == "md").unwrap_or(false) {
            let meta = path.metadata()?;
            let modified = meta.modified()
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

pub async fn run_bookmarks(config_path: Option<&str>, command: BookmarksCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    // Ensure "bookmarks" collection exists
    ensure_bookmarks_collection(&conn)?;

    match command {
        BookmarksCommands::Add { url, title, tags, description } => {
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
                jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()
            );

            let collection_id: String = conn.query_row(
                "SELECT id FROM collections WHERE name = 'bookmarks'",
                [],
                |row| row.get(0),
            )?;

            let id = uuid::Uuid::new_v4().to_string();
            let data_str = serde_json::to_string(&data)?;
            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
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
            let rows: Vec<(String, String, String)> = stmt.query_map(
                rusqlite::params![collection_id, limit],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            )?.filter_map(|r| r.ok()).collect();

            println!("{:<36} {:<50} {:<30} {}", "ID", "URL", "Title", "Tags");
            println!("{}", "-".repeat(130));
            for (id, data_str, _created) in &rows {
                let data: serde_json::Value = serde_json::from_str(data_str).unwrap_or_default();
                let url = data.get("url").and_then(|v| v.as_str()).unwrap_or("-");
                let title = data.get("title").and_then(|v| v.as_str()).unwrap_or("-");
                let tags = data.get("tags").and_then(|v| v.as_array())
                    .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>().join(", "))
                    .unwrap_or_default();

                // Filter by tag if specified
                if let Some(ref filter_tag) = tag {
                    if !tags.contains(filter_tag) {
                        continue;
                    }
                }

                println!("{:<36} {:<50} {:<30} {}", id, url, title, tags);
            }
        }
    }
    Ok(())
}

pub async fn run_trackers(config_path: Option<&str>, command: TrackersCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        TrackersCommands::Log { collection, data } => {
            let data_val: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

            let (collection_id, schema_json): (String, String) = conn.query_row(
                "SELECT id, schema_json FROM collections WHERE name = ?1",
                [&collection],
                |row| Ok((row.get(0)?, row.get(1)?)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        TrackersCommands::Query { collection, since, format, limit } => {
            let (collection_id,): (String,) = conn.query_row(
                "SELECT id FROM collections WHERE name = ?1",
                [&collection],
                |row| Ok((row.get(0)?,)),
            ).map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let limit = limit.unwrap_or(50);

            let rows: Vec<(String, String, String)> = if let Some(ref since_val) = since {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC LIMIT ?3"
                )?;
                stmt.query_map(rusqlite::params![collection_id, since_val, limit],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                )?.filter_map(|r| r.ok()).collect()
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
                )?;
                stmt.query_map(rusqlite::params![collection_id, limit],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                )?.filter_map(|r| r.ok()).collect()
            };

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows.iter().map(|(id, data, created)| {
                        let mut record: serde_json::Value = serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                        if let Some(obj) = record.as_object_mut() {
                            obj.insert("_id".to_string(), serde_json::json!(id));
                            obj.insert("_created_at".to_string(), serde_json::json!(created));
                        }
                        record
                    }).collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                _ => {
                    // Table format
                    println!("{:<36} {:<40} {}", "ID", "Data", "Created");
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

pub async fn run_webhook(config_path: Option<&str>, command: WebhookCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;

    match command {
        WebhookCommands::Token { command } => match command {
            WebhookTokenCommands::Create { name, scopes } => {
                let token = auth::generate_mcp_token(); // reuse token generator
                let token_hash = auth::hash_token(&token);
                let prefix = &token[..std::cmp::min(17, token.len())];
                let id = uuid::Uuid::new_v4().to_string();
                let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

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
                println!("{:<20} {:<20} {:<25} {:<10} {}", "Name", "Prefix", "Scopes", "Rate", "Status");
                println!("{}", "-".repeat(85));
                for row in rows {
                    let (name, prefix, scopes, rate, revoked) = row?;
                    let status = if revoked { "revoked" } else { "active" };
                    println!("{:<20} {:<20} {:<25} {:<10} {}", name, prefix, scopes, rate, status);
                }
            }
            WebhookTokenCommands::Revoke { id } => {
                conn.execute("UPDATE webhook_tokens SET revoked = 1 WHERE id = ?1 OR name = ?1", [&id])?;
                println!("Webhook token revoked");
            }
        },
    }
    Ok(())
}

pub async fn run_notifications(config_path: Option<&str>, command: NotificationCommands) -> anyhow::Result<()> {
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
                    println!("Test notification sent to file sink: {}", data_dir.join("notifications.log").display());
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
            println!("{:<20} {:<10} {:<40} {:<15} {}", "Type", "Priority", "Message", "Sinks", "Time");
            println!("{}", "-".repeat(100));
            for row in rows {
                let (event_type, priority, message, sinks, time) = row?;
                let msg = if message.len() > 38 { format!("{}...", &message[..35]) } else { message };
                println!("{:<20} {:<10} {:<40} {:<15} {}", event_type, priority, msg, sinks, time);
            }
        }
        NotificationCommands::Config => {
            println!("Notification Sinks:");
            println!("  file: enabled (logs all events to notifications.log)");
            println!("  ntfy: {}", "not configured");
            println!("  smtp: {}", "not configured");
            println!("  matrix: {}", "not configured");
            println!("  signal: {}", "not configured");
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

    match command {
        EmailCommands::Search { query } => {
            // First try FTS search
            let mut stmt = conn.prepare(
                "SELECT e.message_id, e.from_address, e.subject, e.date, e.snippet
                 FROM email_fts f
                 JOIN email_messages e ON e.id = f.rowid
                 WHERE email_fts MATCH ?1
                 ORDER BY e.date DESC LIMIT 20"
            );

            let results: Vec<(String, String, String, String, Option<String>)> = match stmt {
                Ok(ref mut s) => {
                    s.query_map([&query], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
                    })?.filter_map(|r| r.ok()).collect()
                }
                Err(_) => {
                    // FTS might be empty, try LIKE search
                    let mut s2 = conn.prepare(
                        "SELECT message_id, from_address, subject, date, snippet FROM email_messages WHERE subject LIKE ?1 OR from_address LIKE ?1 ORDER BY date DESC LIMIT 20"
                    )?;
                    let pattern = format!("%{}%", query);
                    s2.query_map([&pattern], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
                    })?.filter_map(|r| r.ok()).collect()
                }
            };

            if results.is_empty() {
                println!("No emails found matching '{}'", query);
            } else {
                println!("{:<30} {:<30} {:<20} {}", "From", "Subject", "Date", "Snippet");
                println!("{}", "-".repeat(100));
                for (_, from, subject, date, snippet) in &results {
                    let subj = if subject.len() > 28 { format!("{}...", &subject[..25]) } else { subject.clone() };
                    let snip = snippet.as_deref().unwrap_or("").chars().take(30).collect::<String>();
                    println!("{:<30} {:<30} {:<20} {}", from, subj, date, snip);
                }
                println!("{} result(s)", results.len());
            }
        }
        EmailCommands::Show { message_id } => {
            let result = conn.query_row(
                "SELECT from_address, to_addresses, subject, date, snippet, maildir_path FROM email_messages WHERE message_id = ?1",
                [&message_id],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                )),
            );
            match result {
                Ok((from, to, subject, date, snippet, path)) => {
                    println!("From:    {}", from);
                    println!("To:      {}", to);
                    println!("Subject: {}", subject);
                    println!("Date:    {}", date);
                    println!("Path:    {}", path);
                    if let Some(s) = snippet {
                        println!();
                        println!("{}", s);
                    }
                }
                Err(_) => println!("Message not found: {}", message_id),
            }
        }
        EmailCommands::Thread { message_id: _ } => {
            println!("Email threading not yet implemented");
        }
        EmailCommands::Reindex => {
            println!("Email reindex rebuilds SQLite from Maildir files");
            println!("(IMAP sync must run first to populate Maildir)");
        }
        EmailCommands::Status => {
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM email_messages", [], |row| row.get(0)).unwrap_or(0);
            println!("Email Archive Status");
            println!("====================");
            println!("Total messages: {}", count);
            println!("Accounts configured: check config.toml [email] section");
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
                "SELECT p.id, f.path, p.taken_at, p.camera_model, p.tags_json FROM photos p JOIN files f ON p.file_id = f.id WHERE 1=1"
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

            println!("{:<36} {:<40} {:<20} {:<20} {}", "UUID", "Path", "Taken", "Camera", "Tags");
            println!("{}", "-".repeat(130));
            let mut count = 0;
            for row in rows {
                let (uuid, path, taken, camera, tags) = row?;
                println!("{:<36} {:<40} {:<20} {:<20} {}",
                    uuid,
                    path,
                    taken.unwrap_or_else(|| "-".to_string()),
                    camera.unwrap_or_else(|| "-".to_string()),
                    tags.unwrap_or_else(|| "[]".to_string()),
                );
                count += 1;
            }
            if count == 0 {
                println!("No photos found. Drop files in {} to index.", photos_dir.join("_inbox").display());
            }
        }
        PhotosCommands::Tag { uuid, command } => {
            use tilde_cli::TagCommands;
            let _photos_dir_path = photos_dir.clone();
            // Find the photo's file path from the database
            let file_path: Option<String> = conn.query_row(
                "SELECT f.path FROM photos p JOIN files f ON p.file_id = f.id WHERE p.id = ?1",
                [&uuid],
                |row| row.get(0),
            ).ok();

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
                            match tilde_photos::exiftool::read_metadata(&full_path) {
                                Ok(meta) => {
                                    let mut tags = meta.tags.clone();
                                    if !tags.contains(&tag) {
                                        tags.push(tag.clone());
                                    }
                                    tilde_photos::exiftool::write_tags(&full_path, &tags)?;

                                    // Update database
                                    let prefix = tilde_photos::exiftool::classify_tag_prefix(&tag);
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
                                }
                                Err(e) => {
                                    if tilde_photos::exiftool::is_available() {
                                        println!("Failed to read metadata: {}", e);
                                    } else {
                                        println!("ExifTool is not installed. Install it to manage photo tags.");
                                    }
                                }
                            }
                        }
                        TagCommands::Remove { tag } => {
                            match tilde_photos::exiftool::remove_tags(&full_path, &[tag.clone()]) {
                                Ok(()) => {
                                    conn.execute(
                                        "DELETE FROM photo_tags WHERE photo_id = ?1 AND tag = ?2",
                                        rusqlite::params![uuid, tag],
                                    )?;
                                    // Update tags_json in photos table
                                    let remaining: Vec<String> = conn.prepare(
                                        "SELECT tag FROM photo_tags WHERE photo_id = ?1"
                                    )?.query_map([&uuid], |row| row.get(0))?
                                        .filter_map(|r| r.ok())
                                        .collect();
                                    let tags_json = serde_json::to_string(&remaining)?;
                                    conn.execute(
                                        "UPDATE photos SET tags_json = ?1 WHERE id = ?2",
                                        rusqlite::params![tags_json, uuid],
                                    )?;
                                    println!("Tag '{}' removed from photo {}", tag, uuid);
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
                    let photos: Vec<(String, String)> = stmt.query_map([], |row| {
                        Ok((row.get(0)?, row.get(1)?))
                    })?.filter_map(|r| r.ok()).collect();

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

                        let ext = full_path.extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");

                        let result = if tilde_photos::is_photo_ext(ext) {
                            tilde_photos::thumbnail::generate_thumbnails(&full_path, photo_id, &cache_dir, quality)
                        } else if tilde_photos::is_video_ext(ext) {
                            tilde_photos::thumbnail::generate_video_thumbnail(&full_path, photo_id, &cache_dir, quality, config.photos.ffmpeg_timeout_seconds)
                        } else {
                            failed += 1;
                            continue;
                        };

                        match result {
                            Ok(_) => {
                                tilde_photos::thumbnail::mark_thumbnails_generated(&conn, photo_id, true, true)?;
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

fn reindex_photos_from_dir(conn: &rusqlite::Connection, dir: &std::path::Path, base: &std::path::Path) -> anyhow::Result<usize> {
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
            count += reindex_photos_from_dir(conn, &path, base)?;
            continue;
        }

        let ext = path.extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_lowercase())
            .unwrap_or_default();

        if !tilde_photos::is_media_ext(&ext) {
            continue;
        }

        let rel_path = path.strip_prefix(base)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        // Check if already indexed
        let exists: bool = conn.query_row(
            "SELECT COUNT(*) FROM files WHERE path = ?1",
            [&format!("photos/{}", rel_path)],
            |row| row.get::<_, i64>(0),
        ).map(|c| c > 0)?;

        if exists {
            continue;
        }

        // Determine content type from magic bytes or extension
        let content_type = tilde_photos::validate_magic_bytes(&path)
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("image/{}", ext));

        match tilde_photos::index_photo(conn, &path, base, &content_type) {
            Ok(_) => count += 1,
            Err(e) => eprintln!("  Warning: failed to index {}: {}", rel_path, e),
        }
    }

    Ok(count)
}

pub async fn run_reindex(config_path: Option<&str>, index_type: &str) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let notes_dir = config.data_dir().join("files/notes");

    match index_type {
        "notes" | "all" => {
            print!("Rebuilding notes FTS index... ");
            index_notes_fts(&conn, &notes_dir)?;
            let count: i64 = conn.query_row("SELECT COUNT(*) FROM notes_fts", [], |row| row.get(0))?;
            println!("done ({} notes indexed)", count);
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

fn parse_links_from_notes(conn: &rusqlite::Connection, dir: &std::path::Path, base: &std::path::Path) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            parse_links_from_notes(conn, &path, base)?;
        } else if path.extension().is_some_and(|e| e == "md") {
            let rel_path = path.strip_prefix(base)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();
            let content = std::fs::read_to_string(&path).unwrap_or_default();

            // Parse tilde:// URIs
            for cap in content.match_indices("tilde://") {
                let start = cap.0;
                let rest = &content[start..];
                let end = rest.find(|c: char| c.is_whitespace() || c == ')' || c == ']' || c == '>' || c == '"')
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
                        let target_uri = if link_content.starts_with("photo:") {
                            format!("tilde://photo/{}", &link_content[6..])
                        } else if link_content.starts_with('@') {
                            format!("tilde://contact/{}", &link_content[1..])
                        } else if link_content.starts_with('#') {
                            format!("tilde://date/{}", &link_content[1..])
                        } else if link_content.starts_with("email:") {
                            format!("tilde://email/{}", &link_content[6..])
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
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM collections WHERE name = 'bookmarks'",
        [],
        |row| row.get::<_, i64>(0),
    ).map(|c| c > 0)?;

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
        let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
        conn.execute(
            "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, 'bookmarks', ?2, ?3, ?4)",
            rusqlite::params![id, serde_json::to_string(&schema)?, now, now],
        )?;
    }
    Ok(())
}

pub async fn run_calendar(config_path: Option<&str>, command: CalendarCommands) -> anyhow::Result<()> {
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
                println!("{:<20} {:<30} {:<10} {}", "NAME", "DISPLAY NAME", "CTAG", "DESCRIPTION");
                println!("{}", "-".repeat(80));
                for (name, display_name, ctag, desc) in &calendars {
                    println!("{:<20} {:<30} {:<10} {}", name, display_name, ctag, desc.as_deref().unwrap_or(""));
                }
            }
        }
        CalendarCommands::Events { from, to, calendar } => {
            let events = tilde_cal::list_events(
                &conn,
                calendar.as_deref(),
                from.as_deref(),
                to.as_deref(),
            );
            if events.is_empty() {
                println!("No events found.");
            } else {
                println!("{:<38} {:<8} {:<30} {:<22} {:<22} {}", "UID", "TYPE", "SUMMARY", "START", "END", "LOCATION");
                println!("{}", "-".repeat(140));
                for (uid, comp_type, summary, dtstart, dtend, location, _status) in &events {
                    println!("{:<38} {:<8} {:<30} {:<22} {:<22} {}",
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

pub async fn run_contacts(config_path: Option<&str>, command: ContactsCommands) -> anyhow::Result<()> {
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
                println!("{:<38} {:<30} {:<30} {:<20} {}", "UID", "NAME", "EMAIL", "PHONE", "ORG");
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!("{:<38} {:<30} {:<30} {:<20} {}",
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
                println!("{:<38} {:<30} {:<30} {:<20} {}", "UID", "NAME", "EMAIL", "PHONE", "ORG");
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!("{:<38} {:<30} {:<30} {:<20} {}",
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
