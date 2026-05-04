use tilde_core::{config::Config, db};

use super::{check_dep, walkdir};

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
            let db_size = db_path.metadata().map(|m| m.len()).unwrap_or(0);

            status["migrations_applied"] = serde_json::json!(migrations.len());
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
