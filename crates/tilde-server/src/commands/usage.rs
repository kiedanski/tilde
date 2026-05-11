use tilde_core::{config::Config, db};

use super::walkdir;

/// Query a single i64 count from the database.
fn count(conn: &rusqlite::Connection, sql: &str) -> i64 {
    conn.query_row(sql, [], |row| row.get(0)).unwrap_or(0)
}

/// Query recent activity rows: (description, timestamp).
fn recent_activity(conn: &rusqlite::Connection, limit: u32) -> Vec<(String, String)> {
    let sql = format!(
        "SELECT description, ts FROM (
            SELECT 'Uploaded ' || name AS description, modified_at AS ts
              FROM files WHERE is_directory = 0
            UNION ALL
            SELECT CASE component_type
                     WHEN 'VTODO' THEN 'Task: ' || COALESCE(summary, uid)
                     ELSE 'Event: ' || COALESCE(summary, uid)
                   END,
                   updated_at
              FROM calendar_objects WHERE deleted = 0
            UNION ALL
            SELECT 'Contact: ' || COALESCE(fn_name, uid), updated_at
              FROM contacts WHERE deleted = 0
         ) ORDER BY ts DESC LIMIT {}",
        limit
    );
    let mut stmt = conn.prepare(&sql).unwrap();
    stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })
    .unwrap()
    .flatten()
    .collect()
}

/// Recursive directory size in bytes.
fn dir_size_bytes(path: &std::path::Path) -> u64 {
    walkdir(path).unwrap_or(0)
}

/// Format bytes as human-readable (KB, MB, GB).
fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

/// Truncate a timestamp to just the date+time portion for display.
fn short_ts(ts: &str) -> &str {
    // "2026-05-11T15:28:33-03:00" → "2026-05-11 15:28"
    if ts.len() >= 16 { &ts[..16] } else { ts }
}

pub async fn run_usage(config_path: Option<&str>, json_output: bool) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let db_path = config.db_path();
    let data_dir = config.data_dir();

    if !db_path.exists() {
        println!("Database not found. Run `tilde init` first.");
        return Ok(());
    }

    let conn = db::init_db(db_path.to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    // Counts
    let photos = count(&conn, "SELECT COUNT(*) FROM photos");
    let thumbnails = count(
        &conn,
        "SELECT COUNT(*) FROM photos WHERE thumbnail_256_generated = 1",
    );
    let files_total = count(&conn, "SELECT COUNT(*) FROM files WHERE is_directory = 0");
    let notes = count(
        &conn,
        "SELECT COUNT(*) FROM files WHERE path LIKE 'notes/%' AND is_directory = 0",
    );
    let contacts = count(&conn, "SELECT COUNT(*) FROM contacts WHERE deleted = 0");
    let events = count(
        &conn,
        "SELECT COUNT(*) FROM calendar_objects WHERE deleted = 0 AND component_type = 'VEVENT'",
    );
    let tasks = count(
        &conn,
        "SELECT COUNT(*) FROM calendar_objects WHERE deleted = 0 AND component_type = 'VTODO'",
    );
    let emails = count(&conn, "SELECT COUNT(*) FROM email_messages");
    let bookmarks = count(&conn, "SELECT COUNT(*) FROM links");
    let collections = count(&conn, "SELECT COUNT(*) FROM collections");
    let pending_jobs = count(&conn, "SELECT COUNT(*) FROM jobs WHERE status = 'pending'");
    let failed_jobs = count(&conn, "SELECT COUNT(*) FROM jobs WHERE status = 'failed'");

    // Storage
    let db_bytes = db_path.metadata().map(|m| m.len()).unwrap_or(0);
    let photos_dir = data_dir.join("photos");
    let files_dir = data_dir.join("files");
    let notes_dir = data_dir.join("notes");
    let cache_dir = config.cache_dir();

    if json_output {
        let activity: Vec<serde_json::Value> = recent_activity(&conn, 20)
            .into_iter()
            .map(|(desc, ts)| serde_json::json!({"description": desc, "timestamp": ts}))
            .collect();

        let status = serde_json::json!({
            "counts": {
                "photos": photos,
                "thumbnails": thumbnails,
                "files": files_total,
                "notes": notes,
                "contacts": contacts,
                "events": events,
                "tasks": tasks,
                "emails": emails,
                "bookmarks": bookmarks,
                "collections": collections,
                "pending_jobs": pending_jobs,
                "failed_jobs": failed_jobs,
            },
            "storage": {
                "database_bytes": db_bytes,
                "photos_bytes": if photos_dir.exists() { dir_size_bytes(&photos_dir) } else { 0 },
                "files_bytes": if files_dir.exists() { dir_size_bytes(&files_dir) } else { 0 },
                "notes_bytes": if notes_dir.exists() { dir_size_bytes(&notes_dir) } else { 0 },
                "cache_bytes": if cache_dir.exists() { dir_size_bytes(&cache_dir) } else { 0 },
            },
            "recent_activity": activity,
        });
        println!("{}", serde_json::to_string_pretty(&status)?);
        return Ok(());
    }

    // Human-readable output
    println!("tilde — Usage");
    println!("=============");
    println!();
    println!("  Content");
    println!("  -------");
    println!("  Photos:      {:>6}  ({} thumbnails)", photos, thumbnails);
    println!("  Files:       {:>6}", files_total);
    println!("  Notes:       {:>6}", notes);
    println!("  Contacts:    {:>6}", contacts);
    println!("  Events:      {:>6}", events);
    println!("  Tasks:       {:>6}", tasks);
    println!("  Emails:      {:>6}", emails);
    println!("  Bookmarks:   {:>6}", bookmarks);
    println!("  Collections: {:>6}", collections);

    if pending_jobs > 0 || failed_jobs > 0 {
        println!();
        println!("  Jobs");
        println!("  ----");
        if pending_jobs > 0 {
            println!("  Pending:     {:>6}", pending_jobs);
        }
        if failed_jobs > 0 {
            println!("  Failed:      {:>6}", failed_jobs);
        }
    }

    println!();
    println!("  Storage");
    println!("  -------");
    println!("  Database:    {:>10}", format_bytes(db_bytes));
    if photos_dir.exists() {
        println!(
            "  Photos:      {:>10}",
            format_bytes(dir_size_bytes(&photos_dir))
        );
    }
    if files_dir.exists() {
        println!(
            "  Files:       {:>10}",
            format_bytes(dir_size_bytes(&files_dir))
        );
    }
    if notes_dir.exists() {
        println!(
            "  Notes:       {:>10}",
            format_bytes(dir_size_bytes(&notes_dir))
        );
    }
    if cache_dir.exists() {
        println!(
            "  Cache:       {:>10}",
            format_bytes(dir_size_bytes(&cache_dir))
        );
    }

    // Recent activity
    let activity = recent_activity(&conn, 10);
    if !activity.is_empty() {
        println!();
        println!("  Recent Activity");
        println!("  ---------------");
        for (desc, ts) in &activity {
            let display_ts = short_ts(ts).replace('T', " ");
            // Truncate description to fit terminal
            let desc_short = if desc.len() > 50 {
                format!("{}...", &desc[..47])
            } else {
                desc.clone()
            };
            println!("  {}  {}", display_ts, desc_short);
        }
    }

    Ok(())
}
