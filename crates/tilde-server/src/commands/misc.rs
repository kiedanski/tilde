use tilde_cli::{
    BookmarksCommands, CalendarCommands, ContactsCommands, ExportCommands,
    NotificationCommands, UpdateCommands, WebhookCommands, WebhookTokenCommands,
};
use tilde_core::{auth, config::Config, db};

use super::{
    copy_dir_recursive, count_files, count_media_files,
    reindex_photos_from_dir_progress,
};

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

pub async fn run_reindex(config_path: Option<&str>, index_type: &str) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    let notes_dir = config.data_dir().join("notes");

    match index_type {
        "notes" | "all" => {
            // Notes search uses grep — no index to rebuild
            println!("Notes search uses grep (no index needed)");
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
            println!("Email indexing removed — emails are stored as Maildir only");
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

// --- Private helper functions ---

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

/// Compare two semver-like version strings. Returns true if `latest` is newer than `current`.
fn version_is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.').filter_map(|s| s.parse().ok()).collect()
    };
    let c = parse(current);
    let l = parse(latest);
    l > c
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
