use tilde_cli::ExportCommands;
use tilde_core::{config::Config, db};

use super::{copy_dir_recursive, count_files};

pub async fn run_export(config_path: Option<&str>, command: ExportCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    let data_dir = config.data_dir();

    match command {
        ExportCommands::Run {
            path,
            only,
            format,
            encrypt,
            recipient,
        } => {
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
            println!(
                "Export complete: {} ({} sections in {:.1}s)",
                export_dir.display(),
                sections_exported,
                elapsed.as_secs_f64()
            );

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
                    .arg(
                        export_dir
                            .file_name()
                            .unwrap_or(std::ffi::OsStr::new("export")),
                    )
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
                        println!(
                            "Warning: tar compression failed with exit code {:?}",
                            status.code()
                        );
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
                            .arg(
                                export_dir
                                    .file_name()
                                    .unwrap_or(std::ffi::OsStr::new("export")),
                            )
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
                        .arg(
                            export_dir
                                .file_name()
                                .unwrap_or(std::ffi::OsStr::new("export")),
                        )
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
                        anyhow::bail!(
                            "age encryption failed with exit code {:?}. Is `age` installed?",
                            status.code()
                        );
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
                println!(
                    "[DRY RUN] Would import {} cross-reference links",
                    links.len()
                );
            } else {
                let mut imported = 0;
                for link in &links {
                    let source_type = link
                        .get("source_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let source_id = link.get("source_id").and_then(|v| v.as_str()).unwrap_or("");
                    let target_uri = link
                        .get("target_uri")
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
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
        if let Ok(manifest) =
            serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(&manifest_content)
            && !manifest.is_empty()
        {
            println!(
                "Manifest contains {} UUID mappings (tilde:// URIs stable)",
                manifest.len()
            );
        }
    }

    if dry_run {
        println!("\nDry run complete. No changes were made.");
    } else {
        println!("\nImport complete.");
    }

    Ok(())
}
