//! CLI command implementations

mod auth;
mod backup;
mod bookmarks;
mod calendar;
mod collections;
mod contacts;
mod email;
mod export_import;
mod init;
mod mcp;
mod notes;
mod notifications;
mod photos;
mod reindex;
mod serve;
mod status;
mod update;
mod usage;
mod webhooks;

pub use auth::*;
pub use backup::*;
pub use bookmarks::*;
pub use calendar::*;
pub use collections::*;
pub use contacts::*;
pub use email::*;
pub use export_import::*;
pub use init::*;
pub use mcp::*;
pub use notes::*;
pub use notifications::*;
pub use photos::*;
pub use reindex::*;
pub use serve::*;
pub use status::*;
pub use update::*;
pub use usage::*;
pub use webhooks::*;

/// Read a line from stdin, returning the default if empty
pub(crate) fn prompt_with_default(prompt: &str, default: &str) -> String {
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
pub(crate) fn generate_recovery_code() -> String {
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

/// Recursively collect media files from a directory
pub(crate) fn walkdir_media(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    walkdir_media_inner(dir, &mut files);
    files
}

fn walkdir_media_inner(dir: &std::path::Path, files: &mut Vec<std::path::PathBuf>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with('.') {
                continue;
            }
            if path.is_dir() {
                walkdir_media_inner(&path, files);
            } else {
                let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                if tilde_photos::is_media_ext(ext) {
                    files.push(path);
                }
            }
        }
    }
}

/// Parse a schedule string into an interval in seconds
pub(crate) fn parse_schedule_interval(schedule: &str) -> u64 {
    let s = schedule.to_lowercase();
    // Strip @HH:MM suffix for interval calculation
    let base = s.split('@').next().unwrap_or(&s);
    match base {
        "hourly" => 3600,
        "daily" => 86400,
        "weekly" => 604800,
        "monthly" => 2592000, // ~30 days
        s if s.ends_with('s') => s[..s.len() - 1].parse().unwrap_or(3600),
        s if s.ends_with('m') => s[..s.len() - 1].parse::<u64>().unwrap_or(60) * 60,
        s if s.ends_with('h') => s[..s.len() - 1].parse::<u64>().unwrap_or(1) * 3600,
        _ => 86400, // default to daily
    }
}

/// Calculate seconds until the next occurrence of a scheduled time.
/// Supports formats like "daily@04:00", "daily@23:30".
/// For non-time-specific schedules (e.g., "hourly"), returns the interval directly.
pub(crate) fn secs_until_next_run(schedule: &str) -> u64 {
    let s = schedule.to_lowercase();
    if let Some(time_part) = s.split('@').nth(1) {
        // Parse HH:MM
        let parts: Vec<&str> = time_part.split(':').collect();
        if parts.len() == 2
            && let (Ok(hour), Ok(minute)) = (parts[0].parse::<i8>(), parts[1].parse::<i8>())
        {
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
    // No @HH:MM — just use the interval
    parse_schedule_interval(schedule)
}

/// Basic JSON Schema validation (supports type, required, properties)
pub(crate) fn validate_json_schema(
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

pub(crate) fn list_notes_recursive(
    dir: &std::path::Path,
    base: &std::path::Path,
) -> anyhow::Result<()> {
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

pub(crate) fn walkdir(path: &std::path::Path) -> anyhow::Result<u64> {
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

/// Prompt for confirmation on destructive operations. Returns true if user confirms.
pub(crate) fn confirm_prompt() -> bool {
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

pub(crate) fn count_files_recursive(dir: &std::path::Path) -> usize {
    let mut count = 0;
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                count += count_files_recursive(&path);
            } else {
                count += 1;
            }
        }
    }
    count
}

pub(crate) fn reindex_photos_from_dir(
    conn: &rusqlite::Connection,
    dir: &std::path::Path,
    base: &std::path::Path,
) -> anyhow::Result<usize> {
    reindex_photos_from_dir_progress(conn, dir, base, None)
}

pub(crate) fn reindex_photos_from_dir_progress(
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

pub(crate) fn count_media_files(dir: &std::path::Path) -> usize {
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
                let ext = path
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|e| e.to_lowercase())
                    .unwrap_or_default();
                if tilde_photos::is_media_ext(&ext) {
                    total += 1;
                }
            }
        }
    }
    total
}

pub(crate) fn copy_dir_recursive(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> anyhow::Result<()> {
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

pub(crate) fn count_files(dir: &std::path::Path) -> usize {
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

pub(crate) fn check_dep(name: &str) {
    match std::process::Command::new("which").arg(name).output() {
        Ok(output) if output.status.success() => println!("[OK]   {} found", name),
        _ => println!("[WARN] {} not found", name),
    }
}
