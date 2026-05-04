use tilde_core::{config::Config, db};

use super::{count_media_files, reindex_photos_from_dir_progress};

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
                println!(
                    "Rebuilding photos index from disk ({} files found)...",
                    total
                );
                let progress = std::sync::atomic::AtomicUsize::new(0);
                match reindex_photos_from_dir_progress(
                    &conn,
                    &photos_dir,
                    &photos_dir,
                    Some(&progress),
                ) {
                    Ok(count) => {
                        eprintln!();
                        println!(
                            "  done ({} new photos indexed, {} total scanned)",
                            count,
                            progress.load(std::sync::atomic::Ordering::Relaxed)
                        );
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
