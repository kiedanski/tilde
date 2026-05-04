use tilde_cli::PhotosCommands;
use tilde_core::{config::Config, db};

use super::reindex_photos_from_dir;

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
            let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();
            let mut idx = 1;
            if let Some(ref t) = tag {
                sql.push_str(&format!(" AND p.tags_json LIKE ?{}", idx));
                idx += 1;
                params.push(Box::new(format!("%{}%", t)));
            }
            if let Some(ref s) = since {
                sql.push_str(&format!(" AND p.taken_at >= ?{}", idx));
                idx += 1;
                params.push(Box::new(s.clone()));
            }
            if let Some(ref u) = until {
                sql.push_str(&format!(" AND p.taken_at <= ?{}", idx));
                let _ = idx;
                params.push(Box::new(u.clone()));
            }
            sql.push_str(" ORDER BY p.taken_at DESC LIMIT 100");

            let param_refs: Vec<&dyn rusqlite::types::ToSql> =
                params.iter().map(|p| p.as_ref()).collect();
            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map(param_refs.as_slice(), |row| {
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
                                    if let Ok(updated_meta) =
                                        tilde_photos::metadata::read_metadata(&full_path)
                                    {
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
                                                println!(
                                                    "Warning: failed to re-organize photo: {}",
                                                    e
                                                );
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
                                let _ = tilde_photos::thumbnail::create_thumbnail_symlink(
                                    &conn,
                                    photo_id,
                                    &photos_dir,
                                    &cache_dir,
                                );
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
