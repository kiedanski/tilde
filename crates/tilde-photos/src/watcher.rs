//! File system watcher for photo ingestion
//!
//! Watches _inbox/ and _library-drop/ for new files and processes them.

use crate::ingest;
use notify::{Event, EventKind, RecursiveMode, Watcher};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{debug, error, info, warn};

/// Start watching the photos directories for new files.
/// This function spawns a background thread that watches _inbox/ and _library-drop/.
pub fn start_watcher(
    conn: Arc<Mutex<Connection>>,
    photos_base: PathBuf,
    cache_dir: PathBuf,
    organization_pattern: String,
    debounce_secs: u64,
    thumbnail_quality: u8,
) -> anyhow::Result<notify::RecommendedWatcher> {
    let inbox = photos_base.join("_inbox");
    let library_drop = photos_base.join("_library-drop");

    // Ensure dirs exist
    std::fs::create_dir_all(&inbox)?;
    std::fs::create_dir_all(&library_drop)?;

    // Debounce: track pending files
    let pending: Arc<Mutex<std::collections::HashMap<PathBuf, std::time::Instant>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_clone = pending.clone();

    // Spawn debounce processor thread
    let debounce_pending = pending.clone();
    let debounce_conn = conn.clone();
    let debounce_photos = photos_base.clone();
    let debounce_pattern = organization_pattern.clone();
    let debounce_inbox = inbox.clone();
    let debounce_library = library_drop.clone();
    let debounce_cache = cache_dir.clone();

    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));

            let now = std::time::Instant::now();
            let ready: Vec<PathBuf>;
            {
                let mut map = debounce_pending.lock().unwrap();
                ready = map
                    .iter()
                    .filter(|(_, instant)| now.duration_since(**instant).as_secs() >= debounce_secs)
                    .map(|(path, _)| path.clone())
                    .collect();
                for path in &ready {
                    map.remove(path);
                }
            }

            for path in ready {
                if !path.exists() {
                    continue;
                }

                // Check file is stable (size not changing)
                let size1 = path.metadata().map(|m| m.len()).unwrap_or(0);
                std::thread::sleep(Duration::from_millis(500));
                let size2 = path.metadata().map(|m| m.len()).unwrap_or(0);
                if size1 != size2 || size1 == 0 {
                    // Re-add with fresh timestamp
                    debounce_pending
                        .lock()
                        .unwrap()
                        .insert(path, std::time::Instant::now());
                    continue;
                }

                // Process the file with a short-lived DB lock
                let result = {
                    let conn = debounce_conn.lock().unwrap();
                    let r = if path.starts_with(&debounce_inbox) {
                        ingest::process_inbox_file(
                            &conn,
                            &path,
                            &debounce_photos,
                            &debounce_pattern,
                        )
                    } else if path.starts_with(&debounce_library) {
                        ingest::process_library_drop_file(
                            &conn,
                            &path,
                            &debounce_photos,
                            &debounce_library,
                        )
                    } else {
                        continue;
                    };

                    // Create thumbnail job while we have the lock
                    if let Ok(ingest::IngestResult::Indexed {
                        ref photo_id,
                        ref destination,
                    }) = r
                    {
                        let _ = crate::create_thumbnail_job(
                            &conn,
                            photo_id,
                            &destination.to_string_lossy(),
                            &debounce_cache.to_string_lossy(),
                            thumbnail_quality,
                        );
                    }

                    r
                    // conn dropped here — lock released before slow thumbnail work
                };

                // Generate thumbnails for indexed/untriaged photos (no DB lock held)
                let thumb_info = match &result {
                    Ok(ingest::IngestResult::Indexed {
                        photo_id,
                        destination,
                    }) => {
                        info!(photo_id = %photo_id, dest = %destination.display(), "File watcher: photo ingested");
                        Some((photo_id.clone(), destination.clone()))
                    }
                    Ok(ingest::IngestResult::Untriaged {
                        photo_id,
                        destination,
                    }) => {
                        info!(photo_id = %photo_id, dest = %destination.display(), "File watcher: photo untriaged");
                        Some((photo_id.clone(), destination.clone()))
                    }
                    Ok(ingest::IngestResult::AlreadyProcessed) => {
                        debug!("File watcher: file already processed, skipping");
                        None
                    }
                    Ok(ingest::IngestResult::Error {
                        destination, error, ..
                    }) => {
                        warn!(dest = %destination.display(), error = %error, "File watcher: ingestion error");
                        None
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher: processing failed");
                        None
                    }
                };

                // Thumbnail generation (slow) runs without holding the DB lock
                if let Some((photo_id, destination)) = thumb_info {
                    let ext = destination
                        .extension()
                        .and_then(|e| e.to_str())
                        .unwrap_or("");
                    let thumb_result = if crate::is_photo_ext(ext) {
                        Some(crate::thumbnail::generate_thumbnails(
                            &destination,
                            &photo_id,
                            &debounce_cache,
                            thumbnail_quality,
                        ))
                    } else if crate::is_video_ext(ext) {
                        Some(crate::thumbnail::generate_video_thumbnail(
                            &destination,
                            &photo_id,
                            &debounce_cache,
                            thumbnail_quality,
                            60,
                        ))
                    } else {
                        None
                    };

                    if let Some(Ok(_)) = thumb_result {
                        // Brief lock to mark completion
                        if let Ok(c) = debounce_conn.lock() {
                            let _ = crate::thumbnail::mark_thumbnails_generated(
                                &c, &photo_id, true, true,
                            );
                            let _ = c.execute(
                                "UPDATE jobs SET status = 'completed', completed_at = ?1 WHERE job_type = 'thumbnail' AND payload_json LIKE ?2 AND status = 'pending'",
                                rusqlite::params![
                                    jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
                                    format!("%{}%", photo_id),
                                ],
                            );
                        }
                    } else if let Some(Err(e)) = thumb_result {
                        warn!(error = %e, "Thumbnail generation failed");
                    }
                }
            }
        }
    });

    // Create filesystem watcher
    let mut watcher =
        notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => match event.kind {
                EventKind::Create(_) | EventKind::Modify(_) => {
                    for path in &event.paths {
                        if path.is_file() {
                            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            if crate::is_media_ext(ext) {
                                debug!(path = %path.display(), "File watcher: new file detected");
                                pending_clone
                                    .lock()
                                    .unwrap()
                                    .insert(path.clone(), std::time::Instant::now());
                            }
                        }
                    }
                }
                _ => {}
            },
            Err(e) => warn!(error = %e, "File watcher error"),
        })?;

    watcher.watch(&inbox, RecursiveMode::Recursive)?;
    watcher.watch(&library_drop, RecursiveMode::Recursive)?;

    info!(inbox = %inbox.display(), library_drop = %library_drop.display(), "Photo file watcher started");

    Ok(watcher)
}
