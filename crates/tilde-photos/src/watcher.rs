//! File system watcher for photo ingestion
//!
//! Watches _inbox/ and _library-drop/ for new files and processes them.

use crate::ingest;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tracing::{info, warn, error, debug};

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
                ready = map.iter()
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
                    debounce_pending.lock().unwrap().insert(path, std::time::Instant::now());
                    continue;
                }

                let conn = debounce_conn.lock().unwrap();
                let result = if path.starts_with(&debounce_inbox) {
                    ingest::process_inbox_file(&conn, &path, &debounce_photos, &debounce_pattern)
                } else if path.starts_with(&debounce_library) {
                    ingest::process_library_drop_file(&conn, &path, &debounce_photos, &debounce_library)
                } else {
                    continue;
                };

                match result {
                    Ok(ingest::IngestResult::Indexed { photo_id, destination }) => {
                        info!(photo_id = %photo_id, dest = %destination.display(), "File watcher: photo ingested");
                        // Attempt thumbnail generation
                        drop(conn);
                        let ext = destination.extension()
                            .and_then(|e| e.to_str())
                            .unwrap_or("");
                        if crate::is_photo_ext(ext) {
                            match crate::thumbnail::generate_thumbnails(&destination, &photo_id, &debounce_cache, thumbnail_quality) {
                                Ok(_) => {
                                    if let Ok(c) = debounce_conn.lock() {
                                        let _ = crate::thumbnail::mark_thumbnails_generated(&c, &photo_id, true, true);
                                    }
                                }
                                Err(e) => warn!(error = %e, "Thumbnail generation failed"),
                            }
                        }
                    }
                    Ok(ingest::IngestResult::Untriaged { photo_id, destination }) => {
                        info!(photo_id = %photo_id, dest = %destination.display(), "File watcher: photo untriaged");
                    }
                    Ok(ingest::IngestResult::Error { destination, error }) => {
                        warn!(dest = %destination.display(), error = %error, "File watcher: ingestion error");
                    }
                    Err(e) => {
                        error!(error = %e, "File watcher: processing failed");
                    }
                }
            }
        }
    });

    // Create filesystem watcher
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, notify::Error>| {
        match res {
            Ok(event) => {
                match event.kind {
                    EventKind::Create(_) | EventKind::Modify(_) => {
                        for path in &event.paths {
                            if path.is_file() {
                                let ext = path.extension()
                                    .and_then(|e| e.to_str())
                                    .unwrap_or("");
                                if crate::is_media_ext(ext) {
                                    debug!(path = %path.display(), "File watcher: new file detected");
                                    pending_clone.lock().unwrap()
                                        .insert(path.clone(), std::time::Instant::now());
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
            Err(e) => warn!(error = %e, "File watcher error"),
        }
    })?;

    watcher.watch(&inbox, RecursiveMode::Recursive)?;
    watcher.watch(&library_drop, RecursiveMode::Recursive)?;

    info!(inbox = %inbox.display(), library_drop = %library_drop.display(), "Photo file watcher started");

    Ok(watcher)
}
