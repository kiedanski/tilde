//! File system watcher for the health inbox.
//!
//! Watches `files/health/_inbox/` for Gadgetbridge uploads (the sqlite export
//! plus per-workout .fit/.gpx files) and enqueues a `gadgetbridge_import` job.
//! The job regenerates the whole health tree from the inbox, so the payload
//! carries no path — one queued job covers any burst of uploads.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use notify::{Event, EventKind, RecursiveMode, Watcher};
use rusqlite::Connection;
use tilde_core::db::DbPool;
use tracing::{debug, info, warn};

fn is_health_ext(ext: &str) -> bool {
    matches!(ext, "db" | "sqlite" | "fit" | "gpx")
}

/// Enqueue a `gadgetbridge_import` job unless one is already pending or running.
/// A sqlite export uploaded over DAV produces a burst of Modify events; the
/// debounce window collapses most of them and this guard collapses the rest.
pub fn enqueue_import_job(conn: &Connection) -> anyhow::Result<bool> {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let inserted = conn.execute(
        "INSERT INTO jobs (job_type, payload_json, status, created_at)
         SELECT 'gadgetbridge_import', '{}', 'pending', ?1
         WHERE NOT EXISTS (
             SELECT 1 FROM jobs
             WHERE job_type = 'gadgetbridge_import' AND status IN ('pending', 'running')
         )",
        [now],
    )?;
    Ok(inserted > 0)
}

/// Start watching `<health_base>/_inbox` for Gadgetbridge uploads.
///
/// The returned watcher must be kept alive for the lifetime of the server —
/// dropping it stops the watch.
pub fn start_watcher(
    conn: DbPool,
    health_base: PathBuf,
    debounce_secs: u64,
) -> anyhow::Result<notify::RecommendedWatcher> {
    let inbox = health_base.join("_inbox");
    std::fs::create_dir_all(&inbox)?;

    let pending: Arc<Mutex<std::collections::HashMap<PathBuf, std::time::Instant>>> =
        Arc::new(Mutex::new(std::collections::HashMap::new()));
    let pending_clone = pending.clone();

    std::thread::spawn(move || {
        loop {
            std::thread::sleep(Duration::from_secs(1));

            let now = std::time::Instant::now();
            let ready: Vec<PathBuf> = {
                let mut map = pending.lock().unwrap();
                let ready: Vec<PathBuf> = map
                    .iter()
                    .filter(|(_, instant)| now.duration_since(**instant).as_secs() >= debounce_secs)
                    .map(|(path, _)| path.clone())
                    .collect();
                for path in &ready {
                    map.remove(path);
                }
                ready
            };

            let mut any_stable = false;
            for path in ready {
                if !path.exists() {
                    continue;
                }
                // A sqlite export can take a while to upload — require the size
                // to hold still before treating the file as complete.
                let size1 = path.metadata().map(|m| m.len()).unwrap_or(0);
                std::thread::sleep(Duration::from_millis(500));
                let size2 = path.metadata().map(|m| m.len()).unwrap_or(0);
                if size1 != size2 || size1 == 0 {
                    pending
                        .lock()
                        .unwrap()
                        .insert(path, std::time::Instant::now());
                    continue;
                }
                any_stable = true;
            }

            if any_stable {
                match conn.get() {
                    Ok(c) => match enqueue_import_job(&c) {
                        Ok(true) => info!("Health watcher: gadgetbridge_import job enqueued"),
                        Ok(false) => debug!("Health watcher: import job already queued"),
                        Err(e) => warn!(error = %e, "Health watcher: failed to enqueue job"),
                    },
                    Err(e) => warn!(error = %e, "Health watcher: DB pool exhausted"),
                }
            }
        }
    });

    let mut watcher =
        notify::recommended_watcher(move |res: Result<Event, notify::Error>| match res {
            Ok(event) => {
                if matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) {
                    for path in &event.paths {
                        if !path.is_file() {
                            continue;
                        }
                        let name = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default();
                        let ext = path
                            .extension()
                            .map(|e| e.to_string_lossy().to_lowercase())
                            .unwrap_or_default();
                        if !name.starts_with('.') && is_health_ext(&ext) {
                            debug!(path = %path.display(), "Health watcher: file detected");
                            pending_clone
                                .lock()
                                .unwrap()
                                .insert(path.clone(), std::time::Instant::now());
                        }
                    }
                }
            }
            Err(e) => warn!(error = %e, "Health watcher error"),
        })?;

    watcher.watch(&inbox, RecursiveMode::NonRecursive)?;
    info!(inbox = %inbox.display(), "Health inbox watcher started");
    Ok(watcher)
}
