//! tilde-notify: notification sinks (file, ntfy, smtp, matrix, signal, webhook)
//!
//! Priority-routed notification system with rate limiting.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::Instant;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

/// Notification priority levels
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Low => write!(f, "low"),
            Priority::Medium => write!(f, "medium"),
            Priority::High => write!(f, "high"),
            Priority::Critical => write!(f, "critical"),
        }
    }
}

/// A notification event
#[derive(Debug, Clone)]
pub struct NotificationEvent {
    pub event_type: String,
    pub priority: Priority,
    pub message: String,
}

/// Rate limiter for notifications (max per event type per hour)
pub struct NotificationRateLimiter {
    /// event_type → list of send timestamps
    events: Mutex<HashMap<String, Vec<Instant>>>,
    max_per_hour: u32,
}

impl NotificationRateLimiter {
    pub fn new(max_per_hour: u32) -> Self {
        Self {
            events: Mutex::new(HashMap::new()),
            max_per_hour,
        }
    }

    /// Returns true if the event is allowed (not rate-limited)
    pub fn check(&self, event_type: &str) -> bool {
        let mut events = self.events.lock().unwrap();
        let now = Instant::now();
        let hour = std::time::Duration::from_secs(3600);

        let timestamps = events.entry(event_type.to_string()).or_default();
        timestamps.retain(|t| now.duration_since(*t) < hour);

        if timestamps.len() >= self.max_per_hour as usize {
            return false;
        }

        timestamps.push(now);
        true
    }
}

/// Notification sink trait
pub trait NotificationSink {
    fn name(&self) -> &str;
    fn min_priority(&self) -> Priority;
    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()>;
}

/// File notification sink — append-only log file
pub struct FileSink {
    path: PathBuf,
    min_priority: Priority,
}

impl FileSink {
    pub fn new(path: PathBuf, min_priority: Priority) -> Self {
        Self { path, min_priority }
    }
}

impl NotificationSink for FileSink {
    fn name(&self) -> &str {
        "file"
    }

    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        use std::io::Write;
        let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
        let line = format!(
            "[{}] [{}] [{}] {}\n",
            now, event.priority, event.event_type, event.message
        );

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;

        file.write_all(line.as_bytes())?;
        info!(sink = "file", event_type = %event.event_type, "Notification logged to file");
        Ok(())
    }
}

/// Log a notification event to the notification_log table
pub fn log_notification(
    conn: &Connection,
    event: &NotificationEvent,
    sinks_notified: &[&str],
) -> anyhow::Result<()> {
    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let sinks_json = serde_json::to_string(sinks_notified)?;

    conn.execute(
        "INSERT INTO notification_log (event_type, priority, message, sinks_notified, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![event.event_type, event.priority.to_string(), event.message, sinks_json, now],
    )?;

    Ok(())
}

/// Send a notification through all configured sinks, respecting priority and rate limits
pub fn notify(
    sinks: &[Box<dyn NotificationSink>],
    rate_limiter: &NotificationRateLimiter,
    conn: &Connection,
    event: NotificationEvent,
) {
    if !rate_limiter.check(&event.event_type) {
        warn!(event_type = %event.event_type, "Notification rate-limited");
        return;
    }

    let mut notified_sinks = Vec::new();

    for sink in sinks {
        if event.priority >= sink.min_priority() {
            match sink.send(&event) {
                Ok(()) => notified_sinks.push(sink.name()),
                Err(e) => warn!(sink = sink.name(), error = %e, "Notification send failed"),
            }
        }
    }

    if let Err(e) = log_notification(conn, &event, &notified_sinks) {
        warn!(error = %e, "Failed to log notification");
    }
}

/// Create the default file sink pointing to the data directory
pub fn create_file_sink(data_dir: &Path) -> FileSink {
    FileSink::new(
        data_dir.join("notifications.log"),
        Priority::Low, // file sink logs everything
    )
}
