//! tilde-notify: notification sinks (file, ntfy, smtp, matrix, signal, webhook)
//!
//! Priority-routed notification system with rate limiting.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
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
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
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
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let sinks_json = serde_json::to_string(sinks_notified)?;

    conn.execute(
        "INSERT INTO notification_log (event_type, priority, message, sinks_notified, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            event.event_type,
            event.priority.to_string(),
            event.message,
            sinks_json,
            now
        ],
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

/// ntfy.sh notification sink
pub struct NtfySink {
    topic_url: String,
    token: Option<String>,
    min_priority: Priority,
}

impl NtfySink {
    pub fn new(topic_url: String, token: Option<String>, min_priority: Priority) -> Self {
        Self {
            topic_url,
            token,
            min_priority,
        }
    }
}

impl NotificationSink for NtfySink {
    fn name(&self) -> &str {
        "ntfy"
    }

    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        let ntfy_priority = match event.priority {
            Priority::Low => "2",
            Priority::Medium => "3",
            Priority::High => "4",
            Priority::Critical => "5",
        };

        let client = reqwest::blocking::Client::new();
        let mut req = client
            .post(&self.topic_url)
            .header("Title", format!("tilde: {}", event.event_type))
            .header("Priority", ntfy_priority)
            .header("Tags", &event.event_type)
            .body(event.message.clone());

        if let Some(ref token) = self.token {
            req = req.header("Authorization", format!("Bearer {}", token));
        }

        req.send()?;
        info!(sink = "ntfy", event_type = %event.event_type, "Notification sent to ntfy");
        Ok(())
    }
}

/// Webhook notification sink
pub struct WebhookSink {
    url: String,
    min_priority: Priority,
}

impl WebhookSink {
    pub fn new(url: String, min_priority: Priority) -> Self {
        Self { url, min_priority }
    }
}

impl NotificationSink for WebhookSink {
    fn name(&self) -> &str {
        "webhook"
    }

    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "event_type": event.event_type,
            "priority": event.priority.to_string(),
            "message": event.message,
            "timestamp": jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
        });

        let client = reqwest::blocking::Client::new();
        client.post(&self.url).json(&payload).send()?;

        info!(sink = "webhook", event_type = %event.event_type, "Notification sent to webhook");
        Ok(())
    }
}

/// SMTP notification sink (sends email)
#[allow(dead_code)]
pub struct SmtpSink {
    host: String,
    port: u16,
    username: String,
    password: String,
    to_address: String,
    min_priority: Priority,
}

impl SmtpSink {
    pub fn new(
        host: String,
        port: u16,
        username: String,
        password: String,
        to_address: String,
        min_priority: Priority,
    ) -> Self {
        Self {
            host,
            port,
            username,
            password,
            to_address,
            min_priority,
        }
    }
}

impl NotificationSink for SmtpSink {
    fn name(&self) -> &str {
        "smtp"
    }
    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        // SMTP implementation would use lettre or similar
        // For now, log the intent — actual SMTP requires a runtime mail library
        info!(
            sink = "smtp",
            to = %self.to_address,
            host = %self.host,
            event_type = %event.event_type,
            "SMTP notification would be sent (SMTP library not yet integrated)"
        );
        Ok(())
    }
}

/// Matrix notification sink
pub struct MatrixSink {
    homeserver: String,
    access_token: String,
    room_id: String,
    min_priority: Priority,
}

impl MatrixSink {
    pub fn new(
        homeserver: String,
        access_token: String,
        room_id: String,
        min_priority: Priority,
    ) -> Self {
        Self {
            homeserver,
            access_token,
            room_id,
            min_priority,
        }
    }
}

impl NotificationSink for MatrixSink {
    fn name(&self) -> &str {
        "matrix"
    }
    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        let url = format!(
            "{}/_matrix/client/r0/rooms/{}/send/m.room.message",
            self.homeserver,
            urlencoding::encode(&self.room_id)
        );

        let body = serde_json::json!({
            "msgtype": "m.text",
            "body": format!("[{}] {}: {}", event.priority, event.event_type, event.message)
        });

        let client = reqwest::blocking::Client::new();
        client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.access_token))
            .json(&body)
            .send()?;

        info!(sink = "matrix", room = %self.room_id, event_type = %event.event_type, "Notification sent to Matrix");
        Ok(())
    }
}

/// Signal notification sink (via signal-cli REST API)
pub struct SignalSink {
    api_url: String,
    recipient: String,
    min_priority: Priority,
}

impl SignalSink {
    pub fn new(api_url: String, recipient: String, min_priority: Priority) -> Self {
        Self {
            api_url,
            recipient,
            min_priority,
        }
    }
}

impl NotificationSink for SignalSink {
    fn name(&self) -> &str {
        "signal"
    }
    fn min_priority(&self) -> Priority {
        self.min_priority
    }

    fn send(&self, event: &NotificationEvent) -> anyhow::Result<()> {
        let url = format!("{}/v2/send", self.api_url);
        let body = serde_json::json!({
            "message": format!("[tilde] {}: {}", event.event_type, event.message),
            "number": self.recipient,
        });

        let client = reqwest::blocking::Client::new();
        client.post(&url).json(&body).send()?;

        info!(sink = "signal", recipient = %self.recipient, event_type = %event.event_type, "Notification sent via Signal");
        Ok(())
    }
}

/// Predefined notification event types
pub mod events {
    use super::{NotificationEvent, Priority};

    pub fn backup_failed(error: &str) -> NotificationEvent {
        NotificationEvent {
            event_type: "backup_failed".into(),
            priority: Priority::Critical,
            message: format!("Backup failed: {}", error),
        }
    }

    pub fn disk_usage_high(used_percent: u8) -> NotificationEvent {
        NotificationEvent {
            event_type: "disk_usage_high".into(),
            priority: Priority::High,
            message: format!("Disk usage at {}%", used_percent),
        }
    }

    pub fn auth_failed_repeated(ip: &str, count: u32) -> NotificationEvent {
        NotificationEvent {
            event_type: "auth_failed_repeated".into(),
            priority: Priority::High,
            message: format!("{} failed auth attempts from {}", count, ip),
        }
    }

    pub fn cert_expiring_soon(days: u32) -> NotificationEvent {
        NotificationEvent {
            event_type: "cert_expiring_soon".into(),
            priority: Priority::High,
            message: format!("TLS certificate expires in {} days", days),
        }
    }

    pub fn sync_conflict_detected(path: &str) -> NotificationEvent {
        NotificationEvent {
            event_type: "sync_conflict_detected".into(),
            priority: Priority::Medium,
            message: format!("Sync conflict detected: {}", path),
        }
    }

    pub fn update_available(version: &str) -> NotificationEvent {
        NotificationEvent {
            event_type: "update_available".into(),
            priority: Priority::Low,
            message: format!("tilde update available: {}", version),
        }
    }

    pub fn email_sync_error(account: &str, error: &str) -> NotificationEvent {
        NotificationEvent {
            event_type: "email_sync_error".into(),
            priority: Priority::Medium,
            message: format!("Email sync error ({}): {}", account, error),
        }
    }

    pub fn thumbnail_generation_failed(file: &str, error: &str) -> NotificationEvent {
        NotificationEvent {
            event_type: "thumbnail_generation_failed".into(),
            priority: Priority::Low,
            message: format!("Thumbnail generation failed for {}: {}", file, error),
        }
    }
}

/// Create the default file sink pointing to the data directory
pub fn create_file_sink(data_dir: &Path) -> FileSink {
    FileSink::new(
        data_dir.join("notifications.log"),
        Priority::Low, // file sink logs everything
    )
}
