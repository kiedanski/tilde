//! IMAP client for email fetching via `imap` crate.
//!
//! Supports SSL connections, IDLE for push notifications, poll fallback,
//! UID-based incremental sync, and retry with exponential backoff.
//! Uses sync imap crate with tokio::task::spawn_blocking for async compat.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Configuration for a single IMAP email account.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImapAccountConfig {
    pub name: String,
    pub imap_host: String,
    pub imap_port: u16,
    pub username: String,
    pub password: String,
    pub use_ssl: bool,
    pub idle_enabled: bool,
    pub folders_include: Vec<String>,
    pub folders_exclude: Vec<String>,
    pub retention_days: u32,
    pub poll_interval_seconds: u64,
}

impl Default for ImapAccountConfig {
    fn default() -> Self {
        Self {
            name: "personal".to_string(),
            imap_host: String::new(),
            imap_port: 993,
            username: String::new(),
            password: String::new(),
            use_ssl: true,
            idle_enabled: true,
            folders_include: vec![],
            folders_exclude: vec!["Trash".to_string(), "Spam".to_string()],
            retention_days: 0,
            poll_interval_seconds: 300,
        }
    }
}

impl ImapAccountConfig {
    /// Check if a folder should be synced based on include/exclude filters.
    pub fn should_sync_folder(&self, folder: &str) -> bool {
        if !self.folders_include.is_empty() {
            return self.folders_include.iter().any(|f| f == folder);
        }
        !self.folders_exclude.iter().any(|f| f == folder)
    }
}

/// Connect to IMAP server with SSL and login.
fn connect_and_login(
    config: &ImapAccountConfig,
) -> Result<imap::Session<native_tls::TlsStream<std::net::TcpStream>>> {
    info!(
        host = %config.imap_host,
        port = config.imap_port,
        username = %config.username,
        ssl = config.use_ssl,
        "Connecting to IMAP server"
    );

    let tls = native_tls::TlsConnector::builder().build()?;
    let client = imap::connect(
        (config.imap_host.as_str(), config.imap_port),
        &config.imap_host,
        &tls,
    )
    .context("Failed to connect to IMAP server")?;

    info!("IMAP SSL connection established");

    let session = client
        .login(&config.username, &config.password)
        .map_err(|e| anyhow::anyhow!("IMAP login failed: {}", e.0))?;

    info!(username = %config.username, "IMAP login successful");
    Ok(session)
}

/// List available folders on the IMAP server.
fn list_folders(
    session: &mut imap::Session<native_tls::TlsStream<std::net::TcpStream>>,
) -> Result<Vec<String>> {
    let folders = session.list(None, Some("*"))?;
    let names: Vec<String> = folders.iter().map(|f| f.name().to_string()).collect();
    info!(count = names.len(), "Listed IMAP folders");
    Ok(names)
}

/// Fetch new messages from a folder using UID-based tracking.
fn fetch_new_messages(
    session: &mut imap::Session<native_tls::TlsStream<std::net::TcpStream>>,
    folder: &str,
    last_uid: Option<u32>,
) -> Result<Vec<(u32, Vec<u8>)>> {
    session.select(folder)?;

    let uid_range = match last_uid {
        Some(uid) => format!("{}:*", uid + 1),
        None => "1:*".to_string(),
    };

    debug!(folder = %folder, uid_range = %uid_range, "Fetching messages");

    let messages = session.uid_fetch(&uid_range, "(UID RFC822)")?;

    let mut results = Vec::new();
    for msg in messages.iter() {
        if let (Some(uid), Some(body)) = (msg.uid, msg.body()) {
            if let Some(last) = last_uid && uid <= last {
                continue;
            }
            results.push((uid, body.to_vec()));
        }
    }

    info!(folder = %folder, count = results.len(), "Fetched new messages");
    Ok(results)
}

/// Enter IDLE mode on INBOX and wait for changes.
fn idle_wait(
    session: &mut imap::Session<native_tls::TlsStream<std::net::TcpStream>>,
    timeout_secs: u64,
) -> Result<()> {
    info!(timeout_secs = timeout_secs, "Entering IMAP IDLE mode on INBOX");

    session.select("INBOX")?;

    let idle = session.idle()?;
    let result = idle.wait_with_timeout(std::time::Duration::from_secs(timeout_secs));

    match result {
        Ok(reason) => {
            info!(reason = ?reason, "IMAP IDLE completed");
        }
        Err(e) => {
            warn!(error = %e, "IMAP IDLE error");
        }
    }

    Ok(())
}

/// Run one sync cycle: connect, list folders, fetch new messages, store.
fn sync_cycle(
    config: &ImapAccountConfig,
    conn: &rusqlite::Connection,
    maildir_base: &std::path::Path,
) -> Result<()> {
    let mut session = connect_and_login(config)?;

    let folders = list_folders(&mut session)?;

    for folder in &folders {
        if !config.should_sync_folder(folder) {
            debug!(folder = %folder, "Skipping excluded folder");
            continue;
        }

        let last_uid = get_last_uid(conn, &config.name, folder);
        let messages = fetch_new_messages(&mut session, folder, last_uid)?;

        if messages.is_empty() {
            continue;
        }

        let mut max_uid = last_uid.unwrap_or(0);

        for (uid, raw) in &messages {
            let writer = crate::MaildirWriter::new(maildir_base)?;
            let maildir_path = writer.write_message(&config.name, folder, *uid, raw)?;

            if let Ok(parsed) = crate::ParsedEmail::parse(raw) {
                let _ = crate::index_email(conn, &config.name, folder, *uid, &maildir_path, &parsed);
            }

            if *uid > max_uid {
                max_uid = *uid;
            }
        }

        if max_uid > last_uid.unwrap_or(0) {
            set_last_uid(conn, &config.name, folder, max_uid)?;
        }

        info!(
            account = %config.name,
            folder = %folder,
            new_messages = messages.len(),
            "Folder sync complete"
        );
    }

    record_sync(conn, &config.name)?;
    let _ = session.logout();

    Ok(())
}

/// Run the email sync loop for one account (async wrapper).
/// Handles IDLE, polling fallback, and retry with exponential backoff.
pub async fn run_sync_loop(
    config: ImapAccountConfig,
    db: Arc<Mutex<rusqlite::Connection>>,
    maildir_base: std::path::PathBuf,
) {
    let mut retry_delay = std::time::Duration::from_secs(5);
    let max_retry_delay = std::time::Duration::from_secs(300);

    loop {
        // Run sync in blocking thread
        let config_clone = config.clone();
        let db_clone = db.clone();
        let maildir_clone = maildir_base.clone();

        let result = tokio::task::spawn_blocking(move || {
            let conn = db_clone.blocking_lock();
            sync_cycle(&config_clone, &conn, &maildir_clone)
        })
        .await;

        match result {
            Ok(Ok(())) => {
                retry_delay = std::time::Duration::from_secs(5);
                info!(account = %config.name, "Sync cycle completed successfully");
            }
            Ok(Err(e)) => {
                error!(
                    account = %config.name,
                    error = %e,
                    retry_secs = retry_delay.as_secs(),
                    "IMAP sync error — retrying with exponential backoff"
                );
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
                continue;
            }
            Err(e) => {
                error!(error = %e, "Sync task panicked");
                tokio::time::sleep(retry_delay).await;
                retry_delay = (retry_delay * 2).min(max_retry_delay);
                continue;
            }
        }

        // After successful sync: IDLE or poll
        if config.idle_enabled {
            let config_for_idle = config.clone();
            let idle_result = tokio::task::spawn_blocking(move || {
                let mut session = connect_and_login(&config_for_idle)?;
                idle_wait(&mut session, 1740)?; // 29 min
                let _ = session.logout();
                Ok::<_, anyhow::Error>(())
            })
            .await;

            match idle_result {
                Ok(Ok(())) => {
                    info!(account = %config.name, "IDLE notification — re-syncing");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "IDLE error — will retry");
                    tokio::time::sleep(retry_delay).await;
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                }
                Err(e) => {
                    error!(error = %e, "IDLE task panicked");
                    tokio::time::sleep(retry_delay).await;
                }
            }
        } else {
            info!(
                account = %config.name,
                interval_secs = config.poll_interval_seconds,
                "IDLE disabled — polling fallback"
            );
            tokio::time::sleep(std::time::Duration::from_secs(
                config.poll_interval_seconds,
            ))
            .await;
        }
    }
}

/// Track the last seen UID per folder for incremental sync.
pub fn get_last_uid(conn: &rusqlite::Connection, account: &str, folder: &str) -> Option<u32> {
    let key = format!("imap:{}:{}:last_uid", account, folder);
    conn.query_row("SELECT value FROM kv_meta WHERE key = ?1", [&key], |row| {
        let val: String = row.get(0)?;
        Ok(val.parse::<u32>().ok())
    })
    .ok()
    .flatten()
}

/// Update the last seen UID for a folder.
pub fn set_last_uid(
    conn: &rusqlite::Connection,
    account: &str,
    folder: &str,
    uid: u32,
) -> anyhow::Result<()> {
    let key = format!("imap:{}:{}:last_uid", account, folder);
    let now = jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    conn.execute(
        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![key, uid.to_string(), now],
    )?;
    Ok(())
}

/// Get the sync status for an account.
pub fn get_sync_status(conn: &rusqlite::Connection, account: &str) -> SyncStatus {
    let message_count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM email_messages WHERE account = ?1",
            [account],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let last_sync_key = format!("imap:{}:last_sync", account);
    let last_sync: Option<String> = conn
        .query_row(
            "SELECT value FROM kv_meta WHERE key = ?1",
            [&last_sync_key],
            |row| row.get(0),
        )
        .ok();

    let folders: Vec<String> = {
        let mut stmt = conn
            .prepare("SELECT DISTINCT folder FROM email_messages WHERE account = ?1")
            .unwrap();
        stmt.query_map([account], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect()
    };

    SyncStatus {
        account: account.to_string(),
        message_count,
        last_sync,
        folders,
    }
}

#[derive(Debug)]
pub struct SyncStatus {
    pub account: String,
    pub message_count: i64,
    pub last_sync: Option<String>,
    pub folders: Vec<String>,
}

/// Record a successful sync timestamp.
pub fn record_sync(conn: &rusqlite::Connection, account: &str) -> anyhow::Result<()> {
    let key = format!("imap:{}:last_sync", account);
    let now = jiff::Timestamp::now()
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string();
    conn.execute(
        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES (?1, ?2, ?3)",
        rusqlite::params![key, &now, &now],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_folder_filtering_exclude() {
        let config = ImapAccountConfig {
            folders_exclude: vec!["Trash".to_string(), "Spam".to_string()],
            ..Default::default()
        };
        assert!(config.should_sync_folder("INBOX"));
        assert!(config.should_sync_folder("Sent"));
        assert!(!config.should_sync_folder("Trash"));
        assert!(!config.should_sync_folder("Spam"));
    }

    #[test]
    fn test_folder_filtering_include() {
        let config = ImapAccountConfig {
            folders_include: vec!["INBOX".to_string(), "Sent".to_string()],
            folders_exclude: vec!["Trash".to_string()],
            ..Default::default()
        };
        assert!(config.should_sync_folder("INBOX"));
        assert!(config.should_sync_folder("Sent"));
        assert!(!config.should_sync_folder("Drafts"));
        assert!(!config.should_sync_folder("Trash"));
    }
}
