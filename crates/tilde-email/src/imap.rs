//! IMAP client for email fetching (async-imap integration)
//!
//! This module provides the IMAP client connection, UID-based tracking,
//! IDLE support, and folder filtering. Actual IMAP library integration
//! requires the async-imap crate which is not currently a dependency.
//! The module provides the data structures and configuration for when
//! IMAP connectivity is enabled.

use serde::{Deserialize, Serialize};

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
        // If include list is non-empty, only sync listed folders
        if !self.folders_include.is_empty() {
            return self.folders_include.iter().any(|f| f == folder);
        }
        // Otherwise, exclude listed folders
        !self.folders_exclude.iter().any(|f| f == folder)
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
        // When include is non-empty, only included folders are synced
        assert!(config.should_sync_folder("INBOX"));
        assert!(config.should_sync_folder("Sent"));
        assert!(!config.should_sync_folder("Drafts"));
        assert!(!config.should_sync_folder("Trash"));
    }
}
