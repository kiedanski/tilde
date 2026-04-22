//! SQLite indexing and FTS5 search for email messages

use anyhow::{Context, Result};
use rusqlite::Connection;
use crate::parser::ParsedEmail;
use crate::maildir::MaildirReader;
use std::path::Path;

/// Index a parsed email into SQLite + FTS5.
pub fn index_email(
    conn: &Connection,
    account: &str,
    folder: &str,
    uid: u32,
    maildir_path: &str,
    email: &ParsedEmail,
) -> Result<()> {
    // Check for duplicate by message_id
    let exists: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM email_messages WHERE account = ?1 AND message_id = ?2",
        rusqlite::params![account, email.message_id],
        |row| row.get(0),
    )?;

    if exists {
        tracing::debug!(message_id = %email.message_id, "Skipping duplicate email");
        return Ok(());
    }

    let to_json = serde_json::to_string(&email.to_addresses)?;
    let cc_json = if email.cc_addresses.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&email.cc_addresses)?)
    };
    let refs_json = if email.references.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&email.references)?)
    };
    let now = jiff::Timestamp::now().strftime("%Y-%m-%dT%H:%M:%SZ").to_string();

    conn.execute(
        "INSERT INTO email_messages (
            account, message_id, folder, uid, from_address, from_name,
            to_addresses, cc_addresses, subject, date, in_reply_to,
            references_list, snippet, has_attachment, size_bytes,
            flags, maildir_path, created_at
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
        rusqlite::params![
            account,
            email.message_id,
            folder,
            uid,
            email.from_address,
            email.from_name,
            to_json,
            cc_json,
            email.subject,
            email.date,
            email.in_reply_to,
            refs_json,
            email.snippet,
            email.has_attachment as i32,
            email.size_bytes as i64,
            "[]", // flags JSON
            maildir_path,
            now,
        ],
    ).context("Failed to insert email message")?;

    // Get the rowid for FTS
    let rowid = conn.last_insert_rowid();

    // Insert into FTS5 index
    conn.execute(
        "INSERT INTO email_fts (rowid, subject, from_address, from_name, body_text) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![
            rowid,
            email.subject,
            email.from_address,
            email.from_name.as_deref().unwrap_or(""),
            email.body_text,
        ],
    ).context("Failed to insert into FTS index")?;

    Ok(())
}

/// Search emails using FTS5.
pub fn search_emails(
    conn: &Connection,
    query: &str,
    limit: usize,
) -> Result<Vec<EmailSearchResult>> {
    let mut stmt = conn.prepare(
        "SELECT e.message_id, e.from_address, e.subject, e.date, e.snippet
         FROM email_fts f
         JOIN email_messages e ON e.id = f.rowid
         WHERE email_fts MATCH ?1
         ORDER BY e.date DESC
         LIMIT ?2"
    )?;

    let results = stmt.query_map(rusqlite::params![query, limit as i64], |row| {
        Ok(EmailSearchResult {
            message_id: row.get(0)?,
            from_address: row.get(1)?,
            subject: row.get(2)?,
            date: row.get(3)?,
            snippet: row.get(4)?,
        })
    })?.filter_map(|r| r.ok()).collect();

    Ok(results)
}

#[derive(Debug)]
pub struct EmailSearchResult {
    pub message_id: String,
    pub from_address: String,
    pub subject: String,
    pub date: String,
    pub snippet: Option<String>,
}

/// Get a full email thread by following In-Reply-To and References chains.
pub fn get_thread(conn: &Connection, message_id: &str) -> Result<Vec<ThreadMessage>> {
    // Collect all related message IDs
    let mut seen = std::collections::HashSet::new();
    let mut queue = vec![message_id.to_string()];
    let mut thread_messages = Vec::new();

    while let Some(mid) = queue.pop() {
        if !seen.insert(mid.clone()) {
            continue;
        }

        // Find this message
        let msg = conn.query_row(
            "SELECT id, message_id, from_address, from_name, to_addresses, subject, date, snippet, in_reply_to, references_list
             FROM email_messages WHERE message_id = ?1",
            [&mid],
            |row| {
                Ok(ThreadMessage {
                    id: row.get(0)?,
                    message_id: row.get(1)?,
                    from_address: row.get(2)?,
                    from_name: row.get(3)?,
                    to_addresses: row.get(4)?,
                    subject: row.get(5)?,
                    date: row.get(6)?,
                    snippet: row.get(7)?,
                })
            },
        );

        if let Ok(msg) = msg {
            thread_messages.push(msg);
        }

        // Find replies to this message
        let mut stmt = conn.prepare(
            "SELECT message_id FROM email_messages WHERE in_reply_to = ?1"
        )?;
        let replies: Vec<String> = stmt.query_map([&mid], |row| row.get(0))?
            .filter_map(|r| r.ok())
            .collect();
        queue.extend(replies);

        // Find parent via in_reply_to
        let parent: Option<String> = conn.query_row(
            "SELECT in_reply_to FROM email_messages WHERE message_id = ?1",
            [&mid],
            |row| row.get(0),
        ).ok().flatten();
        if let Some(p) = parent {
            queue.push(p);
        }

        // Follow references
        let refs: Option<String> = conn.query_row(
            "SELECT references_list FROM email_messages WHERE message_id = ?1",
            [&mid],
            |row| row.get(0),
        ).ok().flatten();
        if let Some(refs_json) = refs {
            if let Ok(refs_list) = serde_json::from_str::<Vec<String>>(&refs_json) {
                queue.extend(refs_list);
            }
        }
    }

    // Sort by date
    thread_messages.sort_by(|a, b| a.date.cmp(&b.date));
    Ok(thread_messages)
}

#[derive(Debug)]
pub struct ThreadMessage {
    pub id: i64,
    pub message_id: String,
    pub from_address: String,
    pub from_name: Option<String>,
    pub to_addresses: String,
    pub subject: String,
    pub date: String,
    pub snippet: Option<String>,
}

/// Add a local tag to an email (not synced to IMAP).
pub fn add_tag(conn: &Connection, message_id: &str, tag: &str) -> Result<()> {
    let current: Option<String> = conn.query_row(
        "SELECT tags_json FROM email_messages WHERE message_id = ?1",
        [message_id],
        |row| row.get(0),
    ).context("Message not found")?;

    let mut tags: Vec<String> = current
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();

    if !tags.contains(&tag.to_string()) {
        tags.push(tag.to_string());
    }

    let tags_json = serde_json::to_string(&tags)?;
    conn.execute(
        "UPDATE email_messages SET tags_json = ?1 WHERE message_id = ?2",
        rusqlite::params![tags_json, message_id],
    )?;

    Ok(())
}

/// Remove a local tag from an email.
pub fn remove_tag(conn: &Connection, message_id: &str, tag: &str) -> Result<()> {
    let current: Option<String> = conn.query_row(
        "SELECT tags_json FROM email_messages WHERE message_id = ?1",
        [message_id],
        |row| row.get(0),
    ).context("Message not found")?;

    let mut tags: Vec<String> = current
        .and_then(|j| serde_json::from_str(&j).ok())
        .unwrap_or_default();

    tags.retain(|t| t != tag);

    let tags_json = serde_json::to_string(&tags)?;
    conn.execute(
        "UPDATE email_messages SET tags_json = ?1 WHERE message_id = ?2",
        rusqlite::params![tags_json, message_id],
    )?;

    Ok(())
}

/// Extract attachments from an email and save to a directory.
pub fn extract_attachments(
    conn: &Connection,
    mail_dir: &Path,
    message_id: &str,
    output_dir: &Path,
) -> Result<Vec<String>> {
    // Get the maildir_path for this message
    let maildir_path: String = conn.query_row(
        "SELECT maildir_path FROM email_messages WHERE message_id = ?1",
        [message_id],
        |row| row.get(0),
    ).context("Message not found")?;

    // Read the raw message
    let reader = MaildirReader::new(mail_dir);
    let raw = reader.read_message(&maildir_path)?;

    // Parse and extract attachments
    let email = ParsedEmail::parse(&raw)?;

    if email.attachments.is_empty() {
        return Ok(vec![]);
    }

    std::fs::create_dir_all(output_dir)?;
    let mut saved = Vec::new();

    for att in &email.attachments {
        let out_path = output_dir.join(&att.filename);
        std::fs::write(&out_path, &att.data)?;
        saved.push(att.filename.clone());
        tracing::info!(filename = %att.filename, size = att.data.len(), "Extracted attachment");
    }

    Ok(saved)
}

/// Reindex all emails from Maildir, rebuilding the SQLite database.
pub fn reindex_from_maildir(
    conn: &Connection,
    mail_dir: &Path,
) -> Result<usize> {
    let reader = MaildirReader::new(mail_dir);
    let accounts = reader.list_accounts()?;
    let mut count = 0;

    // Clear existing data
    conn.execute("DELETE FROM email_fts", [])?;
    conn.execute("DELETE FROM email_messages", [])?;

    for account in &accounts {
        let folders = reader.list_folders(account)?;
        for folder in &folders {
            let messages = reader.read_folder(account, &folder)?;
            for msg in messages {
                match ParsedEmail::parse(&msg.raw) {
                    Ok(email) => {
                        // Extract UID from filename if possible
                        let uid = extract_uid_from_path(&msg.path);
                        if let Err(e) = index_email(conn, account, &folder, uid, &msg.path, &email) {
                            tracing::warn!(path = %msg.path, error = %e, "Failed to index email during reindex");
                        } else {
                            count += 1;
                        }
                    }
                    Err(e) => {
                        tracing::warn!(path = %msg.path, error = %e, "Failed to parse email during reindex");
                    }
                }
            }
        }
    }

    tracing::info!(count, "Reindexed emails from Maildir");
    Ok(count)
}

fn extract_uid_from_path(path: &str) -> u32 {
    // Filename format: <timestamp>.<uuid>.<uid>:2,<flags>
    path.rsplit('/').next()
        .and_then(|filename| {
            let base = filename.split(':').next()?;
            let parts: Vec<&str> = base.split('.').collect();
            parts.last()?.parse().ok()
        })
        .unwrap_or(0)
}

/// Prune emails older than retention_days.
pub fn prune_old_emails(
    conn: &Connection,
    mail_dir: &Path,
    account: &str,
    retention_days: u32,
) -> Result<usize> {
    if retention_days == 0 {
        return Ok(0); // 0 means keep forever
    }

    let cutoff = jiff::Timestamp::now()
        .checked_sub(jiff::SignedDuration::from_hours(retention_days as i64 * 24))
        .unwrap_or(jiff::Timestamp::now());
    let cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ").to_string();

    // Get paths of messages to delete
    let mut stmt = conn.prepare(
        "SELECT id, maildir_path FROM email_messages WHERE account = ?1 AND date < ?2"
    )?;
    let rows: Vec<(i64, String)> = stmt.query_map(
        rusqlite::params![account, cutoff_str],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?.filter_map(|r| r.ok()).collect();

    let count = rows.len();
    for (id, path) in &rows {
        // Delete from FTS
        let _ = conn.execute("DELETE FROM email_fts WHERE rowid = ?1", [id]);
        // Delete from messages
        let _ = conn.execute("DELETE FROM email_messages WHERE id = ?1", [id]);
        // Delete file from Maildir
        let full_path = mail_dir.join(path);
        let _ = std::fs::remove_file(&full_path);
    }

    if count > 0 {
        tracing::info!(account, count, "Pruned old emails");
    }

    Ok(count)
}
