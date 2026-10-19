//! IMAP client for email fetching via `imap` crate.
//!
//! Supports SSL and plain connections, IDLE for push notifications, poll fallback,
//! UID-based incremental sync, and retry with exponential backoff.
//! Uses sync imap crate with tokio::task::spawn_blocking for async compat.

use anyhow::{Context, Result};
use imap::extensions::idle::{SetReadTimeout, WaitOutcome};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use tilde_core::db::DbPool;
use tracing::{debug, error, info, warn};

/// How long to wait for the TCP connection to the IMAP server.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// How long any one IMAP read or write may block. Without it a server that
/// goes silent mid-command wedges the sync thread for good: in production a
/// cycle sat waiting for the reply to LOGIN for two days. Short under test.
const IO_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 2 } else { 60 });

/// IDLE runs in cycles of this length, so its thread notices a shutdown.
const IDLE_CYCLE: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 30 });

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

    /// Create from tilde-core EmailAccountConfig, resolving env vars.
    pub fn from_config(cfg: &tilde_core::config::EmailAccountConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            imap_host: cfg.imap_host.clone(),
            imap_port: cfg.imap_port,
            username: cfg.resolve_username(),
            password: cfg.resolve_password(),
            use_ssl: cfg.use_ssl,
            idle_enabled: cfg.idle_enabled,
            folders_include: cfg.folders_include.clone(),
            folders_exclude: cfg.folders_exclude.clone(),
            retention_days: cfg.retention_days,
            poll_interval_seconds: cfg.poll_interval_seconds,
        }
    }
}

/// An IMAP transport whose reads all give up after `IO_TIMEOUT`.
///
/// The timeout is set on the socket at connect, but imap's IDLE swaps in its
/// own for the wait and then clears it to "none", after which its handle's
/// drop sends DONE and reads the reply. Here clearing restores `IO_TIMEOUT`
/// instead, so that read and every one after it stay bounded.
struct Bounded<S>(S);

impl<S: Read> Read for Bounded<S> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}

impl<S: Write> Write for Bounded<S> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

/// The TCP socket under a transport, which is where its timeouts live.
trait Socket {
    fn socket(&self) -> &TcpStream;
}

impl Socket for TcpStream {
    fn socket(&self) -> &TcpStream {
        self
    }
}

impl Socket for native_tls::TlsStream<TcpStream> {
    fn socket(&self) -> &TcpStream {
        self.get_ref()
    }
}

impl<S: Socket> SetReadTimeout for Bounded<S> {
    fn set_read_timeout(&mut self, timeout: Option<Duration>) -> imap::Result<()> {
        self.0
            .socket()
            .set_read_timeout(Some(timeout.unwrap_or(IO_TIMEOUT)))
            .map_err(imap::Error::Io)
    }
}

/// Abstraction over SSL and plain IMAP sessions.
enum ImapSession {
    Ssl(imap::Session<Bounded<native_tls::TlsStream<TcpStream>>>),
    Plain(imap::Session<Bounded<TcpStream>>),
}

impl ImapSession {
    fn list(&mut self, reference: Option<&str>, pattern: Option<&str>) -> Result<Vec<String>> {
        let names = match self {
            ImapSession::Ssl(s) => s.list(reference, pattern)?,
            ImapSession::Plain(s) => s.list(reference, pattern)?,
        };
        Ok(names.iter().map(|f| f.name().to_string()).collect())
    }

    fn select(&mut self, folder: &str) -> Result<()> {
        match self {
            ImapSession::Ssl(s) => {
                s.select(folder)?;
            }
            ImapSession::Plain(s) => {
                s.select(folder)?;
            }
        }
        Ok(())
    }

    fn uid_fetch(
        &mut self,
        range: &str,
        query: &str,
    ) -> Result<Vec<(Option<u32>, Option<Vec<u8>>)>> {
        #![allow(clippy::type_complexity)]
        let fetches = match self {
            ImapSession::Ssl(s) => s.uid_fetch(range, query)?,
            ImapSession::Plain(s) => s.uid_fetch(range, query)?,
        };
        Ok(fetches
            .iter()
            .map(|m| (m.uid, m.body().map(|b| b.to_vec())))
            .collect())
    }

    /// IDLE on the selected mailbox for up to `timeout`, reporting whether the
    /// server announced a change meanwhile.
    fn idle_wait(&mut self, timeout: Duration) -> Result<WaitOutcome> {
        let outcome = match self {
            ImapSession::Ssl(s) => s.idle()?.wait_with_timeout(timeout)?,
            ImapSession::Plain(s) => s.idle()?.wait_with_timeout(timeout)?,
        };
        Ok(outcome)
    }

    fn logout(&mut self) -> Result<()> {
        match self {
            ImapSession::Ssl(s) => {
                let _ = s.logout();
            }
            ImapSession::Plain(s) => {
                let _ = s.logout();
            }
        }
        Ok(())
    }
}

/// Connect to IMAP server (SSL or plain) and login.
fn connect_and_login(config: &ImapAccountConfig) -> Result<ImapSession> {
    info!(
        host = %config.imap_host,
        port = config.imap_port,
        username = %config.username,
        ssl = config.use_ssl,
        "Connecting to IMAP server"
    );

    let tcp = connect_tcp(&config.imap_host, config.imap_port)?;

    if config.use_ssl {
        let tls = native_tls::TlsConnector::builder().build()?;
        let stream = match tls.connect(&config.imap_host, tcp) {
            Ok(stream) => stream,
            Err(native_tls::HandshakeError::Failure(e)) => {
                return Err(e).context("IMAP TLS handshake failed");
            }
            // The socket's read timeout ran out mid-handshake.
            Err(native_tls::HandshakeError::WouldBlock(_)) => {
                anyhow::bail!(
                    "IMAP TLS handshake timed out after {}s",
                    IO_TIMEOUT.as_secs()
                );
            }
        };
        let mut client = imap::Client::new(Bounded(stream));
        client
            .read_greeting()
            .context("No greeting from IMAP server")?;

        info!("IMAP SSL connection established");

        let session = client
            .login(&config.username, &config.password)
            .map_err(|e| anyhow::anyhow!("IMAP login failed: {}", e.0))?;

        info!(username = %config.username, "IMAP login successful");
        Ok(ImapSession::Ssl(session))
    } else {
        let mut client = imap::Client::new(Bounded(tcp));
        client
            .read_greeting()
            .context("No greeting from IMAP server")?;

        info!("IMAP plain connection established");

        let session = client
            .login(&config.username, &config.password)
            .map_err(|e| anyhow::anyhow!("IMAP login failed: {}", e.0))?;

        info!(username = %config.username, "IMAP login successful");
        Ok(ImapSession::Plain(session))
    }
}

/// Open a TCP connection to the IMAP server, trying each address the host
/// resolves to, with every later read and write bounded by `IO_TIMEOUT`.
fn connect_tcp(host: &str, port: u16) -> Result<TcpStream> {
    let addrs = (host, port)
        .to_socket_addrs()
        .with_context(|| format!("Failed to resolve IMAP host {host}"))?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT) {
            Ok(tcp) => {
                tcp.set_read_timeout(Some(IO_TIMEOUT))?;
                tcp.set_write_timeout(Some(IO_TIMEOUT))?;
                return Ok(tcp);
            }
            Err(e) => last_error = Some(e),
        }
    }
    match last_error {
        Some(e) => Err(e).context("Failed to connect to IMAP server"),
        None => anyhow::bail!("IMAP host {host} resolved to no addresses"),
    }
}

/// List available folders on the IMAP server.
fn list_folders(session: &mut ImapSession) -> Result<Vec<String>> {
    let names = session.list(None, Some("*"))?;
    info!(count = names.len(), "Listed IMAP folders");
    Ok(names)
}

/// Fetch new messages from a folder using UID-based tracking.
fn fetch_new_messages(
    session: &mut ImapSession,
    folder: &str,
    last_uid: Option<u32>,
) -> Result<Vec<(u32, Vec<u8>)>> {
    session.select(folder)?;

    let uid_range = match last_uid {
        Some(uid) => format!("{}:*", uid + 1),
        None => "1:*".to_string(),
    };

    debug!(folder = %folder, uid_range = %uid_range, "Fetching messages");

    let fetched = session.uid_fetch(&uid_range, "(UID RFC822)")?;

    let mut results = Vec::new();
    for (uid_opt, body_opt) in &fetched {
        if let (Some(uid), Some(body)) = (uid_opt, body_opt) {
            if let Some(last) = last_uid
                && *uid <= last
            {
                continue;
            }
            results.push((*uid, body.clone()));
        }
    }

    info!(folder = %folder, count = results.len(), "Fetched new messages");
    Ok(results)
}

/// Run one sync cycle: connect, list folders, fetch new messages, store.
/// Takes DbPool and only holds a connection briefly for DB operations,
/// releasing it during slow IMAP I/O.
fn sync_cycle(
    config: &ImapAccountConfig,
    db: &DbPool,
    maildir_base: &std::path::Path,
) -> Result<()> {
    let mut session = connect_and_login(config)?;

    let folders = list_folders(&mut session)?;

    for folder in &folders {
        if !config.should_sync_folder(folder) {
            debug!(folder = %folder, "Skipping excluded folder");
            continue;
        }

        // The folder name is whatever the server put in its LIST response. A
        // hostile or compromised server can answer with "/etc/cron.d" or
        // "../../x"; skip those rather than aborting the whole account's sync.
        if let Err(e) = crate::maildir::sanitize_relative_name(folder) {
            warn!(folder = %folder, error = %e, "Skipping IMAP folder with an unsafe name");
            continue;
        }

        // Brief lock to read last UID
        let last_uid = {
            let conn = db.get().unwrap();
            get_last_uid(&conn, &config.name, folder)
        };

        // IMAP fetch — no DB lock held
        let messages = fetch_new_messages(&mut session, folder, last_uid)?;

        if messages.is_empty() {
            continue;
        }

        let mut max_uid = last_uid.unwrap_or(0);

        for (uid, raw) in &messages {
            // Write to Maildir on disk — no DB lock needed
            let writer = crate::MaildirWriter::new(maildir_base)?;
            let _ = writer.write_message(&config.name, folder, *uid, raw)?;

            if *uid > max_uid {
                max_uid = *uid;
            }
        }

        // Brief lock to update last UID
        if max_uid > last_uid.unwrap_or(0) {
            let conn = db.get().unwrap();
            set_last_uid(&conn, &config.name, folder, max_uid)?;
        }

        info!(
            account = %config.name,
            folder = %folder,
            new_messages = messages.len(),
            "Folder sync complete"
        );
    }

    {
        let conn = db.get().unwrap();
        record_sync(&conn, &config.name)?;
    }
    let _ = session.logout();

    Ok(())
}

/// Run the email sync loop for one account (async wrapper).
/// Handles IDLE, polling fallback, and retry with exponential backoff.
/// The `shutdown` token allows graceful termination — the loop returns at once,
/// whether it is mid sync cycle, in IDLE, backing off, or waiting to poll.
/// Callback invoked with (account name, error) once per failure streak.
/// Keeps this crate free of a notification dependency — the server passes a
/// closure that owns the sinks.
pub type SyncFailureCallback = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

pub async fn run_sync_loop(
    config: ImapAccountConfig,
    db: DbPool,
    maildir_base: std::path::PathBuf,
    shutdown: tokio_util::sync::CancellationToken,
    // Called once per failure streak (on the 3rd consecutive error).
    on_repeated_failure: Option<SyncFailureCallback>,
) {
    let mut retry_delay = std::time::Duration::from_secs(5);
    let max_retry_delay = std::time::Duration::from_secs(300);
    let mut consecutive_failures: u32 = 0;
    const FAILURE_NOTIFY_THRESHOLD: u32 = 3;

    loop {
        if shutdown.is_cancelled() {
            info!(account = %config.name, "Shutting down email sync");
            return;
        }
        // Run sync in blocking thread
        let config_clone = config.clone();
        let db_clone = db.clone();
        let maildir_clone = maildir_base.clone();

        // The cycle's IMAP reads block until the server answers, and one that
        // goes silent mid-cycle never does: a cycle once sat in LOGIN for two
        // days, holding every upgrade for the full 10s drain. So on shutdown
        // stop waiting for it, as for IDLE below. Each message is renamed into
        // the Maildir atomically; the worst a cut-off cycle leaves is a folder
        // whose last UID was not yet recorded, re-fetched on the next start.
        let cycle = tokio::task::spawn_blocking(move || {
            sync_cycle(&config_clone, &db_clone, &maildir_clone)
        });
        let result = tokio::select! {
            result = cycle => result,
            _ = shutdown.cancelled() => {
                info!(account = %config.name, "Shutting down email sync");
                return;
            }
        };

        match result {
            Ok(Ok(())) => {
                retry_delay = std::time::Duration::from_secs(5);
                consecutive_failures = 0;
                info!(account = %config.name, "Sync cycle completed successfully");
            }
            Ok(Err(e)) => {
                error!(
                    account = %config.name,
                    error = %e,
                    retry_secs = retry_delay.as_secs(),
                    "IMAP sync error — retrying with exponential backoff"
                );
                consecutive_failures += 1;
                if consecutive_failures == FAILURE_NOTIFY_THRESHOLD
                    && let Some(cb) = &on_repeated_failure
                {
                    cb(&config.name, &e.to_string());
                }
                if wait_or_shutdown(retry_delay, &shutdown).await {
                    return;
                }
                retry_delay = (retry_delay * 2).min(max_retry_delay);
                continue;
            }
            Err(e) => {
                error!(error = %e, "Sync task panicked");
                consecutive_failures += 1;
                if consecutive_failures == FAILURE_NOTIFY_THRESHOLD
                    && let Some(cb) = &on_repeated_failure
                {
                    cb(&config.name, &e.to_string());
                }
                if wait_or_shutdown(retry_delay, &shutdown).await {
                    return;
                }
                retry_delay = (retry_delay * 2).min(max_retry_delay);
                continue;
            }
        }

        // After successful sync: IDLE or poll
        if config.idle_enabled {
            // IMAP IDLE is a blocking TCP read that can't be interrupted, so it
            // runs in 30s cycles on a blocking thread. On shutdown, stop waiting
            // for that thread instead of sitting out the cycle: nothing is
            // written while idling, and it ends with the process. Waiting here
            // made every upgrade re-exec sit out the full 10s drain timeout.
            let config_for_idle = config.clone();
            let shutdown_flag = shutdown.clone();
            let idle = tokio::task::spawn_blocking(move || {
                let mut session = connect_and_login(&config_for_idle)?;
                session.select("INBOX")?;
                info!(
                    cycle_secs = IDLE_CYCLE.as_secs(),
                    "Entering IMAP IDLE mode on INBOX"
                );
                // Idle cycle after cycle until shutdown or a server notification;
                // a notification returns Ok so the loop re-syncs.
                loop {
                    if shutdown_flag.is_cancelled() {
                        break;
                    }
                    if session.idle_wait(IDLE_CYCLE)? == WaitOutcome::MailboxChanged {
                        break;
                    }
                }
                session.logout()?;
                Ok::<_, anyhow::Error>(())
            });
            let idle_result = tokio::select! {
                result = idle => result,
                _ = shutdown.cancelled() => {
                    info!(account = %config.name, "Shutting down email sync");
                    return;
                }
            };

            match idle_result {
                Ok(Ok(())) => {
                    if shutdown.is_cancelled() {
                        return;
                    }
                    info!(account = %config.name, "IDLE notification — re-syncing");
                }
                Ok(Err(e)) => {
                    warn!(error = %e, "IDLE error — will retry");
                    if wait_or_shutdown(retry_delay, &shutdown).await {
                        return;
                    }
                    retry_delay = (retry_delay * 2).min(max_retry_delay);
                }
                Err(e) => {
                    error!(error = %e, "IDLE task panicked");
                    if wait_or_shutdown(retry_delay, &shutdown).await {
                        return;
                    }
                }
            }
        } else {
            info!(
                account = %config.name,
                interval_secs = config.poll_interval_seconds,
                "IDLE disabled — polling fallback"
            );
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(std::time::Duration::from_secs(config.poll_interval_seconds)) => {},
            }
        }
    }
}

/// Sleep for `delay`, returning `true` early if `shutdown` is cancelled first.
async fn wait_or_shutdown(
    delay: std::time::Duration,
    shutdown: &tokio_util::sync::CancellationToken,
) -> bool {
    tokio::select! {
        _ = shutdown.cancelled() => true,
        _ = tokio::time::sleep(delay) => false,
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

    /// Shutdown must cut a back-off short: the server's drain waits for this
    /// loop, and the first retry delay alone is 5s.
    #[tokio::test]
    async fn shutdown_interrupts_retry_backoff() {
        let dir = std::env::temp_dir().join(format!("tilde-imap-backoff-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = tilde_core::db::init_pool(dir.join("t.db").to_str().unwrap()).unwrap();
        // Nothing listens on port 1, so every sync cycle fails at connect.
        let config = ImapAccountConfig {
            imap_host: "127.0.0.1".into(),
            imap_port: 1,
            use_ssl: false,
            ..Default::default()
        };
        let shutdown = tokio_util::sync::CancellationToken::new();
        let sync = tokio::spawn(run_sync_loop(
            config,
            db,
            dir.join("mail"),
            shutdown.clone(),
            None,
        ));
        // Well inside the first 5s back-off by now.
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(1), sync)
            .await
            .expect("sync loop sat out its back-off after shutdown")
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Shutdown must not wait on a sync cycle either. A server that accepts
    /// the connection and then goes silent leaves the cycle's thread blocked
    /// on a read for good: in production one sat in LOGIN for two days, and
    /// the upgrade drain then waited out its full 10s on it.
    #[tokio::test]
    async fn shutdown_abandons_a_stalled_sync_cycle() {
        let dir = std::env::temp_dir().join(format!("tilde-imap-stalled-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = tilde_core::db::init_pool(dir.join("t.db").to_str().unwrap()).unwrap();
        // Accepts the connection, then never says a word.
        let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let config = ImapAccountConfig {
            imap_host: "127.0.0.1".into(),
            imap_port: server.local_addr().unwrap().port(),
            use_ssl: false,
            ..Default::default()
        };
        let shutdown = tokio_util::sync::CancellationToken::new();
        let sync = tokio::spawn(run_sync_loop(
            config,
            db,
            dir.join("mail"),
            shutdown.clone(),
            None,
        ));
        // Once accepted, the cycle is waiting for a reply that never comes.
        let (silent, _) = tokio::task::spawn_blocking(move || server.accept())
            .await
            .unwrap()
            .unwrap();
        shutdown.cancel();
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), sync).await;
        // Hang up so the abandoned thread ends and the test runtime can stop.
        drop(silent);
        result
            .expect("sync loop waited on a stalled sync cycle after shutdown")
            .unwrap();
        std::fs::remove_dir_all(&dir).ok();
    }

    const GREETING: &[u8] = b"* OK [CAPABILITY IMAP4rev1 IDLE] fake ready\r\n";

    /// What the fake server does once it has accepted an IDLE.
    #[derive(Clone, Copy)]
    enum OnIdle {
        /// Say nothing until the client sends DONE.
        Quiet,
        /// Announce a new message.
        NewMail,
        /// Announce a new message, then never answer again.
        NewMailThenSilence,
    }

    /// A local IMAP server with one empty INBOX. `on_idle(n)` picks how it
    /// answers the n-th IDLE (from 0) on a connection. Every command it gets
    /// is reported as (connection number, verb).
    fn fake_imap(
        on_idle: fn(usize) -> OnIdle,
    ) -> (u16, std::sync::mpsc::Receiver<(usize, String)>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let (events, received) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for (conn, stream) in listener.incoming().enumerate() {
                let Ok(stream) = stream else { return };
                let events = events.clone();
                std::thread::spawn(move || serve_fake_imap(conn, stream, on_idle, events));
            }
        });
        (port, received)
    }

    fn serve_fake_imap(
        conn: usize,
        stream: TcpStream,
        on_idle: fn(usize) -> OnIdle,
        events: std::sync::mpsc::Sender<(usize, String)>,
    ) {
        use std::io::BufRead;
        let mut out = stream.try_clone().unwrap();
        let mut lines = std::io::BufReader::new(stream).lines();
        let mut idles = 0;
        out.write_all(GREETING).unwrap();
        while let Some(Ok(line)) = lines.next() {
            let (tag, command) = line.split_once(' ').unwrap_or((line.as_str(), ""));
            let verb = command.split(' ').next().unwrap_or("").to_ascii_uppercase();
            let _ = events.send((conn, verb.clone()));
            let reply = match verb.as_str() {
                "LIST" => format!("* LIST (\\HasNoChildren) \"/\" INBOX\r\n{tag} OK LIST done\r\n"),
                "SELECT" => format!(
                    "* 0 EXISTS\r\n* OK [UIDVALIDITY 1] ok\r\n{tag} OK [READ-WRITE] SELECT done\r\n"
                ),
                "IDLE" => {
                    let mode = on_idle(idles);
                    idles += 1;
                    out.write_all(b"+ idling\r\n").unwrap();
                    if !matches!(mode, OnIdle::Quiet) {
                        out.write_all(b"* 1 EXISTS\r\n").unwrap();
                    }
                    let Some(Ok(done)) = lines.next() else { return };
                    let _ = events.send((conn, done.to_ascii_uppercase()));
                    if matches!(mode, OnIdle::NewMailThenSilence) {
                        // Keep the connection open, and never say another word.
                        for _ in lines.by_ref() {}
                        return;
                    }
                    format!("{tag} OK IDLE done\r\n")
                }
                "LOGOUT" => {
                    let _ = out.write_all(format!("* BYE\r\n{tag} OK LOGOUT done\r\n").as_bytes());
                    return;
                }
                // LOGIN, and a UID FETCH that finds nothing.
                _ => format!("{tag} OK done\r\n"),
            };
            if out.write_all(reply.as_bytes()).is_err() {
                return;
            }
        }
    }

    /// A server that goes silent must fail the connection within `IO_TIMEOUT`
    /// rather than wedge the sync thread. In production a cycle sat waiting on
    /// LOGIN for two days, and email sync was dead the whole time.
    #[test]
    fn a_silent_server_times_out_instead_of_hanging() {
        // (TLS, sends a greeting): silent from the start, as in a stalled TLS
        // handshake or a missing greeting, and silent from LOGIN on.
        for (use_ssl, greet) in [(false, false), (false, true), (true, false)] {
            let server = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            let config = ImapAccountConfig {
                imap_host: "127.0.0.1".into(),
                imap_port: server.local_addr().unwrap().port(),
                use_ssl,
                ..Default::default()
            };
            let (done, result) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let _ = done.send(connect_and_login(&config).map(|_| ()));
            });
            let (mut silent, _) = server.accept().unwrap();
            if greet {
                silent.write_all(GREETING).unwrap();
            }
            let result = result.recv_timeout(IO_TIMEOUT * 3).unwrap_or_else(|_| {
                panic!("connect hung on a silent server (ssl={use_ssl}, greeting={greet})")
            });
            assert!(
                result.is_err(),
                "a silent server cannot log us in (ssl={use_ssl}, greeting={greet})"
            );
        }
    }

    /// imap's IDLE clears the socket's read timeout once its wait ends, and
    /// its handle's drop then sends DONE and reads the reply. A server that
    /// announces mail and then goes silent must not hang that read.
    #[test]
    fn idle_stays_bounded_after_a_notification() {
        let (port, _events) = fake_imap(|_| OnIdle::NewMailThenSilence);
        let config = ImapAccountConfig {
            imap_host: "127.0.0.1".into(),
            imap_port: port,
            use_ssl: false,
            ..Default::default()
        };
        let (done, result) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let outcome = connect_and_login(&config).and_then(|mut session| {
                session.select("INBOX")?;
                session.idle_wait(IDLE_CYCLE)
            });
            let _ = done.send(outcome);
        });
        let outcome = result
            .recv_timeout(IO_TIMEOUT * 3)
            .expect("IDLE hung waiting for the reply to DONE")
            .unwrap();
        assert_eq!(outcome, WaitOutcome::MailboxChanged);
    }

    /// New mail announced during IDLE must end the IDLE and re-sync. The
    /// outcome used to be thrown away, so mail only arrived at boot or after
    /// an IDLE error. An IDLE cycle that just times out keeps idling instead,
    /// on the same connection.
    #[tokio::test]
    async fn new_mail_during_idle_triggers_a_resync() {
        let dir = std::env::temp_dir().join(format!("tilde-imap-resync-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = tilde_core::db::init_pool(dir.join("t.db").to_str().unwrap()).unwrap();
        // A cycle has to complete for the loop to go on to IDLE.
        tilde_core::db::run_embedded_migrations(&db.get().unwrap()).unwrap();
        // Quiet for the first IDLE cycle on a connection, new mail in the next.
        let (port, events) = fake_imap(|nth| {
            if nth == 0 {
                OnIdle::Quiet
            } else {
                OnIdle::NewMail
            }
        });
        let config = ImapAccountConfig {
            imap_host: "127.0.0.1".into(),
            imap_port: port,
            use_ssl: false,
            idle_enabled: true,
            ..Default::default()
        };
        let shutdown = tokio_util::sync::CancellationToken::new();
        let sync = tokio::spawn(run_sync_loop(
            config,
            db,
            dir.join("mail"),
            shutdown.clone(),
            None,
        ));

        // Connection 0 syncs, 1 idles, and 2 must be the re-sync.
        let seen = tokio::task::spawn_blocking(move || {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
            let mut seen = Vec::new();
            while let Ok(event) =
                events.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()))
            {
                let resynced = event == (2, "LIST".to_string());
                seen.push(event);
                if resynced {
                    break;
                }
            }
            seen
        })
        .await
        .unwrap();
        shutdown.cancel();
        sync.await.unwrap();
        std::fs::remove_dir_all(&dir).ok();

        let on = |conn: usize| -> Vec<&str> {
            seen.iter()
                .filter(|(c, _)| *c == conn)
                .map(|(_, verb)| verb.as_str())
                .collect()
        };
        assert_eq!(
            on(1),
            ["LOGIN", "SELECT", "IDLE", "DONE", "IDLE", "DONE", "LOGOUT"],
            "a timed-out IDLE cycle re-idles; new mail ends the IDLE"
        );
        assert!(
            on(2).contains(&"LIST"),
            "new mail during IDLE never triggered a re-sync: {seen:?}"
        );
    }

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
    fn test_hostile_list_folder_names_are_not_path_safe() {
        // The default filter only excludes Trash/Spam by name, so containment
        // has to come from the Maildir layer, not from here. This pins that
        // split: `should_sync_folder` lets these through on purpose, and
        // `sanitize_relative_name` is what stops them.
        let config = ImapAccountConfig::default();
        for hostile in ["/etc/cron.d", "../../etc", "INBOX/../../../etc"] {
            assert!(
                config.should_sync_folder(hostile),
                "the name filter is not a security control for {:?}",
                hostile
            );
            assert!(
                crate::maildir::sanitize_relative_name(hostile).is_err(),
                "{:?} must be refused before it reaches the filesystem",
                hostile
            );
        }
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
