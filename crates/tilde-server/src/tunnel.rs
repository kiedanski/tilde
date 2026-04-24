//! Newt tunnel subprocess manager with log-based diagnostics

use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use tilde_core::config::TunnelConfig;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tracing::{error, info, warn};

/// Observable tunnel health state, shared with the health endpoint.
#[derive(Debug)]
pub struct TunnelStatus {
    /// Whether the tunnel subprocess is currently running
    pub running: AtomicBool,
    /// Whether we've seen a "Tunnel connection ... established" log line
    pub connected: AtomicBool,
    /// Consecutive ping failures (reset to 0 on success/reconnect)
    pub consecutive_ping_failures: AtomicU64,
    /// Total number of times Newt has been (re)started
    pub restart_count: AtomicU64,
    /// Timestamp of last successful connection (unix secs, 0 = never)
    pub last_connected_at: AtomicU64,
}

impl Default for TunnelStatus {
    fn default() -> Self {
        Self {
            running: AtomicBool::new(false),
            connected: AtomicBool::new(false),
            consecutive_ping_failures: AtomicU64::new(0),
            restart_count: AtomicU64::new(0),
            last_connected_at: AtomicU64::new(0),
        }
    }
}

impl TunnelStatus {
    /// Summary string for health endpoint
    pub fn summary(&self) -> &'static str {
        if !self.running.load(Ordering::Relaxed) {
            "stopped"
        } else if self.connected.load(Ordering::Relaxed) {
            let failures = self.consecutive_ping_failures.load(Ordering::Relaxed);
            if failures > 5 {
                "degraded"
            } else {
                "connected"
            }
        } else {
            "connecting"
        }
    }
}

pub type SharedTunnelStatus = Arc<TunnelStatus>;

/// Parse a Newt log line and update tunnel status accordingly.
fn classify_and_log(line: &str, status: &TunnelStatus) {
    // Determine the Newt log level prefix
    let (level, msg) = if let Some(rest) = line.strip_prefix("INFO: ") {
        ("info", rest)
    } else if let Some(rest) = line.strip_prefix("WARN: ") {
        ("warn", rest)
    } else if let Some(rest) = line.strip_prefix("ERROR: ") {
        ("error", rest)
    } else if let Some(rest) = line.strip_prefix("FATAL: ") {
        ("fatal", rest)
    } else {
        ("info", line)
    };

    // Strip the timestamp (format: "2026/04/24 10:11:54 ") to get the message
    let msg_body = if msg.len() > 20 && msg.as_bytes().get(4) == Some(&b'/') {
        msg[20..].trim_start()
    } else {
        msg
    };

    // Classify and update state
    if msg_body.contains("Tunnel connection to server established") {
        status.connected.store(true, Ordering::Relaxed);
        status.consecutive_ping_failures.store(0, Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        status.last_connected_at.store(now, Ordering::Relaxed);
        info!(target: "newt", "Tunnel connected");
    } else if msg_body.contains("Periodic ping failed") {
        if let Some(start) = msg_body.find('(') {
            if let Some(end) = msg_body.find(" consecutive") {
                if let Ok(n) = msg_body[start + 1..end].parse::<u64>() {
                    status.consecutive_ping_failures.store(n, Ordering::Relaxed);
                }
            }
        }
        warn!(target: "newt", consecutive_failures = status.consecutive_ping_failures.load(Ordering::Relaxed), "Ping check failing");
    } else if msg_body.contains("Error connecting to target") {
        status.connected.store(false, Ordering::Relaxed);
        error!(target: "newt", "{}", msg_body);
    } else if msg_body.contains("Failed to connect") {
        status.connected.store(false, Ordering::Relaxed);
        error!(target: "newt", "{}", msg_body);
    } else if msg_body.contains("Exiting") {
        status.connected.store(false, Ordering::Relaxed);
        status.running.store(false, Ordering::Relaxed);
        info!(target: "newt", "Newt exiting");
    } else {
        match level {
            "warn" => warn!(target: "newt", "{}", msg_body),
            "error" | "fatal" => error!(target: "newt", "{}", msg_body),
            _ => info!(target: "newt", "{}", msg_body),
        }
    }
}

/// Spawn and supervise the Newt tunnel process.
/// Returns the shared status handle (for health endpoint) and a JoinHandle.
pub fn spawn_tunnel_supervisor(
    config: TunnelConfig,
) -> (SharedTunnelStatus, tokio::task::JoinHandle<()>) {
    let status = Arc::new(TunnelStatus::default());
    let status_clone = status.clone();

    let handle = tokio::spawn(async move {
        let mut delay = config.restart_delay_seconds;
        let max_delay = config.max_restart_delay_seconds;

        // Resolve secret
        let secret = if !config.secret_env.is_empty() {
            std::env::var(&config.secret_env).unwrap_or_else(|_| {
                warn!(
                    env_var = %config.secret_env,
                    "Tunnel secret env var not set, falling back to inline secret"
                );
                config.secret.clone()
            })
        } else {
            config.secret.clone()
        };

        if secret.is_empty() {
            error!(
                "Tunnel enabled but no secret configured \
                 (set tunnel.secret or tunnel.secret_env)"
            );
            return;
        }
        if config.endpoint.is_empty() {
            error!("Tunnel enabled but no endpoint configured");
            return;
        }
        if config.id.is_empty() {
            error!("Tunnel enabled but no id configured");
            return;
        }

        loop {
            status_clone.restart_count.fetch_add(1, Ordering::Relaxed);
            info!(
                binary = %config.binary,
                endpoint = %config.endpoint,
                id = %config.id,
                restart_count = status_clone.restart_count.load(Ordering::Relaxed),
                "Starting tunnel (newt)..."
            );

            let result = Command::new(&config.binary)
                .arg("--id")
                .arg(&config.id)
                .arg("--secret")
                .arg(&secret)
                .arg("--endpoint")
                .arg(&config.endpoint)
                .arg("--log-level")
                .arg(&config.log_level)
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn();

            match result {
                Ok(mut child) => {
                    status_clone.running.store(true, Ordering::Relaxed);
                    // Reset backoff on successful spawn
                    delay = config.restart_delay_seconds;

                    // Pipe stdout — this is where Newt writes its structured logs
                    if let Some(stdout) = child.stdout.take() {
                        let st = status_clone.clone();
                        tokio::spawn(async move {
                            let reader = BufReader::new(stdout);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                classify_and_log(&line, &st);
                            }
                        });
                    }

                    // Pipe stderr (Newt rarely uses stderr, but capture it)
                    if let Some(stderr) = child.stderr.take() {
                        tokio::spawn(async move {
                            let reader = BufReader::new(stderr);
                            let mut lines = reader.lines();
                            while let Ok(Some(line)) = lines.next_line().await {
                                warn!(target: "newt::stderr", "{}", line);
                            }
                        });
                    }

                    // Wait for exit
                    match child.wait().await {
                        Ok(exit_status) => {
                            warn!(exit_code = ?exit_status.code(), "Tunnel (newt) exited");
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to wait on tunnel process");
                        }
                    }
                    status_clone.running.store(false, Ordering::Relaxed);
                    status_clone.connected.store(false, Ordering::Relaxed);
                }
                Err(e) => {
                    error!(
                        error = %e,
                        binary = %config.binary,
                        "Failed to spawn tunnel (newt)"
                    );
                }
            }

            // Exponential backoff restart
            warn!(delay_seconds = delay, "Restarting tunnel after delay...");
            tokio::time::sleep(std::time::Duration::from_secs(delay)).await;
            delay = (delay * 2).min(max_delay);
        }
    });

    (status, handle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_tunnel_connected() {
        let status = TunnelStatus::default();
        status.running.store(true, Ordering::Relaxed);

        classify_and_log(
            "INFO: 2026/04/24 10:11:54 Tunnel connection to server established successfully!",
            &status,
        );
        assert!(status.connected.load(Ordering::Relaxed));
        assert_eq!(status.consecutive_ping_failures.load(Ordering::Relaxed), 0);
        assert!(status.last_connected_at.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_classify_ping_failure() {
        let status = TunnelStatus::default();
        status.running.store(true, Ordering::Relaxed);
        status.connected.store(true, Ordering::Relaxed);

        classify_and_log(
            "WARN: 2026/04/24 10:12:00 Periodic ping failed (3 consecutive failures)",
            &status,
        );
        assert_eq!(status.consecutive_ping_failures.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_classify_connection_error() {
        let status = TunnelStatus::default();
        status.running.store(true, Ordering::Relaxed);
        status.connected.store(true, Ordering::Relaxed);

        classify_and_log(
            "ERROR: 2026/04/24 10:12:00 Error connecting to target: dial tcp 127.0.0.1:8080",
            &status,
        );
        assert!(!status.connected.load(Ordering::Relaxed));
    }

    #[test]
    fn test_classify_exiting() {
        let status = TunnelStatus::default();
        status.running.store(true, Ordering::Relaxed);
        status.connected.store(true, Ordering::Relaxed);

        classify_and_log("INFO: 2026/04/24 10:12:00 Exiting...", &status);
        assert!(!status.connected.load(Ordering::Relaxed));
        assert!(!status.running.load(Ordering::Relaxed));
    }

    #[test]
    fn test_summary_states() {
        let status = TunnelStatus::default();

        assert_eq!(status.summary(), "stopped");

        status.running.store(true, Ordering::Relaxed);
        assert_eq!(status.summary(), "connecting");

        status.connected.store(true, Ordering::Relaxed);
        assert_eq!(status.summary(), "connected");

        status.consecutive_ping_failures.store(10, Ordering::Relaxed);
        assert_eq!(status.summary(), "degraded");
    }
}
