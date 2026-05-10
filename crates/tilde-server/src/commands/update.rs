use std::path::PathBuf;
use tilde_cli::UpdateCommands;
use tilde_core::config::Config;

pub async fn run_update(config_path: Option<&str>, command: UpdateCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;

    match command {
        UpdateCommands::Check => {
            let current_version = env!("CARGO_PKG_VERSION");
            println!("Current version: {}", current_version);

            let info = check_latest(&config).await?;
            println!("Latest version: {}", info.version);

            if version_is_newer(current_version, &info.version) {
                println!("Update available: {} → {}", current_version, info.version);
                println!("Run `tilde update apply` to upgrade in-place.");
            } else {
                println!("You are running the latest version.");
            }
        }
        UpdateCommands::Download => {
            let staging_path = download_latest(&config).await?;
            println!("Downloaded to: {}", staging_path.display());
            println!("To install manually:");
            println!("  sudo cp {} $(which tilde)", staging_path.display());
            println!("  sudo systemctl restart tilde");
        }
        UpdateCommands::Apply => {
            let current_version = env!("CARGO_PKG_VERSION");
            println!("Current version: {}", current_version);

            // Download new binary
            let staging_path = download_latest(&config).await?;

            // Validate the new binary
            println!("Validating new binary...");
            let output = std::process::Command::new(&staging_path)
                .arg("--version")
                .output();
            match output {
                Ok(o) if o.status.success() => {
                    let version_out = String::from_utf8_lossy(&o.stdout);
                    println!("New binary: {}", version_out.trim());
                }
                Ok(o) => {
                    let _ = std::fs::remove_file(&staging_path);
                    anyhow::bail!(
                        "New binary failed validation (exit {})",
                        o.status.code().unwrap_or(-1)
                    );
                }
                Err(e) => {
                    let _ = std::fs::remove_file(&staging_path);
                    anyhow::bail!("New binary is not executable: {}", e);
                }
            }

            // Atomic replace: rename staging binary over current exe
            let current_exe = std::env::current_exe()?;
            println!(
                "Replacing {} → {}",
                staging_path.display(),
                current_exe.display()
            );
            atomic_replace(&staging_path, &current_exe)?;
            println!("Binary replaced successfully.");

            // Signal the running server to re-exec
            match find_server_pid() {
                Some(pid) => {
                    println!("Sending upgrade signal to tilde server (PID {})...", pid);
                    #[cfg(unix)]
                    {
                        let ret = unsafe { libc::kill(pid, libc::SIGUSR2) };
                        if ret != 0 {
                            let err = std::io::Error::last_os_error();
                            anyhow::bail!("Failed to send SIGUSR2 to PID {}: {}", pid, err);
                        }
                    }
                    println!("Server will re-exec with the new binary. Check logs:");
                    println!("  journalctl -u tilde -f");
                }
                None => {
                    println!("No running tilde server found.");
                    println!("Start it with: sudo systemctl start tilde");
                }
            }
        }
    }

    Ok(())
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Resolved update info: version + download URL.
struct UpdateInfo {
    version: String,
    download_url: String,
}

/// Check for the latest version, trying manifest first, then GitHub Releases.
async fn check_latest(config: &Config) -> anyhow::Result<UpdateInfo> {
    // Try manifest-based update if configured
    if !config.updates.manifest_mirror.is_empty() || !config.updates.manifest_url.is_empty() {
        return check_latest_manifest(config).await;
    }

    // Fall back to GitHub Releases
    if !config.updates.github_repo.is_empty() {
        return check_latest_github(&config.updates.github_repo).await;
    }

    anyhow::bail!("No update source configured. Set updates.github_repo or updates.manifest_url.")
}

/// Check latest version from a signed manifest.
async fn check_latest_manifest(config: &Config) -> anyhow::Result<UpdateInfo> {
    let manifest_url = if !config.updates.manifest_mirror.is_empty() {
        println!("Using manifest mirror: {}", config.updates.manifest_mirror);
        config.updates.manifest_mirror.clone()
    } else {
        config.updates.manifest_url.clone()
    };

    println!("Checking for updates from: {}", manifest_url);
    let client = reqwest::Client::new();

    let manifest_text = client
        .get(&manifest_url)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;

    // Verify signature if public key is configured
    if let Some(ref pubkey_str) = config.updates.public_key {
        let sig_url = format!("{}.minisig", manifest_url);
        let sig_text = client
            .get(&sig_url)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;
        let pk = minisign_verify::PublicKey::from_base64(pubkey_str)
            .map_err(|e| anyhow::anyhow!("Invalid minisign public key: {}", e))?;
        let sig = minisign_verify::Signature::decode(&sig_text)
            .map_err(|e| anyhow::anyhow!("Invalid minisign signature: {}", e))?;
        pk.verify(manifest_text.as_bytes(), &sig, false)
            .map_err(|e| anyhow::anyhow!("Manifest signature verification failed: {}", e))?;
        println!("Manifest signature verified.");
    }

    let manifest: serde_json::Value = serde_json::from_str(&manifest_text)?;
    let version = manifest
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Manifest missing 'version' field"))?
        .to_string();

    let arch = std::env::consts::ARCH;
    let download_key = format!("download_{}", arch);
    let download_url = manifest
        .get(&download_key)
        .or_else(|| manifest.get("download_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("No download URL for arch '{}'", arch))?
        .to_string();

    Ok(UpdateInfo {
        version,
        download_url,
    })
}

/// Check latest version from GitHub Releases API.
async fn check_latest_github(repo: &str) -> anyhow::Result<UpdateInfo> {
    let api_url = format!("https://api.github.com/repos/{}/releases/latest", repo);
    println!("Checking GitHub releases: {}", repo);

    let client = reqwest::Client::builder()
        .user_agent("tilde-updater")
        .build()?;

    let response = client.get(&api_url).send().await?;
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        anyhow::bail!(
            "No releases found for {}. Create one by pushing a tag: git tag v0.1.1 && git push --tags",
            repo
        );
    }
    let release: serde_json::Value = response.error_for_status()?.json().await?;

    let tag = release
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("Release missing tag_name"))?;
    // Strip leading 'v' from tag to get semver
    let version = tag.strip_prefix('v').unwrap_or(tag).to_string();

    // Find the asset matching our architecture
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;
    let asset_name = format!("tilde-{}-{}", os, arch);

    let assets = release
        .get("assets")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("Release has no assets"))?;

    let download_url = assets
        .iter()
        .find(|a| {
            a.get("name")
                .and_then(|n| n.as_str())
                .map_or(false, |n| n == asset_name)
        })
        .and_then(|a| a.get("browser_download_url"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            let available: Vec<&str> = assets
                .iter()
                .filter_map(|a| a.get("name").and_then(|n| n.as_str()))
                .collect();
            anyhow::anyhow!(
                "No asset '{}' in release. Available: {:?}",
                asset_name,
                available
            )
        })?
        .to_string();

    Ok(UpdateInfo {
        version,
        download_url,
    })
}

/// Download the latest binary to a staging path. Returns the staging path.
async fn download_latest(config: &Config) -> anyhow::Result<PathBuf> {
    let current_version = env!("CARGO_PKG_VERSION");
    let info = check_latest(config).await?;

    if !version_is_newer(current_version, &info.version) {
        anyhow::bail!("Already running latest version ({}).", current_version);
    }

    println!(
        "Downloading tilde {} from {}...",
        info.version, info.download_url
    );

    let client = reqwest::Client::builder()
        .user_agent("tilde-updater")
        .build()?;
    let response = client
        .get(&info.download_url)
        .send()
        .await?
        .error_for_status()?;
    let bytes = response.bytes().await?;

    let data_dir = config.data_dir();
    let staging_path = data_dir.join(format!("tilde-{}", info.version));
    std::fs::write(&staging_path, &bytes)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&staging_path)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&staging_path, perms)?;
    }

    Ok(staging_path)
}

/// Atomically replace `dst` with `src`.
///
/// Tries `rename` first (instant, same filesystem). Falls back to
/// copy-to-temp + rename for cross-filesystem moves.
fn atomic_replace(src: &PathBuf, dst: &PathBuf) -> anyhow::Result<()> {
    // Try direct rename (only works on same filesystem)
    if std::fs::rename(src, dst).is_ok() {
        return Ok(());
    }

    // Cross-filesystem: copy src next to dst, then rename
    let tmp = dst.with_extension("new");
    std::fs::copy(src, &tmp)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tmp, perms)?;
    }

    std::fs::rename(&tmp, dst).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        anyhow::anyhow!("Failed to rename into place: {}", e)
    })?;

    let _ = std::fs::remove_file(src);
    Ok(())
}

/// Find the PID of a running `tilde serve` process.
fn find_server_pid() -> Option<i32> {
    // Try systemd first
    if let Ok(output) = std::process::Command::new("systemctl")
        .args(["show", "tilde", "-p", "MainPID", "--value"])
        .output()
    {
        if output.status.success() {
            let pid_str = String::from_utf8_lossy(&output.stdout);
            if let Ok(pid) = pid_str.trim().parse::<i32>() {
                if pid > 0 {
                    return Some(pid);
                }
            }
        }
    }

    // Fallback: pgrep
    if let Ok(output) = std::process::Command::new("pgrep")
        .args(["-f", "tilde serve"])
        .output()
    {
        if output.status.success() {
            let pid_str = String::from_utf8_lossy(&output.stdout);
            // Take the first PID (skip our own process)
            let my_pid = std::process::id();
            for line in pid_str.lines() {
                if let Ok(pid) = line.trim().parse::<i32>() {
                    if pid > 0 && pid as u32 != my_pid {
                        return Some(pid);
                    }
                }
            }
        }
    }

    None
}

/// Compare two semver-like version strings. Returns true if `latest` is newer than `current`.
fn version_is_newer(current: &str, latest: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> { v.split('.').filter_map(|s| s.parse().ok()).collect() };
    let c = parse(current);
    let l = parse(latest);
    l > c
}

fn nix_is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(unix))]
    {
        false
    }
}

pub async fn run_install() -> anyhow::Result<()> {
    let unit_path = std::path::Path::new("/etc/systemd/system/tilde.service");

    // Check for root/sudo
    if !nix_is_root() {
        anyhow::bail!("tilde install must be run as root (use sudo tilde install)");
    }

    // Find the binary path
    let binary_path =
        std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("/usr/bin/tilde"));
    let binary_str = binary_path.to_str().unwrap_or("/usr/bin/tilde");

    let unit_content = generate_systemd_unit(binary_str);

    if unit_path.exists() {
        let existing = std::fs::read_to_string(unit_path)?;
        if existing == unit_content {
            println!(
                "[OK] systemd unit file already up-to-date at {}",
                unit_path.display()
            );
            return Ok(());
        }
        println!(
            "[INFO] Updating existing systemd unit file at {}",
            unit_path.display()
        );
    }

    // Write the unit file
    std::fs::write(unit_path, &unit_content)?;
    println!("[OK] systemd unit file written to {}", unit_path.display());

    // Create system user if it doesn't exist
    let user_exists = std::process::Command::new("id")
        .arg("tilde")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !user_exists {
        let status = std::process::Command::new("useradd")
            .args([
                "--system",
                "--home-dir",
                "/var/lib/tilde",
                "--shell",
                "/usr/sbin/nologin",
                "--user-group",
                "tilde",
            ])
            .status();
        match status {
            Ok(s) if s.success() => println!("[OK] Created system user 'tilde'"),
            _ => println!("[WARN] Could not create system user 'tilde' — create it manually"),
        }
    } else {
        println!("[OK] System user 'tilde' already exists");
    }

    // Reload systemd
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .status();
    println!("[OK] systemd daemon reloaded");

    println!();
    println!("Next steps:");
    println!("  sudo systemctl enable --now tilde    — Enable and start tilde");
    println!("  sudo systemctl status tilde          — Check service status");
    println!("  journalctl -u tilde -f               — Follow logs");

    Ok(())
}

fn generate_systemd_unit(binary_path: &str) -> String {
    format!(
        r#"[Unit]
Description=tilde Personal Cloud Server
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart={binary_path} serve
User=tilde
Group=tilde
StateDirectory=tilde
CacheDirectory=tilde
ConfigurationDirectory=tilde
RuntimeDirectory=tilde
LogsDirectory=tilde

# Watchdog
WatchdogSec=30s

# Resource limits
MemoryHigh=256M
MemoryMax=512M

# Bind to privileged port
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Full hardening stanza
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
NoNewPrivileges=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
ReadWritePaths=/var/lib/tilde /var/cache/tilde

[Install]
WantedBy=multi-user.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_systemd_unit_contains_required_fields() {
        let unit = generate_systemd_unit("/usr/bin/tilde");
        assert!(unit.contains("Type=notify"));
        assert!(unit.contains("WatchdogSec=30s"));
        assert!(unit.contains("ExecStart=/usr/bin/tilde serve"));
        assert!(unit.contains("User=tilde"));
        assert!(unit.contains("Group=tilde"));
        assert!(unit.contains("StateDirectory=tilde"));
        assert!(unit.contains("ProtectSystem=strict"));
        assert!(unit.contains("ProtectHome=yes"));
        assert!(unit.contains("NoNewPrivileges=yes"));
        assert!(unit.contains("MemoryHigh=256M"));
        assert!(unit.contains("MemoryMax=512M"));
        assert!(unit.contains("AmbientCapabilities=CAP_NET_BIND_SERVICE"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("WantedBy=multi-user.target"));
    }

    #[test]
    fn test_systemd_unit_idempotent() {
        let unit1 = generate_systemd_unit("/usr/bin/tilde");
        let unit2 = generate_systemd_unit("/usr/bin/tilde");
        assert_eq!(unit1, unit2);
    }

    #[test]
    fn test_version_is_newer() {
        assert!(version_is_newer("0.1.0", "0.2.0"));
        assert!(version_is_newer("0.1.0", "1.0.0"));
        assert!(version_is_newer("0.1.0", "0.1.1"));
        assert!(!version_is_newer("0.2.0", "0.1.0"));
        assert!(!version_is_newer("0.1.0", "0.1.0"));
    }
}
