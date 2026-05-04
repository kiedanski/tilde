use tilde_cli::UpdateCommands;
use tilde_core::config::Config;

pub async fn run_update(config_path: Option<&str>, command: UpdateCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;

    match command {
        UpdateCommands::Check => {
            let current_version = env!("CARGO_PKG_VERSION");
            println!("Current version: {}", current_version);

            let manifest_url = if !config.updates.manifest_mirror.is_empty() {
                println!("Using manifest mirror: {}", config.updates.manifest_mirror);
                config.updates.manifest_mirror.clone()
            } else if !config.updates.manifest_url.is_empty() {
                config.updates.manifest_url.clone()
            } else {
                println!(
                    "No manifest URL configured. Set updates.manifest_url or updates.manifest_mirror in config."
                );
                println!("Update check: no updates available (manifest not configured)");
                return Ok(());
            };

            println!("Checking for updates from: {}", manifest_url);

            let client = reqwest::Client::new();

            // Fetch manifest
            let manifest_text = client
                .get(&manifest_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            // Fetch signature
            let sig_url = format!("{}.minisig", manifest_url);
            let sig_text = client
                .get(&sig_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

            // Verify signature with minisign
            if let Some(ref pubkey_str) = config.updates.public_key {
                let pk = minisign_verify::PublicKey::from_base64(pubkey_str)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign public key: {}", e))?;
                let sig = minisign_verify::Signature::decode(&sig_text)
                    .map_err(|e| anyhow::anyhow!("Invalid minisign signature: {}", e))?;
                pk.verify(manifest_text.as_bytes(), &sig, false)
                    .map_err(|e| {
                        anyhow::anyhow!("Manifest signature verification failed: {}", e)
                    })?;
                println!("Manifest signature verified.");
            } else {
                println!(
                    "Warning: no updates.public_key configured, skipping signature verification"
                );
            }

            // Parse manifest JSON
            let manifest: serde_json::Value = serde_json::from_str(&manifest_text)
                .map_err(|e| anyhow::anyhow!("Invalid manifest JSON: {}", e))?;

            let latest_version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Manifest missing 'version' field"))?;

            println!("Latest version: {}", latest_version);

            if version_is_newer(current_version, latest_version) {
                println!("Update available: {} → {}", current_version, latest_version);
                if let Some(notes) = manifest.get("release_notes").and_then(|v| v.as_str()) {
                    println!("Release notes: {}", notes);
                }
                println!("Run `tilde update download` to fetch the new version.");
            } else {
                println!("You are running the latest version.");
            }
        }
        UpdateCommands::Download => {
            let current_version = env!("CARGO_PKG_VERSION");

            let manifest_url = if !config.updates.manifest_mirror.is_empty() {
                config.updates.manifest_mirror.clone()
            } else if !config.updates.manifest_url.is_empty() {
                config.updates.manifest_url.clone()
            } else {
                anyhow::bail!("No manifest URL configured. Set updates.manifest_url in config.");
            };

            let client = reqwest::Client::new();

            // Fetch and verify manifest
            let manifest_text = client
                .get(&manifest_url)
                .send()
                .await?
                .error_for_status()?
                .text()
                .await?;

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
                    .map_err(|e| {
                        anyhow::anyhow!("Manifest signature verification failed: {}", e)
                    })?;
            }

            let manifest: serde_json::Value = serde_json::from_str(&manifest_text)?;
            let latest_version = manifest
                .get("version")
                .and_then(|v| v.as_str())
                .ok_or_else(|| anyhow::anyhow!("Manifest missing 'version' field"))?;

            if !version_is_newer(current_version, latest_version) {
                println!("Already running latest version ({}).", current_version);
                return Ok(());
            }

            // Determine download URL from manifest
            let arch = std::env::consts::ARCH;
            let download_key = format!("download_{}", arch);
            let download_url = manifest
                .get(&download_key)
                .or_else(|| manifest.get("download_url"))
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("No download URL found in manifest for arch '{}'", arch)
                })?;

            println!(
                "Downloading tilde {} from {}...",
                latest_version, download_url
            );

            let response = client.get(download_url).send().await?.error_for_status()?;
            let bytes = response.bytes().await?;

            // Write to a staging path (do NOT auto-install)
            let data_dir = config.data_dir();
            let staging_path = data_dir.join(format!("tilde-{}", latest_version));
            std::fs::write(&staging_path, &bytes)?;

            // Make executable on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = std::fs::metadata(&staging_path)?.permissions();
                perms.set_mode(0o755);
                std::fs::set_permissions(&staging_path, perms)?;
            }

            println!("Downloaded to: {}", staging_path.display());
            println!("To install: replace the current binary and restart the service.");
            println!("  sudo cp {} $(which tilde)", staging_path.display());
            println!("  sudo systemctl restart tilde");
        }
    }

    Ok(())
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

// --- Private helper functions ---

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
}
