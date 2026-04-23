//! Configuration loading via figment (TOML + env + CLI)

use figment::{
    Figment,
    providers::{Env, Format, Serialized, Toml},
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tracing::info;

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub files: FilesConfig,
    #[serde(default)]
    pub photos: PhotosConfig,
    #[serde(default)]
    pub notes: NotesConfig,
    #[serde(default)]
    pub mcp: McpConfig,
    #[serde(default)]
    pub updates: UpdatesConfig,
    #[serde(default)]
    pub backup: BackupConfig,
}

impl Config {
    /// Load configuration with layered priority: defaults < TOML file < env vars
    pub fn load(config_path: Option<&str>) -> anyhow::Result<Self> {
        let mut figment = Figment::from(Serialized::defaults(Config::default()));

        // Layer TOML file if provided or found at default locations
        if let Some(path) = config_path {
            if Path::new(path).exists() {
                figment = figment.merge(Toml::file(path));
                info!(path = path, "Loaded config from explicit path");
            }
        } else {
            // Try default locations
            for candidate in Self::default_config_paths() {
                if candidate.exists() {
                    figment = figment.merge(Toml::file(&candidate));
                    info!(path = %candidate.display(), "Loaded config from default path");
                    break;
                }
            }
        }

        // Layer env vars: supports both flat (TILDE_HOSTNAME) and nested (TILDE_SERVER__LISTEN_PORT)
        figment = figment.merge(Env::prefixed("TILDE_").map(|key| {
            let key_lower = key.as_str().to_ascii_lowercase();
            match key_lower.as_str() {
                "hostname" => "server.hostname".into(),
                "acme_email" => "tls.acme_email".into(),
                "admin_password" => "auth.admin_password".into(),
                _ => key_lower.replace("__", ".").into(),
            }
        }));

        let config: Config = figment.extract()?;
        Ok(config)
    }

    /// Resolve data directory based on mode (systemd vs user)
    pub fn data_dir(&self) -> PathBuf {
        if let Ok(state_dir) = std::env::var("STATE_DIRECTORY") {
            PathBuf::from(state_dir)
        } else if let Ok(dir) = std::env::var("TILDE_DATA_DIR") {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            PathBuf::from(xdg).join("tilde")
        } else if let Some(data_dir) =
            directories::ProjectDirs::from("", "", "tilde").map(|d| d.data_dir().to_path_buf())
        {
            data_dir
        } else {
            PathBuf::from(".dev-data")
        }
    }

    /// Resolve cache directory
    pub fn cache_dir(&self) -> PathBuf {
        if let Ok(cache_dir) = std::env::var("CACHE_DIRECTORY") {
            PathBuf::from(cache_dir)
        } else if Self::is_systemd_mode() {
            PathBuf::from("/var/cache/tilde")
        } else if let Ok(dir) = std::env::var("TILDE_CACHE_DIR") {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            PathBuf::from(xdg).join("tilde")
        } else if let Some(cache_dir) =
            directories::ProjectDirs::from("", "", "tilde").map(|d| d.cache_dir().to_path_buf())
        {
            cache_dir
        } else {
            PathBuf::from(".dev-cache")
        }
    }

    /// Resolve config directory
    pub fn config_dir() -> PathBuf {
        if std::env::var("STATE_DIRECTORY").is_ok() {
            PathBuf::from("/etc/tilde")
        } else if let Ok(dir) = std::env::var("TILDE_CONFIG_DIR") {
            PathBuf::from(dir)
        } else if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            PathBuf::from(xdg).join("tilde")
        } else if let Some(config_dir) =
            directories::ProjectDirs::from("", "", "tilde").map(|d| d.config_dir().to_path_buf())
        {
            config_dir
        } else {
            PathBuf::from(".")
        }
    }

    /// Database file path
    pub fn db_path(&self) -> PathBuf {
        self.data_dir().join("tilde.db")
    }

    /// Whether running in systemd mode
    pub fn is_systemd_mode() -> bool {
        std::env::var("STATE_DIRECTORY").is_ok()
    }

    fn default_config_paths() -> Vec<PathBuf> {
        let mut paths = Vec::new();

        // Systemd mode
        if Self::is_systemd_mode() {
            paths.push(PathBuf::from("/etc/tilde/config.toml"));
        }

        // Explicit TILDE_CONFIG_DIR
        if let Ok(dir) = std::env::var("TILDE_CONFIG_DIR") {
            paths.push(PathBuf::from(dir).join("config.toml"));
        }

        // XDG config
        if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
            paths.push(PathBuf::from(xdg).join("tilde").join("config.toml"));
        }

        // directories crate fallback
        if let Some(proj_dirs) = directories::ProjectDirs::from("", "", "tilde") {
            paths.push(proj_dirs.config_dir().join("config.toml"));
        }

        // Current directory fallback
        paths.push(PathBuf::from("config.toml"));

        paths
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    #[serde(default)]
    pub hostname: String,
    #[serde(default = "default_listen_addr")]
    pub listen_addr: String,
    #[serde(default = "default_listen_port")]
    pub listen_port: u16,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            hostname: String::new(),
            listen_addr: default_listen_addr(),
            listen_port: default_listen_port(),
            trusted_proxies: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TlsConfig {
    #[serde(default = "default_tls_mode")]
    pub mode: String,
    #[serde(default)]
    pub acme_email: String,
    #[serde(default)]
    pub cert_path: String,
    #[serde(default)]
    pub key_path: String,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            mode: default_tls_mode(),
            acme_email: String::new(),
            cert_path: String::new(),
            key_path: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    #[serde(default = "default_session_ttl")]
    pub session_ttl_hours: u32,
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration_minutes: u32,
    #[serde(default)]
    pub admin_password: String,
    #[serde(default)]
    pub webauthn_enabled: bool,
    #[serde(default)]
    pub webauthn_rp_id: String,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: default_session_ttl(),
            max_login_attempts: default_max_login_attempts(),
            lockout_duration_minutes: default_lockout_duration(),
            admin_password: String::new(),
            webauthn_enabled: false,
            webauthn_rp_id: String::new(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default = "default_log_format")]
    pub format: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            format: default_log_format(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FilesConfig {
    #[serde(default = "default_max_upload_size")]
    pub max_upload_size_mb: u64,
    #[serde(default = "default_chunked_ttl")]
    pub chunked_upload_session_ttl_hours: u32,
}

impl Default for FilesConfig {
    fn default() -> Self {
        Self {
            max_upload_size_mb: default_max_upload_size(),
            chunked_upload_session_ttl_hours: default_chunked_ttl(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PhotosConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_org_pattern")]
    pub organization_pattern: String,
    #[serde(default = "default_thumbnail_sizes")]
    pub thumbnail_sizes: Vec<u32>,
    #[serde(default = "default_thumbnail_quality")]
    pub thumbnail_quality: u8,
    #[serde(default = "default_watch_debounce")]
    pub watch_debounce_seconds: u64,
    #[serde(default = "default_exiftool_timeout")]
    pub exiftool_timeout_seconds: u64,
    #[serde(default = "default_ffmpeg_timeout")]
    pub ffmpeg_timeout_seconds: u64,
}

impl Default for PhotosConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            organization_pattern: default_org_pattern(),
            thumbnail_sizes: default_thumbnail_sizes(),
            thumbnail_quality: default_thumbnail_quality(),
            watch_debounce_seconds: default_watch_debounce(),
            exiftool_timeout_seconds: default_exiftool_timeout(),
            ffmpeg_timeout_seconds: default_ffmpeg_timeout(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NotesConfig {
    #[serde(default = "default_notes_root")]
    pub root_path: String,
}

impl Default for NotesConfig {
    fn default() -> Self {
        Self {
            root_path: default_notes_root(),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct McpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_tool_allowlist")]
    pub tool_allowlist: Vec<String>,
    #[serde(default = "default_mcp_rate_limit")]
    pub default_rate_limit: u32,
    #[serde(default = "default_audit_retention")]
    pub audit_log_retention_days: u32,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            tool_allowlist: default_tool_allowlist(),
            default_rate_limit: default_mcp_rate_limit(),
            audit_log_retention_days: default_audit_retention(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesConfig {
    #[serde(default = "default_true")]
    pub check_enabled: bool,
    #[serde(default = "default_check_interval")]
    pub check_interval_hours: u32,
    #[serde(default)]
    pub manifest_url: String,
    #[serde(default)]
    pub manifest_mirror: String,
    #[serde(default)]
    pub public_key: Option<String>,
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            check_enabled: true,
            check_interval_hours: 24,
            manifest_url: String::new(),
            manifest_mirror: String::new(),
            public_key: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub enabled: bool,
    /// Schedule: "hourly", "daily", "weekly", or cron-like expression
    #[serde(default = "default_backup_schedule")]
    pub schedule: String,
    #[serde(default)]
    pub local_retention: BackupRetention,
    #[serde(default)]
    pub offsite: Vec<BackupOffsiteConfig>,
    /// Paranoid mode: encrypt backups with age public key (server cannot decrypt)
    #[serde(default)]
    pub encrypt_recipient: String,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: default_backup_schedule(),
            local_retention: BackupRetention::default(),
            offsite: Vec::new(),
            encrypt_recipient: String::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupRetention {
    #[serde(default = "default_24")]
    pub hourly: u32,
    #[serde(default = "default_7")]
    pub daily: u32,
    #[serde(default = "default_4")]
    pub weekly: u32,
    #[serde(default = "default_12")]
    pub monthly: u32,
}

impl Default for BackupRetention {
    fn default() -> Self {
        Self { hourly: 24, daily: 7, weekly: 4, monthly: 12 }
    }
}

fn default_24() -> u32 { 24 }
fn default_7() -> u32 { 7 }
fn default_4() -> u32 { 4 }
fn default_12() -> u32 { 12 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupOffsiteConfig {
    pub name: String,
    #[serde(default = "default_offsite_type")]
    pub r#type: String,
    #[serde(default)]
    pub endpoint: String,
    #[serde(default)]
    pub bucket_env: String,
    #[serde(default)]
    pub key_id_env: String,
    #[serde(default)]
    pub key_env: String,
    #[serde(default = "default_backup_schedule")]
    pub schedule: String,
}

fn default_offsite_type() -> String { "s3".to_string() }
fn default_backup_schedule() -> String { "hourly".to_string() }

fn default_check_interval() -> u32 {
    24
}

fn default_tool_allowlist() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_listen_addr() -> String {
    "0.0.0.0".to_string()
}
fn default_listen_port() -> u16 {
    443
}
fn default_tls_mode() -> String {
    "acme".to_string()
}
fn default_session_ttl() -> u32 {
    24
}
fn default_max_login_attempts() -> u32 {
    5
}
fn default_lockout_duration() -> u32 {
    15
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_log_format() -> String {
    "json".to_string()
}
fn default_max_upload_size() -> u64 {
    10240
}
fn default_chunked_ttl() -> u32 {
    24
}
fn default_true() -> bool {
    true
}
fn default_org_pattern() -> String {
    "{year}/{month:02}".to_string()
}
fn default_thumbnail_sizes() -> Vec<u32> {
    vec![256, 1920]
}
fn default_thumbnail_quality() -> u8 {
    80
}
fn default_watch_debounce() -> u64 {
    5
}
fn default_exiftool_timeout() -> u64 {
    30
}
fn default_ffmpeg_timeout() -> u64 {
    60
}
fn default_notes_root() -> String {
    "notes".to_string()
}
fn default_mcp_rate_limit() -> u32 {
    60
}
fn default_audit_retention() -> u32 {
    90
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.server.listen_addr, "0.0.0.0");
        assert_eq!(config.server.listen_port, 443);
        assert_eq!(config.auth.session_ttl_hours, 24);
        assert_eq!(config.auth.max_login_attempts, 5);
    }

    #[test]
    fn test_load_defaults() {
        let config = Config::load(None).unwrap();
        assert_eq!(config.server.listen_port, 443);
        assert_eq!(config.tls.mode, "acme");
    }
}
