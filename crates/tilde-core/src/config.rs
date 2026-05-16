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
    /// Explicit data directory. If set in config or via TILDE_DATA_DIR env var,
    /// takes precedence over XDG/platform defaults.
    #[serde(default)]
    pub data_dir_override: Option<String>,
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
    #[serde(default)]
    pub email: EmailConfig,
    #[serde(default)]
    pub tunnel: TunnelConfig,
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
                "data_dir" => "data_dir_override".into(),
                _ => key_lower.replace("__", ".").into(),
            }
        }));

        let config: Config = figment.extract()?;
        Ok(config)
    }

    /// Resolve data directory based on mode (systemd vs user)
    pub fn data_dir(&self) -> PathBuf {
        // 1. Systemd StateDirectory (highest priority in service mode)
        if let Ok(state_dir) = std::env::var("STATE_DIRECTORY") {
            return PathBuf::from(state_dir);
        }
        // 2. Config file field or TILDE_DATA_DIR env var (mapped via figment)
        if let Some(ref dir) = self.data_dir_override {
            return PathBuf::from(dir);
        }
        // 3. Env var directly (in case figment mapping didn't fire)
        if let Ok(dir) = std::env::var("TILDE_DATA_DIR") {
            return PathBuf::from(dir);
        }
        // 4. XDG fallback
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
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

        // Systemd mode (highest priority)
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

        // System-wide fallback (for Linux servers without systemd env vars)
        if !Self::is_systemd_mode() {
            let etc_path = PathBuf::from("/etc/tilde/config.toml");
            if !paths.contains(&etc_path) {
                paths.push(etc_path);
            }
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

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct AuthConfig {
    // All auth is app-password-only now; no session/WebAuthn fields remain.
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
    /// GitHub repo (owner/name) for release-based updates.
    /// Used when no manifest_url is configured.
    #[serde(default = "default_github_repo")]
    pub github_repo: String,
}

fn default_github_repo() -> String {
    "kiedanski/tilde".to_string()
}

impl Default for UpdatesConfig {
    fn default() -> Self {
        Self {
            check_enabled: true,
            check_interval_hours: 24,
            manifest_url: String::new(),
            manifest_mirror: String::new(),
            public_key: None,
            github_repo: default_github_repo(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_backup_schedule")]
    pub schedule: String,
    /// Path to restic binary
    #[serde(default = "default_restic_binary")]
    pub binary: String,
    /// Env var name containing the repository URL (e.g. "b2:bucket:path")
    #[serde(default = "default_restic_repository_env")]
    pub repository_env: String,
    /// Path to restic password file
    #[serde(default)]
    pub password_file: String,
    /// Env var name for B2 account ID
    #[serde(default = "default_b2_account_id_env")]
    pub b2_account_id_env: String,
    /// Env var name for B2 account key
    #[serde(default = "default_b2_account_key_env")]
    pub b2_account_key_env: String,
    /// Daily snapshots to keep
    #[serde(default = "default_7")]
    pub keep_daily: u32,
    /// Weekly snapshots to keep
    #[serde(default = "default_4")]
    pub keep_weekly: u32,
    /// Monthly snapshots to keep
    #[serde(default = "default_12")]
    pub keep_monthly: u32,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            schedule: default_backup_schedule(),
            binary: default_restic_binary(),
            repository_env: default_restic_repository_env(),
            password_file: String::new(),
            b2_account_id_env: default_b2_account_id_env(),
            b2_account_key_env: default_b2_account_key_env(),
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
        }
    }
}

fn default_7() -> u32 {
    7
}
fn default_4() -> u32 {
    4
}
fn default_12() -> u32 {
    12
}
fn default_restic_binary() -> String {
    "restic".to_string()
}
fn default_restic_repository_env() -> String {
    "RESTIC_REPOSITORY".to_string()
}
fn default_b2_account_id_env() -> String {
    "B2_ACCOUNT_ID".to_string()
}
fn default_b2_account_key_env() -> String {
    "B2_ACCOUNT_KEY".to_string()
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct EmailConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub accounts: Vec<EmailAccountConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmailAccountConfig {
    #[serde(default = "default_email_account_name")]
    pub name: String,
    #[serde(default)]
    pub imap_host: String,
    #[serde(default = "default_imap_port")]
    pub imap_port: u16,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    /// Environment variable name for username (alternative to inline username)
    #[serde(default)]
    pub username_env: String,
    /// Environment variable name for password (alternative to inline password)
    #[serde(default)]
    pub password_env: String,
    #[serde(default = "default_true")]
    pub use_ssl: bool,
    #[serde(default = "default_true")]
    pub idle_enabled: bool,
    #[serde(default)]
    pub folders_include: Vec<String>,
    #[serde(default = "default_folders_exclude")]
    pub folders_exclude: Vec<String>,
    #[serde(default)]
    pub retention_days: u32,
    #[serde(default = "default_poll_interval")]
    pub poll_interval_seconds: u64,
}

impl Default for EmailAccountConfig {
    fn default() -> Self {
        Self {
            name: default_email_account_name(),
            imap_host: String::new(),
            imap_port: default_imap_port(),
            username: String::new(),
            password: String::new(),
            username_env: String::new(),
            password_env: String::new(),
            use_ssl: true,
            idle_enabled: true,
            folders_include: Vec::new(),
            folders_exclude: default_folders_exclude(),
            retention_days: 0,
            poll_interval_seconds: default_poll_interval(),
        }
    }
}

impl EmailAccountConfig {
    /// Resolve the actual username (from direct value or env var).
    pub fn resolve_username(&self) -> String {
        if !self.username.is_empty() {
            return self.username.clone();
        }
        if !self.username_env.is_empty()
            && let Ok(val) = std::env::var(&self.username_env)
        {
            return val;
        }
        String::new()
    }

    /// Resolve the actual password (from direct value or env var).
    pub fn resolve_password(&self) -> String {
        if !self.password.is_empty() {
            return self.password.clone();
        }
        if !self.password_env.is_empty()
            && let Ok(val) = std::env::var(&self.password_env)
        {
            return val;
        }
        String::new()
    }
}

fn default_email_account_name() -> String {
    "personal".to_string()
}
fn default_imap_port() -> u16 {
    993
}
fn default_folders_exclude() -> Vec<String> {
    vec!["Trash".to_string(), "Spam".to_string()]
}
fn default_poll_interval() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TunnelConfig {
    /// Enable tunnel (requires newt binary). Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Path to the newt binary. Default: "newt" (found via PATH).
    #[serde(default = "default_newt_binary")]
    pub binary: String,
    /// Pangolin server endpoint (e.g., "https://pangolin.example.com")
    #[serde(default)]
    pub endpoint: String,
    /// Newt client ID
    #[serde(default)]
    pub id: String,
    /// Newt client secret (prefer secret_env for production)
    #[serde(default)]
    pub secret: String,
    /// Env var name containing the secret (preferred over inline secret)
    #[serde(default)]
    pub secret_env: String,
    /// Log level for newt (DEBUG, INFO, WARN, ERROR). Default: INFO.
    #[serde(default = "default_newt_log_level")]
    pub log_level: String,
    /// Restart delay after crash, in seconds. Default: 5.
    #[serde(default = "default_restart_delay")]
    pub restart_delay_seconds: u64,
    /// Max restart delay (exponential backoff cap), in seconds. Default: 300.
    #[serde(default = "default_max_restart_delay")]
    pub max_restart_delay_seconds: u64,
}

impl Default for TunnelConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            binary: default_newt_binary(),
            endpoint: String::new(),
            id: String::new(),
            secret: String::new(),
            secret_env: String::new(),
            log_level: default_newt_log_level(),
            restart_delay_seconds: default_restart_delay(),
            max_restart_delay_seconds: default_max_restart_delay(),
        }
    }
}

fn default_newt_binary() -> String {
    "newt".to_string()
}
fn default_newt_log_level() -> String {
    "INFO".to_string()
}
fn default_restart_delay() -> u64 {
    5
}
fn default_max_restart_delay() -> u64 {
    300
}

fn default_backup_schedule() -> String {
    "daily@04:00".to_string()
}

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
    }

    #[test]
    fn test_load_defaults() {
        let config = Config::default();
        assert_eq!(config.server.listen_port, 443);
        assert_eq!(config.tls.mode, "acme");
    }

    #[test]
    fn test_tunnel_config_defaults() {
        let config = Config::default();
        assert!(!config.tunnel.enabled);
        assert_eq!(config.tunnel.binary, "newt");
        assert_eq!(config.tunnel.log_level, "INFO");
        assert_eq!(config.tunnel.restart_delay_seconds, 5);
        assert_eq!(config.tunnel.max_restart_delay_seconds, 300);
    }
}
