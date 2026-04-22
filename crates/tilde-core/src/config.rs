//! Configuration loading via figment (TOML + env + CLI)

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,
    #[serde(default)]
    pub tls: TlsConfig,
    #[serde(default)]
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
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

#[derive(Debug, Deserialize)]
pub struct AuthConfig {
    #[serde(default = "default_session_ttl")]
    pub session_ttl_hours: u32,
    #[serde(default = "default_max_login_attempts")]
    pub max_login_attempts: u32,
    #[serde(default = "default_lockout_duration")]
    pub lockout_duration_minutes: u32,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            session_ttl_hours: default_session_ttl(),
            max_login_attempts: default_max_login_attempts(),
            lockout_duration_minutes: default_lockout_duration(),
        }
    }
}

#[derive(Debug, Deserialize)]
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

fn default_listen_addr() -> String { "0.0.0.0".to_string() }
fn default_listen_port() -> u16 { 443 }
fn default_tls_mode() -> String { "acme".to_string() }
fn default_session_ttl() -> u32 { 24 }
fn default_max_login_attempts() -> u32 { 5 }
fn default_lockout_duration() -> u32 { 15 }
fn default_log_level() -> String { "info".to_string() }
fn default_log_format() -> String { "json".to_string() }
