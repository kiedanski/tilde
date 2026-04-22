//! Authentication: Argon2id password hashing, session tokens, app-passwords

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;
use uuid::Uuid;

/// Hash a password with Argon2id
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;
    Ok(hash.to_string())
}

/// Verify a password against an Argon2id hash
pub fn verify_password(password: &str, hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Generate a random session token (46 chars: "tilde_session_" + 32 hex chars from 16 random bytes)
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let token_body: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
    format!("tilde_session_{}", token_body)
}

/// Generate a random MCP token
pub fn generate_mcp_token() -> String {
    let mut bytes = [0u8; 30];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let token_body: String = bytes
        .iter()
        .map(|b| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[(*b as usize) % chars.len()] as char
        })
        .collect();
    format!("mcp_prod_{}", token_body)
}

/// Generate a random app password
pub fn generate_app_password() -> String {
    let mut bytes = [0u8; 24];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    let body: String = bytes
        .iter()
        .map(|b| {
            let chars = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            chars[(*b as usize) % chars.len()] as char
        })
        .collect();
    format!("tilde_app_{}", body)
}

/// SHA-256 hash of a token (for storage)
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Constant-time token comparison
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Store the admin password hash in the kv_meta table
pub fn store_admin_password(conn: &Connection, password: &str) -> anyhow::Result<()> {
    let hash = hash_password(password)?;
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    conn.execute(
        "INSERT OR REPLACE INTO kv_meta (key, value, updated_at) VALUES ('admin_password_hash', ?1, ?2)",
        rusqlite::params![hash, now],
    )?;
    info!("Admin password hash stored");
    Ok(())
}

/// Get the admin password hash from kv_meta
pub fn get_admin_password_hash(conn: &Connection) -> anyhow::Result<Option<String>> {
    let result = conn.query_row(
        "SELECT value FROM kv_meta WHERE key = 'admin_password_hash'",
        [],
        |row| row.get::<_, String>(0),
    );
    match result {
        Ok(hash) => Ok(Some(hash)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Verify admin password
pub fn verify_admin_password(conn: &Connection, password: &str) -> anyhow::Result<bool> {
    match get_admin_password_hash(conn)? {
        Some(hash) => Ok(verify_password(password, &hash)),
        None => Ok(false),
    }
}

/// Create a new session in the database
pub fn create_session(
    conn: &Connection,
    user_agent: Option<&str>,
    source_ip: Option<&str>,
    ttl_hours: u32,
) -> anyhow::Result<String> {
    let token = generate_session_token();
    let token_hash = hash_token(&token);
    let prefix = &token[..std::cmp::min(22, token.len())]; // "tilde_session_" + 8 hex chars
    let now = jiff::Zoned::now();
    let expires = now.checked_add(jiff::SignedDuration::from_hours(ttl_hours as i64))?;
    let now_str = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let expires_str = expires.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    conn.execute(
        "INSERT INTO auth_sessions (id, token_prefix, created_at, last_used_at, expires_at, user_agent, source_ip, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        rusqlite::params![token_hash, prefix, now_str, now_str, expires_str, user_agent, source_ip],
    )?;

    info!(prefix = prefix, "Session created");
    Ok(token)
}

/// Validate a session token, returns true if valid and not expired.
/// Implements sliding TTL: extends expires_at by ttl_hours from current time on each valid use.
pub fn validate_session(conn: &Connection, token: &str, ttl_hours: u32) -> anyhow::Result<bool> {
    let token_hash = hash_token(token);
    let now = jiff::Zoned::now();
    let now_str = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    let result = conn.query_row(
        "SELECT expires_at, revoked FROM auth_sessions WHERE id = ?1",
        [&token_hash],
        |row| {
            let expires_at: String = row.get(0)?;
            let revoked: bool = row.get(1)?;
            Ok((expires_at, revoked))
        },
    );

    match result {
        Ok((expires_at, revoked)) => {
            if revoked {
                return Ok(false);
            }
            // Check expiry
            if expires_at < now_str {
                return Ok(false);
            }
            // Sliding TTL: extend expires_at from now
            let new_expires =
                now.checked_add(jiff::SignedDuration::from_hours(ttl_hours as i64))?;
            let new_expires_str = new_expires.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            conn.execute(
                "UPDATE auth_sessions SET last_used_at = ?1, expires_at = ?2 WHERE id = ?3",
                rusqlite::params![now_str, new_expires_str, token_hash],
            )?;
            Ok(true)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(e.into()),
    }
}

/// Create an app password
pub fn create_app_password(
    conn: &Connection,
    name: &str,
    scope_prefix: &str,
) -> anyhow::Result<String> {
    let password = generate_app_password();
    let hash = hash_password(&password)?;
    let id = Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    conn.execute(
        "INSERT INTO app_passwords (id, name, password_hash, scope_prefix, created_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, 0)",
        rusqlite::params![id, name, hash, scope_prefix, now],
    )?;

    info!(name = name, scope = scope_prefix, "App password created");
    Ok(password)
}

/// Verify an app password and check scope
pub fn verify_app_password(
    conn: &Connection,
    password: &str,
    request_path: &str,
) -> anyhow::Result<bool> {
    let mut stmt =
        conn.prepare("SELECT password_hash, scope_prefix FROM app_passwords WHERE revoked = 0")?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    for row in rows {
        let (hash, scope) = row?;
        if verify_password(password, &hash) {
            // Check scope
            let scope_pattern = scope.trim_end_matches('*');
            if request_path.starts_with(scope_pattern) || scope == "*" {
                return Ok(true);
            }
        }
    }

    Ok(false)
}

/// Create an MCP token
pub fn create_mcp_token(
    conn: &Connection,
    name: &str,
    scopes: &str,
    rate_limit: u32,
) -> anyhow::Result<String> {
    let token = generate_mcp_token();
    let token_hash = hash_token(&token);
    let prefix = &token[..std::cmp::min(17, token.len())]; // "mcp_prod_" + 8 chars
    let id = Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    conn.execute(
        "INSERT INTO mcp_tokens (id, name, token_hash, token_prefix, scopes, rate_limit, created_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
        rusqlite::params![id, name, token_hash, prefix, scopes, rate_limit, now],
    )?;

    info!(name = name, prefix = prefix, "MCP token created");
    Ok(token)
}

/// Validate an MCP token, returns (token_name, scopes) if valid
pub fn validate_mcp_token(
    conn: &Connection,
    token: &str,
) -> anyhow::Result<Option<(String, String)>> {
    let token_hash = hash_token(token);

    let result = conn.query_row(
        "SELECT name, scopes, revoked FROM mcp_tokens WHERE token_hash = ?1",
        [&token_hash],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, bool>(2)?,
            ))
        },
    );

    match result {
        Ok((name, scopes, revoked)) => {
            if revoked {
                return Ok(None);
            }
            // Update last_used_at
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "UPDATE mcp_tokens SET last_used_at = ?1 WHERE token_hash = ?2",
                rusqlite::params![now, token_hash],
            )?;
            Ok(Some((name, scopes)))
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_and_verify_password() {
        let hash = hash_password("testpass123").unwrap();
        assert!(hash.starts_with("$argon2id$"));
        assert!(verify_password("testpass123", &hash));
        assert!(!verify_password("wrongpass", &hash));
    }

    #[test]
    fn test_session_token_format() {
        let token = generate_session_token();
        assert!(token.starts_with("tilde_session_"));
        assert_eq!(token.len(), 14 + 32); // prefix + 16 bytes as hex = 46 chars
    }

    #[test]
    fn test_mcp_token_format() {
        let token = generate_mcp_token();
        assert!(token.starts_with("mcp_prod_"));
        assert_eq!(token.len(), 9 + 30); // prefix + 30 alphanumeric
    }

    #[test]
    fn test_hash_token() {
        let hash = hash_token("test_token");
        assert_eq!(hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_constant_time_compare() {
        assert!(constant_time_compare(b"hello", b"hello"));
        assert!(!constant_time_compare(b"hello", b"world"));
        assert!(!constant_time_compare(b"hello", b"hell"));
    }

    #[test]
    fn test_admin_password_roundtrip() {
        use crate::db;
        let conn = db::init_db(":memory:").unwrap();
        let migrations_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("migrations");
        db::run_migrations(&conn, &migrations_dir).unwrap();

        store_admin_password(&conn, "testpass123").unwrap();
        assert!(verify_admin_password(&conn, "testpass123").unwrap());
        assert!(!verify_admin_password(&conn, "wrongpass").unwrap());
    }
}
