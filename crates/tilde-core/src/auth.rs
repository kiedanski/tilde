//! Authentication: Argon2id password hashing, app-passwords, MCP tokens

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

/// Create an app password
pub fn create_app_password(
    conn: &Connection,
    name: &str,
    scope_prefix: &str,
) -> anyhow::Result<String> {
    let password = generate_app_password();
    let hash = hash_password(&password)?;
    let lookup = hash_token(&password); // SHA-256 for fast O(1) lookup
    let id = Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    conn.execute(
        "INSERT INTO app_passwords (id, name, password_hash, lookup_hash, scope_prefix, created_at, revoked)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, 0)",
        rusqlite::params![id, name, hash, lookup, scope_prefix, now],
    )?;

    info!(name = name, scope = scope_prefix, "App password created");
    Ok(password)
}

/// Verify an app password and check scope.
/// Uses SHA-256 lookup hash for O(1) matching (avoids iterating all Argon2 hashes).
/// Falls back to scanning all rows for passwords created before the lookup_hash migration.
pub fn verify_app_password(
    conn: &Connection,
    password: &str,
    request_path: &str,
) -> anyhow::Result<bool> {
    let lookup = hash_token(password);

    // Fast path: O(1) lookup by SHA-256 hash (for passwords created after migration 006)
    let fast_result = conn.query_row(
        "SELECT password_hash, scope_prefix FROM app_passwords WHERE lookup_hash = ?1 AND revoked = 0",
        [&lookup],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    );

    if let Ok((hash, scope)) = fast_result
        && verify_password(password, &hash)
    {
        let scope_pattern = scope.trim_end_matches('*');
        if request_path.starts_with(scope_pattern) || scope == "*" {
            return Ok(true);
        }
    }

    // Slow fallback: scan rows without lookup_hash (pre-migration passwords)
    let mut stmt = conn.prepare(
        "SELECT password_hash, scope_prefix FROM app_passwords WHERE revoked = 0 AND lookup_hash IS NULL",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
    })?;

    for row in rows {
        let (hash, scope) = row?;
        if verify_password(password, &hash) {
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

    tracing::debug!(name = name, prefix = prefix, "MCP token created");
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
}
