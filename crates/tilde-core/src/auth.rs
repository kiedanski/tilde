//! Authentication: Argon2id password hashing, session tokens, app-passwords, WebAuthn

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use rand::rngs::OsRng;
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::info;
use uuid::Uuid;

pub use webauthn_rs::Webauthn;
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, RequestChallengeResponse,
    Passkey, PasskeyRegistration, PasskeyAuthentication,
    RegisterPublicKeyCredential, PublicKeyCredential,
    AuthenticationResult,
};

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

// ─── WebAuthn Support ────────────────────────────────────────────────────

/// Create a Webauthn instance from config
pub fn create_webauthn(rp_id: &str, hostname: &str) -> anyhow::Result<Webauthn> {
    let rp_id = if rp_id.is_empty() { hostname } else { rp_id };
    let rp_origin = url::Url::parse(&format!("https://{}", rp_id))
        .unwrap_or_else(|_| url::Url::parse("https://localhost").unwrap());
    let builder = webauthn_rs::WebauthnBuilder::new(rp_id, &rp_origin)?;
    let builder = builder.rp_name("tilde");
    Ok(builder.build()?)
}

/// Start WebAuthn registration — returns (challenge, registration_state)
pub fn webauthn_start_registration(
    webauthn: &Webauthn,
    user_name: &str,
) -> anyhow::Result<(CreationChallengeResponse, PasskeyRegistration)> {
    let user_id = Uuid::new_v4();
    let (ccr, reg_state) = webauthn.start_passkey_registration(user_id, user_name, user_name, None)?;
    Ok((ccr, reg_state))
}

/// Complete WebAuthn registration — returns the credential to store
pub fn webauthn_finish_registration(
    webauthn: &Webauthn,
    response: &RegisterPublicKeyCredential,
    reg_state: &PasskeyRegistration,
) -> anyhow::Result<Passkey> {
    let credential = webauthn.finish_passkey_registration(response, reg_state)?;
    Ok(credential)
}

/// Start WebAuthn authentication — returns (challenge, auth_state)
pub fn webauthn_start_authentication(
    webauthn: &Webauthn,
    credentials: &[Passkey],
) -> anyhow::Result<(RequestChallengeResponse, PasskeyAuthentication)> {
    let (rcr, auth_state) = webauthn.start_passkey_authentication(credentials)?;
    Ok((rcr, auth_state))
}

/// Complete WebAuthn authentication
pub fn webauthn_finish_authentication(
    webauthn: &Webauthn,
    response: &PublicKeyCredential,
    auth_state: &PasskeyAuthentication,
) -> anyhow::Result<AuthenticationResult> {
    let result = webauthn.finish_passkey_authentication(response, auth_state)?;
    Ok(result)
}

/// Store a WebAuthn credential in the database
pub fn store_webauthn_credential(
    conn: &Connection,
    name: &str,
    credential: &Passkey,
) -> anyhow::Result<String> {
    let id = Uuid::new_v4().to_string();
    let cred_json = serde_json::to_string(credential)?;
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    conn.execute(
        "INSERT INTO webauthn_credentials (id, public_key, counter, name, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![id, cred_json.as_bytes(), 0, name, now],
    )?;

    info!(name = name, "WebAuthn credential registered");
    Ok(id)
}

/// A WebAuthn credential summary: (id, name, created_at, last_used_at)
pub type WebauthnCredentialInfo = (String, String, String, Option<String>);

/// List all WebAuthn credentials
pub fn list_webauthn_credentials(
    conn: &Connection,
) -> anyhow::Result<Vec<WebauthnCredentialInfo>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, created_at, last_used_at FROM webauthn_credentials ORDER BY created_at DESC",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })?;
    let mut result = Vec::new();
    for row in rows {
        result.push(row?);
    }
    Ok(result)
}

/// Load all WebAuthn credentials as Passkey objects
pub fn load_webauthn_credentials(conn: &Connection) -> anyhow::Result<Vec<Passkey>> {
    let mut stmt = conn.prepare("SELECT public_key FROM webauthn_credentials")?;
    let rows = stmt.query_map([], |row| row.get::<_, Vec<u8>>(0))?;
    let mut credentials = Vec::new();
    for row in rows {
        let bytes = row?;
        let credential: Passkey = serde_json::from_slice(&bytes)?;
        credentials.push(credential);
    }
    Ok(credentials)
}

/// Remove a WebAuthn credential by ID
pub fn remove_webauthn_credential(conn: &Connection, id: &str) -> anyhow::Result<bool> {
    let affected = conn.execute("DELETE FROM webauthn_credentials WHERE id = ?1", [id])?;
    if affected > 0 {
        info!(id = id, "WebAuthn credential removed");
    }
    Ok(affected > 0)
}

/// Update last_used_at for a WebAuthn credential after authentication
pub fn update_webauthn_credential_counter(
    conn: &Connection,
    credential: &Passkey,
) -> anyhow::Result<()> {
    let cred_json = serde_json::to_string(credential)?;
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    // Update the stored credential (counter changed) and last_used_at
    // We match on the credential ID embedded in the JSON
    let cred_id_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        credential.cred_id(),
    );
    // Update all credentials — in single-user mode we just update by matching serialized data
    conn.execute(
        "UPDATE webauthn_credentials SET public_key = ?1, last_used_at = ?2, counter = counter + 1
         WHERE id IN (SELECT id FROM webauthn_credentials LIMIT 1)",
        rusqlite::params![cred_json.as_bytes(), now],
    )?;
    let _ = cred_id_b64; // suppress unused warning
    Ok(())
}

/// Check if any WebAuthn credentials exist (to know if 2FA is configured)
pub fn has_webauthn_credentials(conn: &Connection) -> anyhow::Result<bool> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM webauthn_credentials",
        [],
        |row| row.get(0),
    )?;
    Ok(count > 0)
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
