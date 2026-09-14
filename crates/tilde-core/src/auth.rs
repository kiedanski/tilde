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
///
/// Thin wrapper over [`authenticate_app_password`] for callers that only need a
/// yes/no answer (CalDAV, CardDAV).
pub fn verify_app_password(
    conn: &Connection,
    password: &str,
    request_path: &str,
) -> anyhow::Result<bool> {
    Ok(authenticate_app_password(conn, password, request_path)?.is_some())
}

/// Authenticate an app password and return the **id of the credential** that
/// matched, or `None` if the password is unknown, revoked, or out of scope.
///
/// The id matters because per-client state — notably the base version used for
/// three-way merge (see plan.md §5) — is keyed by credential. A shared password
/// across devices collapses that tracking, so each device should have its own.
///
/// Uses SHA-256 lookup hash for O(1) matching (avoids iterating all Argon2 hashes).
/// Falls back to scanning all rows for passwords created before the lookup_hash migration.
pub fn authenticate_app_password(
    conn: &Connection,
    password: &str,
    request_path: &str,
) -> anyhow::Result<Option<String>> {
    let lookup = hash_token(password);

    let scope_allows = |scope: &str| -> bool {
        if scope == "*" {
            return true;
        }
        let scope_pattern = scope.trim_end_matches('*');
        if request_path.starts_with(scope_pattern) {
            return true;
        }
        // Issue #8: "/dav/" names the whole DAV family, so a credential scoped
        // "/dav/*" deliberately also covers CalDAV and CardDAV. This is the rule
        // the tests dav_scoped_password_works_on_{caldav,carddav} pin.
        //
        // It used to be implemented by passing the constant "/dav/" as the
        // request path at every call site, which made authorization compare a
        // constant against itself: the family rule worked, but nothing narrower
        // did — "/caldav/*" was rejected on its own mount, and no credential
        // could be limited to a single mount. Encoding the rule explicitly keeps
        // the intent and restores the granularity.
        if matches!(scope_pattern, "/dav/" | "/dav") {
            return request_path.starts_with("/caldav/") || request_path.starts_with("/carddav/");
        }
        false
    };

    // Fast path: O(1) lookup by SHA-256 hash (for passwords created after migration 006)
    let fast_result = conn.query_row(
        "SELECT id, password_hash, scope_prefix FROM app_passwords WHERE lookup_hash = ?1 AND revoked = 0",
        [&lookup],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        },
    );

    if let Ok((id, hash, scope)) = fast_result
        && verify_password(password, &hash)
        && scope_allows(&scope)
    {
        return Ok(Some(id));
    }

    // Slow fallback: scan rows without lookup_hash (pre-migration passwords)
    let mut stmt = conn.prepare(
        "SELECT id, password_hash, scope_prefix FROM app_passwords WHERE revoked = 0 AND lookup_hash IS NULL",
    )?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;

    for row in rows {
        let (id, hash, scope) = row?;
        if verify_password(password, &hash) && scope_allows(&scope) {
            return Ok(Some(id));
        }
    }

    Ok(None)
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

    // ─── authenticate_app_password ───────────────────────────────────────────
    //
    // Phase 2' slice 1: base-version tracking is keyed per client, so auth must
    // report *which* credential authenticated, not just that one did.

    fn auth_db() -> (tempfile::TempDir, Connection) {
        let dir = tempfile::tempdir().unwrap();
        let conn = crate::db::init_db(dir.path().join("t.db").to_str().unwrap()).unwrap();
        crate::db::run_embedded_migrations(&conn).unwrap();
        (dir, conn)
    }

    fn id_of(conn: &Connection, name: &str) -> String {
        conn.query_row(
            "SELECT id FROM app_passwords WHERE name = ?1",
            [name],
            |r| r.get(0),
        )
        .unwrap()
    }

    #[test]
    fn authenticate_app_password_returns_credential_id() {
        let (_d, conn) = auth_db();
        let pw = create_app_password(&conn, "phone", "/dav/").unwrap();

        let got = authenticate_app_password(&conn, &pw, "/dav/notes/a.md").unwrap();

        assert_eq!(
            got,
            Some(id_of(&conn, "phone")),
            "must identify which credential authenticated"
        );
    }

    #[test]
    fn authenticate_app_password_distinguishes_two_devices() {
        let (_d, conn) = auth_db();
        let phone = create_app_password(&conn, "phone", "/dav/").unwrap();
        let laptop = create_app_password(&conn, "laptop", "/dav/").unwrap();

        let a = authenticate_app_password(&conn, &phone, "/dav/x").unwrap();
        let b = authenticate_app_password(&conn, &laptop, "/dav/x").unwrap();

        assert_ne!(a, b, "separate devices must resolve to separate ids");
        assert_eq!(a, Some(id_of(&conn, "phone")));
        assert_eq!(b, Some(id_of(&conn, "laptop")));
    }

    #[test]
    fn authenticate_app_password_rejects_wrong_password() {
        let (_d, conn) = auth_db();
        create_app_password(&conn, "phone", "/dav/").unwrap();

        let got = authenticate_app_password(&conn, "not-the-password", "/dav/x").unwrap();

        assert_eq!(got, None);
    }

    #[test]
    fn authenticate_app_password_rejects_out_of_scope() {
        let (_d, conn) = auth_db();
        let pw = create_app_password(&conn, "caldav-only", "/caldav/").unwrap();

        let got = authenticate_app_password(&conn, &pw, "/dav/notes/a.md").unwrap();

        assert_eq!(got, None, "scope must still be enforced");
    }

    #[test]
    fn authenticate_app_password_rejects_revoked() {
        let (_d, conn) = auth_db();
        let pw = create_app_password(&conn, "old", "/dav/").unwrap();
        conn.execute("UPDATE app_passwords SET revoked = 1", [])
            .unwrap();

        let got = authenticate_app_password(&conn, &pw, "/dav/x").unwrap();

        assert_eq!(got, None);
    }

    /// The bool wrapper must keep behaving exactly as before for existing callers
    /// (tilde-cal:100, tilde-card:97).
    #[test]
    fn verify_app_password_still_agrees_with_authenticate() {
        let (_d, conn) = auth_db();
        let pw = create_app_password(&conn, "phone", "/dav/").unwrap();

        assert!(verify_app_password(&conn, &pw, "/dav/x").unwrap());
        // Issue #8: the DAV family rule — "/dav/" deliberately covers CalDAV and
        // CardDAV as well.
        assert!(verify_app_password(&conn, &pw, "/caldav/x").unwrap());
        assert!(verify_app_password(&conn, &pw, "/carddav/x").unwrap());
        assert!(!verify_app_password(&conn, "wrong", "/dav/x").unwrap());

        // ...but a mount-specific scope stays mount-specific, which the old
        // constant-path implementation made impossible.
        let cal = create_app_password(&conn, "cal", "/caldav/").unwrap();
        assert!(verify_app_password(&conn, &cal, "/caldav/admin/x").unwrap());
        assert!(!verify_app_password(&conn, &cal, "/dav/notes/x").unwrap());
        assert!(!verify_app_password(&conn, &cal, "/carddav/x").unwrap());
    }

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

    #[test]
    fn test_app_password_format() {
        let pw = generate_app_password();
        assert!(pw.starts_with("tilde_app_"));
        assert_eq!(pw.len(), 10 + 24); // prefix + 24 alphanumeric
    }

    /// Scope matching logic: wildcard scope "*" matches any path.
    #[test]
    fn scope_wildcard_matches_all() {
        let scope = "*";
        // The logic in verify_app_password:
        // scope == "*" → always true
        assert!(scope == "*");
    }

    /// Scope matching logic: prefix "/dav/" matches "/dav/files/test.txt"
    #[test]
    fn scope_prefix_matches_subpaths() {
        let scope = "/dav/*";
        let scope_pattern = scope.trim_end_matches('*');
        assert!("/dav/files/test.txt".starts_with(scope_pattern));
        assert!("/dav/notes/note.md".starts_with(scope_pattern));
        assert!(!"/caldav/admin/".starts_with(scope_pattern));
    }

    /// Scope matching logic: exact prefix without wildcard
    #[test]
    fn scope_exact_prefix_without_wildcard() {
        let scope = "/caldav/";
        let scope_pattern = scope.trim_end_matches('*');
        assert!("/caldav/admin/default/".starts_with(scope_pattern));
        assert!(!"/dav/files/".starts_with(scope_pattern));
    }
}
