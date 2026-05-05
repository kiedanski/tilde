//! Compatibility and discovery endpoint tests.
//!
//! Tests health check, well-known redirects, OCS capabilities, Nextcloud compat,
//! Apple mobileconfig, principals, webhooks, and OAuth metadata.

mod common;

use axum::http::{Method, StatusCode, header};

// ─── Health & status ──────────────────────────────────────────────────────────

#[tokio::test]
async fn health_endpoint() {
    let env = common::create_test_server();

    let resp = env.server.get("/health").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(
        body.contains("\"status\":\"healthy\"") || body.contains("\"status\": \"healthy\"")
    );
}

#[tokio::test]
async fn status_php() {
    let env = common::create_test_server();

    let resp = env.server.get("/status.php").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(body.contains("\"installed\":true") || body.contains("\"installed\": true"));
    assert!(body.contains("tilde"));
}

// ─── Well-known redirects ─────────────────────────────────────────────────────

#[tokio::test]
async fn well_known_caldav_redirect() {
    let env = common::create_test_server();

    let resp = env.server.get("/.well-known/caldav").await;
    resp.assert_status(StatusCode::MOVED_PERMANENTLY);
    let location = resp.header(header::LOCATION);
    assert_eq!(location.to_str().unwrap(), "/caldav/");
}

#[tokio::test]
async fn well_known_carddav_redirect() {
    let env = common::create_test_server();

    let resp = env.server.get("/.well-known/carddav").await;
    resp.assert_status(StatusCode::MOVED_PERMANENTLY);
    let location = resp.header(header::LOCATION);
    assert_eq!(location.to_str().unwrap(), "/carddav/");
}

// ─── OCS capabilities ─────────────────────────────────────────────────────────

#[tokio::test]
async fn ocs_capabilities() {
    let env = common::create_test_server();

    let resp = env.server.get("/ocs/v2.php/cloud/capabilities").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(body.contains("dav"));
    assert!(body.contains("chunking"));
}

#[tokio::test]
async fn ocs_user_handler() {
    let env = common::create_test_server();

    let resp = env.server.get("/ocs/v1.php/cloud/user").await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(body.contains("admin"));
    assert!(body.contains("quota"));
}

// ─── Principals ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn root_propfind() {
    let env = common::create_test_server();

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/")
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("current-user-principal"));
}

#[tokio::test]
async fn principals_propfind() {
    let env = common::create_test_server();

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/principals/admin/",
        )
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("calendar-home-set"));
    assert!(body.contains("addressbook-home-set"));
}

#[tokio::test]
async fn principals_options() {
    let env = common::create_test_server();

    let resp = env
        .server
        .method(Method::OPTIONS, "/principals/admin/")
        .await;
    resp.assert_status_ok();
}

// ─── Nextcloud compat redirects ───────────────────────────────────────────────

#[tokio::test]
async fn remote_php_dav_redirect() {
    let env = common::create_test_server();

    let resp = env
        .server
        .get("/remote.php/dav/files/admin/documents/test.txt")
        .await;
    resp.assert_status(StatusCode::PERMANENT_REDIRECT);
    let location = resp.header(header::LOCATION);
    assert!(location.to_str().unwrap().contains("/dav/files/"));
}

#[tokio::test]
async fn remote_php_webdav_redirect() {
    let env = common::create_test_server();

    let resp = env.server.get("/remote.php/webdav/test.txt").await;
    resp.assert_status(StatusCode::PERMANENT_REDIRECT);
    let location = resp.header(header::LOCATION);
    assert!(location.to_str().unwrap().contains("/dav/files/test.txt"));
}

// ─── Apple mobileconfig ───────────────────────────────────────────────────────

#[tokio::test]
async fn apple_mobileconfig() {
    let env = common::create_test_server();

    let resp = env.server.get("/apple-mobileconfig").await;
    resp.assert_status_ok();
    let ct = resp.header(header::CONTENT_TYPE);
    assert!(ct.to_str().unwrap().contains("x-apple-aspen-config"));
    let body = resp.text();
    assert!(body.contains("CalDAV"));
    assert!(body.contains("CardDAV"));
}

// ─── OAuth metadata ───────────────────────────────────────────────────────────

#[tokio::test]
async fn oauth_protected_resource() {
    let env = common::create_test_server();

    let resp = env
        .server
        .get("/.well-known/oauth-protected-resource")
        .await;
    resp.assert_status_ok();
    assert!(resp.text().contains("bearer_methods_supported"));
}

// ─── Webhook tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn webhook_valid_hmac() {
    let env = common::create_test_server();
    let token_prefix = "test_hook_01";
    let hmac_secret = "supersecret";

    {
        let conn = env.pool.get().unwrap();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, rate_limit, revoked, hmac_secret, created_at)
             VALUES ('wh1', 'test-webhook', 'fakehash1', ?1, 'generic:write', 100, 0, ?2, ?3)",
            rusqlite::params![token_prefix, hmac_secret, now],
        )
        .unwrap();
    }

    let payload = r#"{"msg":"hello"}"#;

    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(hmac_secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

    let resp = env
        .server
        .post(&format!("/api/webhook/{}", token_prefix))
        .content_type("application/json")
        .add_header("X-Tilde-Signature", signature)
        .text(payload)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn webhook_no_hmac_secret_returns_403() {
    let env = common::create_test_server();
    let token_prefix = "test_hook_02";

    {
        let conn = env.pool.get().unwrap();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, rate_limit, revoked, hmac_secret, created_at)
             VALUES ('wh2', 'no-hmac', 'fakehash2', ?1, 'generic:write', 100, 0, NULL, ?2)",
            rusqlite::params![token_prefix, now],
        )
        .unwrap();
    }

    let resp = env
        .server
        .post(&format!("/api/webhook/{}", token_prefix))
        .content_type("application/json")
        .text(r#"{"msg":"hello"}"#)
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn webhook_wrong_signature_returns_401() {
    let env = common::create_test_server();
    let token_prefix = "test_hook_03";

    {
        let conn = env.pool.get().unwrap();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, rate_limit, revoked, hmac_secret, created_at)
             VALUES ('wh3', 'wrong-sig', 'fakehash3', ?1, 'generic:write', 100, 0, 'realsecret', ?2)",
            rusqlite::params![token_prefix, now],
        )
        .unwrap();
    }

    let resp = env
        .server
        .post(&format!("/api/webhook/{}", token_prefix))
        .content_type("application/json")
        .add_header(
            "X-Tilde-Signature",
            "sha256=0000000000000000000000000000000000000000000000000000000000000000",
        )
        .text(r#"{"msg":"hello"}"#)
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_revoked_token_returns_401() {
    let env = common::create_test_server();
    let token_prefix = "test_hook_04";

    {
        let conn = env.pool.get().unwrap();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO webhook_tokens (id, name, token_hash, token_prefix, scopes, rate_limit, revoked, hmac_secret, created_at)
             VALUES ('wh4', 'revoked-hook', 'fakehash4', ?1, 'generic:write', 100, 1, 'secret', ?2)",
            rusqlite::params![token_prefix, now],
        )
        .unwrap();
    }

    let payload = r#"{"msg":"hello"}"#;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(b"secret").unwrap();
    mac.update(payload.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

    let resp = env
        .server
        .post(&format!("/api/webhook/{}", token_prefix))
        .content_type("application/json")
        .add_header("X-Tilde-Signature", signature)
        .text(payload)
        .await;
    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn webhook_unknown_prefix_returns_404() {
    let env = common::create_test_server();

    let resp = env
        .server
        .post("/api/webhook/nonexistent_prefix")
        .content_type("application/json")
        .text(r#"{"msg":"hello"}"#)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── Host filter ──────────────────────────────────────────────────────────────

#[tokio::test]
async fn host_filter_allows_localhost() {
    let env = common::create_test_server();

    let resp = env
        .server
        .get("/health")
        .add_header(header::HOST, "localhost:8080")
        .await;
    // With empty hostname config, host filter is skipped
    resp.assert_status_ok();
}
