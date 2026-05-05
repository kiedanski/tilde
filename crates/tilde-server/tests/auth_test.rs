//! Authentication integration tests.
//!
//! Tests app-password scoping, revocation, wildcard access, and MCP token auth.

mod common;

use axum::http::{Method, StatusCode, header};

// ─── App password authentication ──────────────────────────────────────────────

#[tokio::test]
async fn no_auth_header_returns_401() {
    let env = common::create_test_server();

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wrong_password_returns_401() {
    let env = common::create_test_server();

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(
            header::AUTHORIZATION,
            common::basic_auth_header("wrong_password_xyz"),
        )
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn correct_app_password_authenticates() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test-dav", "/dav/*");

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;

    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn dav_scoped_password_rejected_on_caldav() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-only", "/dav/");

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/caldav/admin/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn caldav_scoped_password_rejected_on_dav() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "caldav-only", "/caldav/");

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn revoked_password_returns_401() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test-revoke", "/dav/*");

    // Revoke it
    {
        let conn = env.pool.get().unwrap();
        conn.execute(
            "UPDATE app_passwords SET revoked = 1 WHERE name = 'test-revoke'",
            [],
        )
        .unwrap();
    }

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn wildcard_scope_accesses_all_services() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "all-access", "*");

    // DAV
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);

    // CalDAV
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/caldav/admin/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);

    // CardDAV
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/carddav/admin/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

// ─── MCP token authentication ─────────────────────────────────────────────────

#[tokio::test]
async fn mcp_valid_token_authenticates() {
    let env = common::create_test_server();
    let token = common::create_mcp_token(&env.pool, "test-mcp", "notes:read");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;

    resp.assert_status_ok();
}

#[tokio::test]
async fn mcp_invalid_token_returns_401() {
    let env = common::create_test_server();

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(
            header::AUTHORIZATION,
            "Bearer mcp_prod_invalidtokenhere123456789012",
        )
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_app_password_rejected() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-pw", "/dav/*");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, common::basic_auth_header(&pw))
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_revoked_token_returns_401() {
    let env = common::create_test_server();
    let token = common::create_mcp_token(&env.pool, "mcp-revoke", "notes:read");

    // Revoke it
    {
        let conn = env.pool.get().unwrap();
        conn.execute(
            "UPDATE mcp_tokens SET revoked = 1 WHERE name = 'mcp-revoke'",
            [],
        )
        .unwrap();
    }

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;

    resp.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn mcp_tools_list() {
    let env = common::create_test_server();
    let token = common::create_mcp_token(&env.pool, "mcp-tools", "*");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;

    resp.assert_status_ok();
    let text = resp.text();
    assert!(text.contains("tools"), "Expected tools list in response body");
}
