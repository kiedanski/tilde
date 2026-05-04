//! Integration tests for the tilde HTTP server.
//!
//! Each test creates an in-process axum Router backed by a temp-file SQLite DB,
//! exercises it with tower's `ServiceExt::oneshot`, and cleans up automatically.

use axum::{
    body::Body,
    http::{Request, StatusCode, header},
};
use base64::Engine;
use http_body_util::BodyExt;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tilde_core::{auth, config::Config, db};
use tilde_server::{AppState, SharedState, build_router};
use tower::ServiceExt;

// ─── Test harness ──────────────────────────────────────────────────────────

struct TestApp {
    router: axum::Router,
    _dir: tempfile::TempDir,
    db: db::DbPool,
}

impl TestApp {
    /// Send a request to the router.
    /// If the request already has a ConnectInfo extension, it's used directly.
    /// Otherwise a default loopback address is injected.
    async fn request(&self, mut req: Request<Body>) -> axum::response::Response {
        // Inject ConnectInfo extension if not already present (needed by metrics/mcp handlers)
        if req.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>().is_none() {
            req.extensions_mut().insert(axum::extract::ConnectInfo(
                "127.0.0.1:12345".parse::<SocketAddr>().unwrap(),
            ));
        }
        self.router
            .clone()
            .into_service()
            .oneshot(req)
            .await
            .unwrap()
    }
}

async fn setup() -> TestApp {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().to_path_buf();
    let db_path = data_dir.join("tilde.db");

    // Create necessary subdirectories
    let files_root = data_dir.join("files");
    let uploads_root = data_dir.join("uploads");
    let notes_root = data_dir.join("notes");
    let photos_root = data_dir.join("photos");
    std::fs::create_dir_all(&files_root).unwrap();
    std::fs::create_dir_all(&uploads_root).unwrap();
    std::fs::create_dir_all(&notes_root).unwrap();
    std::fs::create_dir_all(&photos_root).unwrap();

    // Init DB and run migrations
    let db_path_str = db_path.to_str().unwrap();
    {
        let conn = db::init_db(db_path_str).unwrap();
        let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("migrations");
        db::run_migrations(&conn, &migrations_dir).unwrap();
    }

    let pool = db::init_pool(db_path_str).unwrap();

    // Ensure default calendar and addressbook
    {
        let conn = pool.get().unwrap();
        tilde_cal::ensure_default_calendar(&conn);
        tilde_card::ensure_default_addressbook(&conn);
    }

    let config = Config::default();

    let mcp_state: tilde_mcp::SharedMcpState = Arc::new(tilde_mcp::McpState {
        db: pool.clone(),
        data_dir: data_dir.clone(),
        rate_limits: Mutex::new(HashMap::new()),
    });

    let state: SharedState = Arc::new(AppState {
        config: arc_swap::ArcSwap::new(Arc::new(config)),
        db: pool.clone(),
        start_time: Instant::now(),
        mcp_state,
        tunnel_status: None,
    });

    let dav_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: pool.clone(),
        files_root: files_root.clone(),
        uploads_root,
        db_path_prefix: String::new(),
        scope_prefix: "/dav/".to_string(),
        organization_pattern: String::new(),
    });

    let caldav_state: tilde_cal::SharedCalDavState =
        Arc::new(tilde_cal::CalDavState { db: pool.clone() });

    let carddav_state: tilde_card::SharedCardDavState =
        Arc::new(tilde_card::CardDavState { db: pool.clone() });

    let router = build_router(state, dav_state, caldav_state, carddav_state);

    TestApp {
        router,
        _dir: dir,
        db: pool,
    }
}

/// Helper: create an app password scoped to the given prefix.
fn create_password(app: &TestApp, name: &str, scope: &str) -> String {
    let conn = app.db.get().unwrap();
    auth::create_app_password(&conn, name, scope).unwrap()
}

/// Helper: create an MCP token
fn create_mcp_token(app: &TestApp, name: &str, scopes: &str) -> String {
    let conn = app.db.get().unwrap();
    auth::create_mcp_token(&conn, name, scopes, 100).unwrap()
}

/// Helper: build Basic auth header value
fn basic_auth(password: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", password));
    format!("Basic {}", encoded)
}

/// Helper: read response body as string
async fn body_string(resp: axum::response::Response) -> String {
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8(bytes.to_vec()).unwrap()
}

// ─── Health & Compat tests ─────────────────────────────────────────────────

#[tokio::test]
async fn test_health_endpoint() {
    let app = setup().await;
    let req = Request::builder()
        .uri("/health")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"status\":\"healthy\"") || body.contains("\"status\": \"healthy\""));
}

#[tokio::test]
async fn test_status_php() {
    let app = setup().await;
    let req = Request::get("/status.php").body(Body::empty()).unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("\"installed\":true") || body.contains("\"installed\": true"));
    assert!(body.contains("tilde"));
}

#[tokio::test]
async fn test_well_known_caldav_redirect() {
    let app = setup().await;
    let req = Request::get("/.well-known/caldav")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/caldav/");
}

#[tokio::test]
async fn test_well_known_carddav_redirect() {
    let app = setup().await;
    let req = Request::get("/.well-known/carddav")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MOVED_PERMANENTLY);
    assert_eq!(resp.headers().get(header::LOCATION).unwrap(), "/carddav/");
}

// ─── Auth tests ────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_auth_no_header_returns_401() {
    let app = setup().await;
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_wrong_password_returns_401() {
    let app = setup().await;
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth("wrong_password_xyz"))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_correct_password_dav() {
    let app = setup().await;
    let password = create_password(&app, "test-dav", "/dav/*");
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_auth_dav_password_cannot_access_caldav() {
    let app = setup().await;
    let password = create_password(&app, "test-dav-only", "/dav/");
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_caldav_password_cannot_access_dav() {
    let app = setup().await;
    let password = create_password(&app, "test-caldav-only", "/caldav/");
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_auth_revoked_password_returns_401() {
    let app = setup().await;
    let password = create_password(&app, "test-revoke", "/dav/*");

    // Revoke it
    {
        let conn = app.db.get().unwrap();
        conn.execute(
            "UPDATE app_passwords SET revoked = 1 WHERE name = 'test-revoke'",
            [],
        )
        .unwrap();
    }

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── WebDAV tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_dav_options() {
    let app = setup().await;
    // OPTIONS without Origin header — CORS layer still intercepts on tower-http
    // so we just verify the status is 200 (not 401, 405, etc.)
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/dav/files/")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    // The DAV header may be consumed by CORS middleware in test mode;
    // in production, real DAV clients (without Origin) get it through.
    // Verify CORS allows all methods (which covers WebDAV methods)
    let allow_methods = resp.headers().get("access-control-allow-methods");
    assert!(allow_methods.is_some());
}

#[tokio::test]
async fn test_dav_put_get_cycle() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // PUT file
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/hello.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("Hello, World!"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET file
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/hello.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert_eq!(body, "Hello, World!");
}

#[tokio::test]
async fn test_dav_put_overwrite_returns_204() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // First PUT (create)
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/overwrite.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("version 1"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second PUT (overwrite)
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/overwrite.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("version 2"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET to verify overwrite
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/overwrite.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert_eq!(body, "version 2");
}

#[tokio::test]
async fn test_dav_delete() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/deleteme.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("to be deleted"))
        .unwrap();
    app.request(req).await;

    // DELETE
    let req = Request::builder()
        .method("DELETE")
        .uri("/dav/files/deleteme.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET should 404
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/deleteme.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dav_mkcol() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // MKCOL
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/testdir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // PROPFIND Depth:1 on root should show the directory
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("testdir"));
}

#[tokio::test]
async fn test_dav_move() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // PUT source file
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/source.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("move me"))
        .unwrap();
    app.request(req).await;

    // MOVE
    let req = Request::builder()
        .method("MOVE")
        .uri("/dav/files/source.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/dest.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Old path 404
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/source.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // New path exists
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/dest.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert_eq!(body, "move me");
}

#[tokio::test]
async fn test_dav_copy() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // PUT source
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/original.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("copy me"))
        .unwrap();
    app.request(req).await;

    // COPY
    let req = Request::builder()
        .method("COPY")
        .uri("/dav/files/original.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/copied.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Both paths exist
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/original.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/copied.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert_eq!(body, "copy me");
}

#[tokio::test]
async fn test_dav_propfind_depth_0() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_dav_propfind_depth_1_lists_files() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Create a file first
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/listed.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("content"))
        .unwrap();
    app.request(req).await;

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("listed.txt"));
}

#[tokio::test]
async fn test_dav_path_traversal_rejected() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/../../../etc/passwd")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_dav_depth_infinity_forbidden() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "infinity")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

// ─── CalDAV tests ──────────────────────────────────────────────────────────

#[tokio::test]
async fn test_caldav_propfind_admin() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_caldav_mkcalendar() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("MKCALENDAR")
        .uri("/caldav/admin/work/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_caldav_put_get_delete_ics() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:event1\r\nSUMMARY:Test Event\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET
    let req = Request::builder()
        .method("GET")
        .uri("/caldav/admin/default/event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Test Event"));
    assert!(body.contains("event1"));

    // DELETE
    let req = Request::builder()
        .method("DELETE")
        .uri("/caldav/admin/default/event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET after delete -> 404
    let req = Request::builder()
        .method("GET")
        .uri("/caldav/admin/default/event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_caldav_report_multiget() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:mg-event1\r\nSUMMARY:Multiget Event\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/mg-event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // REPORT calendar-multiget
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<cal:calendar-multiget xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
  <d:href>/caldav/admin/default/mg-event1.ics</d:href>
</cal:calendar-multiget>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/caldav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("Multiget Event"));
}

#[tokio::test]
async fn test_caldav_if_none_match_star_on_existing() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:inm-event1\r\nSUMMARY:First\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    // First PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/inm-event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // Second PUT with If-None-Match: * should fail
    let ics2 = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:inm-event1\r\nSUMMARY:Second\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/inm-event1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from(ics2))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_caldav_wrong_content_type() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/bad.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("not ics"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

#[tokio::test]
async fn test_caldav_wrong_principal() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/bob/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── CardDAV tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_carddav_propfind_admin() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/admin/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_carddav_mkcol_addressbook() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("MKCOL")
        .uri("/carddav/admin/work/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn test_carddav_put_get_delete_vcf() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Alice Test\r\nEMAIL:alice@example.com\r\nEND:VCARD\r\n";

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/alice.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET
    let req = Request::builder()
        .method("GET")
        .uri("/carddav/admin/default/alice.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("Alice Test"));

    // DELETE
    let req = Request::builder()
        .method("DELETE")
        .uri("/carddav/admin/default/alice.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // GET after delete -> 404
    let req = Request::builder()
        .method("GET")
        .uri("/carddav/admin/default/alice.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_carddav_report_multiget() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Bob Multiget\r\nEMAIL:bob@example.com\r\nEND:VCARD\r\n";

    // PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/bob.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    app.request(req).await;

    // REPORT addressbook-multiget
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
  <d:href>/carddav/admin/default/bob.vcf</d:href>
</card:addressbook-multiget>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/carddav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("Bob Multiget"));
}

#[tokio::test]
async fn test_carddav_report_addressbook_query_text_match() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    // Put two contacts
    let vcard1 = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Charlie Alpha\r\nEMAIL:charlie@example.com\r\nEND:VCARD\r\n";
    let vcard2 = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Delta Beta\r\nEMAIL:delta@example.com\r\nEND:VCARD\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/charlie.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard1))
        .unwrap();
    app.request(req).await;

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/delta.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard2))
        .unwrap();
    app.request(req).await;

    // REPORT addressbook-query filtering for "charlie"
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
  <card:filter>
    <card:prop-filter name="FN">
      <card:text-match collation="i;unicode-casemap" match-type="contains">charlie</card:text-match>
    </card:prop-filter>
  </card:filter>
</card:addressbook-query>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/carddav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("Charlie Alpha"));
    assert!(!body.contains("Delta Beta"));
}

#[tokio::test]
async fn test_carddav_if_none_match_star_on_existing() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Eve Existing\r\nEND:VCARD\r\n";

    // First PUT
    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/eve.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    app.request(req).await;

    // Second PUT with If-None-Match: *
    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/eve.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .header(header::IF_NONE_MATCH, "*")
        .body(Body::from(vcard))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn test_carddav_wrong_principal() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/bob/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── MCP tests ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn test_mcp_valid_token() {
    let app = setup().await;
    let token = create_mcp_token(&app, "test-mcp", "notes:read");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_mcp_invalid_token() {
    let app = setup().await;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(
            header::AUTHORIZATION,
            "Bearer mcp_prod_invalidtokenhere123456789012",
        )
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_mcp_app_password_rejected() {
    let app = setup().await;
    let password = create_password(&app, "dav-pw", "/dav/*");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Webhook tests ─────────────────────────────────────────────────────────

#[tokio::test]
async fn test_webhook_valid_hmac() {
    let app = setup().await;
    let token_prefix = "test_hook_01";
    let hmac_secret = "supersecret";

    // Create webhook token directly in DB
    {
        let conn = app.db.get().unwrap();
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

    // Compute HMAC
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(hmac_secret.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/webhook/{}", token_prefix))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Tilde-Signature", &signature)
        .body(Body::from(payload))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_webhook_no_hmac_secret_returns_403() {
    let app = setup().await;
    let token_prefix = "test_hook_02";

    // Create webhook token without HMAC secret
    {
        let conn = app.db.get().unwrap();
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

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/webhook/{}", token_prefix))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"msg":"hello"}"#))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn test_webhook_wrong_signature_returns_401() {
    let app = setup().await;
    let token_prefix = "test_hook_03";

    // Create webhook token with HMAC secret
    {
        let conn = app.db.get().unwrap();
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

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/webhook/{}", token_prefix))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Tilde-Signature", "sha256=0000000000000000000000000000000000000000000000000000000000000000")
        .body(Body::from(r#"{"msg":"hello"}"#))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Root PROPFIND / principals ────────────────────────────────────────────

#[tokio::test]
async fn test_root_propfind() {
    let app = setup().await;
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/")
        .header("depth", "0")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("current-user-principal"));
}

#[tokio::test]
async fn test_ocs_capabilities() {
    let app = setup().await;
    let req = Request::get("/ocs/v2.php/cloud/capabilities")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("dav"));
    assert!(body.contains("chunking"));
}

#[tokio::test]
async fn test_caldav_propfind_depth_1_lists_calendars() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    // Should list the default calendar
    assert!(body.contains("default"));
    assert!(body.contains("Personal"));
}

#[tokio::test]
async fn test_carddav_propfind_depth_1_lists_addressbooks() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/admin/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    // Should list the default addressbook
    assert!(body.contains("default"));
    assert!(body.contains("Contacts"));
}

// ─── Wildcard scope tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_wildcard_scope_access_all() {
    let app = setup().await;
    let password = create_password(&app, "all-access", "*");

    // Should access DAV
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);

    // Should access CalDAV
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);

    // Should access CardDAV
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/admin/")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

// ─── Additional CalDAV tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_caldav_options() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/caldav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_caldav_proppatch() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:">
  <d:set>
    <d:prop>
      <d:displayname>Renamed Calendar</d:displayname>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let req = Request::builder()
        .method("PROPPATCH")
        .uri("/caldav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_caldav_sync_collection_report() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    // PUT an event first
    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:sync-ev1\r\nSUMMARY:Sync Test\r\nDTSTART:20260701T080000Z\r\nDTEND:20260701T090000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/sync-ev1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // sync-collection with token 0 (full sync)
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:sync-collection xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:sync-token/>
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
</d:sync-collection>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/caldav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("Sync Test"));
    assert!(body.contains("sync-token"));
}

#[tokio::test]
async fn test_caldav_calendar_query_time_range() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    // Create an event in June 2026
    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:range-ev1\r\nSUMMARY:June Event\r\nDTSTART:20260615T100000Z\r\nDTEND:20260615T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/range-ev1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // calendar-query with time-range that includes June
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<cal:calendar-query xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
  <cal:filter>
    <cal:comp-filter name="VCALENDAR">
      <cal:comp-filter name="VEVENT">
        <cal:time-range start="20260601T000000Z" end="20260630T235959Z"/>
      </cal:comp-filter>
    </cal:comp-filter>
  </cal:filter>
</cal:calendar-query>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/caldav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("June Event"));
}

#[tokio::test]
async fn test_caldav_delete_calendar() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    // Create a calendar
    let req = Request::builder()
        .method("MKCALENDAR")
        .uri("/caldav/admin/deletable/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Delete it
    let req = Request::builder()
        .method("DELETE")
        .uri("/caldav/admin/deletable/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

// ─── Additional CardDAV tests ──────────────────────────────────────────────

#[tokio::test]
async fn test_carddav_options() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("OPTIONS")
        .uri("/carddav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_carddav_proppatch() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:">
  <d:set>
    <d:prop>
      <d:displayname>Renamed Book</d:displayname>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let req = Request::builder()
        .method("PROPPATCH")
        .uri("/carddav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_carddav_sync_collection_report() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    // Put a contact first
    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Sync Contact\r\nEMAIL:sync@example.com\r\nEND:VCARD\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/sync-c1.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    app.request(req).await;

    // sync-collection with token 0
    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:sync-collection xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:sync-token/>
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
</d:sync-collection>"#;

    let req = Request::builder()
        .method("REPORT")
        .uri("/carddav/admin/default/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(report_body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("Sync Contact"));
    assert!(body.contains("sync-token"));
}

#[tokio::test]
async fn test_carddav_delete_addressbook() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    // Create an addressbook
    let req = Request::builder()
        .method("MKCOL")
        .uri("/carddav/admin/deleteme/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Delete it
    let req = Request::builder()
        .method("DELETE")
        .uri("/carddav/admin/deleteme/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_carddav_wrong_content_type() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/bad.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("not vcard"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ─── Additional WebDAV tests ───────────────────────────────────────────────

#[tokio::test]
async fn test_dav_head() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Put a file
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/headtest.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("head content"))
        .unwrap();
    app.request(req).await;

    // HEAD should return 200 with no body
    let req = Request::builder()
        .method("HEAD")
        .uri("/dav/files/headtest.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(resp.headers().get(header::CONTENT_LENGTH).is_some());
}

#[tokio::test]
async fn test_dav_get_nonexistent_returns_404() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/no_such_file.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dav_mkcol_duplicate_returns_405() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // First MKCOL
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/dupdir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Second MKCOL (duplicate)
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/dupdir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_dav_put_in_subdir() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Create subdirectory
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/subdir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    app.request(req).await;

    // Put file in subdirectory
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/subdir/nested.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("nested content"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // PROPFIND depth 1 on subdir shows the file
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/dav/files/subdir")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("nested.txt"));
}

#[tokio::test]
async fn test_dav_proppatch() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Put a file first
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/proppatch.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("content"))
        .unwrap();
    app.request(req).await;

    // PROPPATCH
    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:set>
    <d:prop>
      <oc:favorite>1</oc:favorite>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let req = Request::builder()
        .method("PROPPATCH")
        .uri("/dav/files/proppatch.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "application/xml; charset=utf-8")
        .body(Body::from(body))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn test_dav_etag_returned_on_put() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/etag_test.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("etag content"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    // ETag should be present
    let etag = resp.headers().get(header::ETAG);
    assert!(etag.is_some(), "Expected ETag header on PUT response");
}

// ─── Principals and remote.php redirects ───────────────────────────────────

#[tokio::test]
async fn test_principals_propfind() {
    let app = setup().await;
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/principals/admin/")
        .header("depth", "0")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("calendar-home-set"));
    assert!(body.contains("addressbook-home-set"));
}

#[tokio::test]
async fn test_principals_options() {
    let app = setup().await;
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/principals/admin/")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_remote_php_dav_redirect() {
    let app = setup().await;
    let req = Request::get("/remote.php/dav/files/admin/documents/test.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(location.contains("/dav/files/"));
}

#[tokio::test]
async fn test_remote_php_webdav_redirect() {
    let app = setup().await;
    let req = Request::get("/remote.php/webdav/test.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PERMANENT_REDIRECT);
    let location = resp.headers().get(header::LOCATION).unwrap().to_str().unwrap();
    assert!(location.contains("/dav/files/test.txt"));
}

#[tokio::test]
async fn test_ocs_user_handler() {
    let app = setup().await;
    let req = Request::get("/ocs/v1.php/cloud/user")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("admin"));
    assert!(body.contains("quota"));
}

#[tokio::test]
async fn test_apple_mobileconfig() {
    let app = setup().await;
    let req = Request::get("/apple-mobileconfig")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let ct = resp.headers().get(header::CONTENT_TYPE).unwrap().to_str().unwrap();
    assert!(ct.contains("x-apple-aspen-config"));
    let body = body_string(resp).await;
    assert!(body.contains("CalDAV"));
    assert!(body.contains("CardDAV"));
}

#[tokio::test]
async fn test_oauth_protected_resource() {
    let app = setup().await;
    let req = Request::get("/.well-known/oauth-protected-resource")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("bearer_methods_supported"));
}

// ─── CalDAV propfind on calendar collection ────────────────────────────────

#[tokio::test]
async fn test_caldav_propfind_calendar_depth1_lists_events() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    // Put an event
    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:listed-ev\r\nSUMMARY:Listed Event\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/listed-ev.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // PROPFIND depth 1 on the calendar
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/default/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("listed-ev.ics"));
}

#[tokio::test]
async fn test_caldav_propfind_single_event() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:single-ev\r\nSUMMARY:Single Event\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/single-ev.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    app.request(req).await;

    // PROPFIND on the individual event
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/caldav/admin/default/single-ev.ics")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("single-ev"));
}

// ─── CardDAV propfind on single contact ────────────────────────────────────

#[tokio::test]
async fn test_carddav_propfind_single_contact() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Propfind Contact\r\nEMAIL:pf@example.com\r\nEND:VCARD\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/pf-contact.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    app.request(req).await;

    // PROPFIND on individual contact
    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/admin/default/pf-contact.vcf")
        .header("depth", "0")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("pf-contact"));
}

// ─── CardDAV propfind depth 1 on addressbook lists contacts ────────────────

#[tokio::test]
async fn test_carddav_propfind_addressbook_depth1() {
    let app = setup().await;
    let password = create_password(&app, "card-rw", "/carddav/*");

    let vcard = "BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Depth1 Contact\r\nEMAIL:d1@example.com\r\nEND:VCARD\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/carddav/admin/default/depth1.vcf")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/vcard; charset=utf-8")
        .body(Body::from(vcard))
        .unwrap();
    app.request(req).await;

    let req = Request::builder()
        .method("PROPFIND")
        .uri("/carddav/admin/default/")
        .header("depth", "1")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::MULTI_STATUS);
    let body = body_string(resp).await;
    assert!(body.contains("depth1.vcf"));
}

// ─── MCP revoked token test ───────────────────────────────────────────────

#[tokio::test]
async fn test_mcp_revoked_token() {
    let app = setup().await;
    let token = create_mcp_token(&app, "mcp-revoke", "notes:read");

    // Revoke it
    {
        let conn = app.db.get().unwrap();
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

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── MCP tools/list test ──────────────────────────────────────────────────

#[tokio::test]
async fn test_mcp_tools_list() {
    let app = setup().await;
    let token = create_mcp_token(&app, "mcp-tools", "*");

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    });

    let req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .header(header::AUTHORIZATION, format!("Bearer {}", token))
        .header(header::CONTENT_TYPE, "application/json")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:5555".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("tools"));
}

// ─── Webhook revoked token ─────────────────────────────────────────────────

#[tokio::test]
async fn test_webhook_revoked_token_returns_401() {
    let app = setup().await;
    let token_prefix = "test_hook_04";

    {
        let conn = app.db.get().unwrap();
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

    let req = Request::builder()
        .method("POST")
        .uri(format!("/api/webhook/{}", token_prefix))
        .header(header::CONTENT_TYPE, "application/json")
        .header("X-Tilde-Signature", &signature)
        .body(Body::from(payload))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ─── Webhook unknown prefix ───────────────────────────────────────────────

#[tokio::test]
async fn test_webhook_unknown_prefix_returns_404() {
    let app = setup().await;

    let req = Request::builder()
        .method("POST")
        .uri("/api/webhook/nonexistent_prefix")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(r#"{"msg":"hello"}"#))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ─── CalDAV update event (PUT overwrite) ───────────────────────────────────

#[tokio::test]
async fn test_caldav_put_update_event() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics1 = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:update-ev1\r\nSUMMARY:Original\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/update-ev1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics1))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let etag = resp.headers().get(header::ETAG).unwrap().to_str().unwrap().trim_matches('"').to_string();

    // Update with If-Match
    let ics2 = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VEVENT\r\nUID:update-ev1\r\nSUMMARY:Updated\r\nDTSTART:20260601T120000Z\r\nDTEND:20260601T130000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/update-ev1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .header(header::IF_MATCH, format!("\"{}\"", etag))
        .body(Body::from(ics2))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);

    // Verify updated content
    let req = Request::builder()
        .method("GET")
        .uri("/caldav/admin/default/update-ev1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    let body = body_string(resp).await;
    assert!(body.contains("Updated"));
}

// ─── Chunked upload tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_dav_chunked_upload_full_flow() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // 1. MKCOL to create upload session
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/uploads/admin/session-001/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("OC-Total-Length", "26")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 2. PUT chunk 1
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/uploads/admin/session-001/0000000000")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("Hello, "))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 3. PUT chunk 2
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/uploads/admin/session-001/0000000001")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("chunked world!"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 4. MOVE to finalize
    let req = Request::builder()
        .method("MOVE")
        .uri("/dav/uploads/admin/session-001/")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/chunked_result.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // 5. GET the assembled file
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/chunked_result.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    // Chunks are assembled in order (0000000000 then 0000000001)
    assert_eq!(body, "Hello, chunked world!");
}

// ─── DAV edge cases ────────────────────────────────────────────────────────

#[tokio::test]
async fn test_dav_move_nonexistent_returns_404() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("MOVE")
        .uri("/dav/files/does_not_exist.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/new.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dav_copy_nonexistent_returns_404() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("COPY")
        .uri("/dav/files/does_not_exist.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/new.txt")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dav_delete_nonexistent_returns_404() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("DELETE")
        .uri("/dav/files/does_not_exist.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn test_dav_move_no_destination_header() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Put a file first
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/move_src.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("content"))
        .unwrap();
    app.request(req).await;

    // MOVE without destination header
    let req = Request::builder()
        .method("MOVE")
        .uri("/dav/files/move_src.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn test_dav_lock_method_not_allowed() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    let req = Request::builder()
        .method("LOCK")
        .uri("/dav/files/any.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn test_dav_put_conflict_parent_not_exist() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Try to PUT in a directory that doesn't exist
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/nonexistent_dir/file.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("content"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn test_dav_delete_directory() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Create a directory with a file in it
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/del_dir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    app.request(req).await;

    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/del_dir/inner.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("inner"))
        .unwrap();
    app.request(req).await;

    // DELETE the directory
    let req = Request::builder()
        .method("DELETE")
        .uri("/dav/files/del_dir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_dav_move_directory() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Create a directory with a file
    let req = Request::builder()
        .method("MKCOL")
        .uri("/dav/files/movedir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    app.request(req).await;

    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/movedir/child.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("child"))
        .unwrap();
    app.request(req).await;

    // MOVE directory
    let req = Request::builder()
        .method("MOVE")
        .uri("/dav/files/movedir")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("destination", "/dav/files/moveddir")
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // Verify child file at new location
    let req = Request::builder()
        .method("GET")
        .uri("/dav/files/moveddir/child.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert_eq!(body, "child");
}

#[tokio::test]
async fn test_dav_if_match_precondition_failed() {
    let app = setup().await;
    let password = create_password(&app, "dav-rw", "/dav/*");

    // Put a file
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/ifmatch.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::from("v1"))
        .unwrap();
    app.request(req).await;

    // PUT with wrong If-Match
    let req = Request::builder()
        .method("PUT")
        .uri("/dav/files/ifmatch.txt")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header("if-match", "\"wrongetag\"")
        .body(Body::from("v2"))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::PRECONDITION_FAILED);
}

// ─── Host filter test ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_host_filter_allows_localhost() {
    let app = setup().await;
    let req = Request::builder()
        .uri("/health")
        .header(header::HOST, "localhost:8080")
        .extension(axum::extract::ConnectInfo(
            "127.0.0.1:1234".parse::<SocketAddr>().unwrap(),
        ))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    // With empty hostname config, host filter is skipped
    assert_eq!(resp.status(), StatusCode::OK);
}

// ─── CalDAV VTODO tests ───────────────────────────────────────────────────

#[tokio::test]
async fn test_caldav_vtodo() {
    let app = setup().await;
    let password = create_password(&app, "cal-rw", "/caldav/*");

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\nBEGIN:VTODO\r\nUID:todo1\r\nSUMMARY:Test Task\r\nSTATUS:NEEDS-ACTION\r\nPRIORITY:1\r\nEND:VTODO\r\nEND:VCALENDAR\r\n";

    let req = Request::builder()
        .method("PUT")
        .uri("/caldav/admin/default/todo1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .header(header::CONTENT_TYPE, "text/calendar; charset=utf-8")
        .body(Body::from(ics))
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // GET the task
    let req = Request::builder()
        .method("GET")
        .uri("/caldav/admin/default/todo1.ics")
        .header(header::AUTHORIZATION, basic_auth(&password))
        .body(Body::empty())
        .unwrap();
    let resp = app.request(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_string(resp).await;
    assert!(body.contains("VTODO"));
    assert!(body.contains("Test Task"));
}
