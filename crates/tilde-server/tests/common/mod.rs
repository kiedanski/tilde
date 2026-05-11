//! Shared test fixtures for tilde-server integration tests.
//!
//! Provides a `TestServer` backed by a temporary SQLite DB and filesystem,
//! along with helpers for creating app passwords and MCP tokens.

// Suppress dead_code warnings since not all test files use every helper.
#![allow(dead_code)]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum_test::TestServer;
use tilde_core::{auth, config::Config, db};

/// A fully-configured test environment containing:
/// - A `TestServer` ready to handle requests
/// - A DB pool for direct database manipulation in tests
/// - A `TempDir` that keeps the filesystem alive for the test's duration
pub struct TestEnv {
    pub server: TestServer,
    pub pool: db::DbPool,
    pub _dir: tempfile::TempDir,
}

/// Create a fresh test server with an empty database and filesystem.
///
/// Returns a `TestEnv` with everything wired up. The temp directory is
/// automatically cleaned up when the `TestEnv` is dropped.
pub fn create_test_server() -> TestEnv {
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

    let state: tilde_server::SharedState = Arc::new(tilde_server::AppState {
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
        allowed_symlink_targets: vec![],
        cache_dir: None,
    });

    let caldav_state: tilde_cal::SharedCalDavState =
        Arc::new(tilde_cal::CalDavState { db: pool.clone() });

    let carddav_state: tilde_card::SharedCardDavState =
        Arc::new(tilde_card::CardDavState { db: pool.clone() });

    let router = tilde_server::build_router(state, dav_state, caldav_state, carddav_state);

    // Use HTTP transport so ConnectInfo<SocketAddr> is available for handlers that need it
    let app = router.into_make_service_with_connect_info::<SocketAddr>();
    let server = TestServer::builder().http_transport().build(app);

    TestEnv {
        server,
        pool,
        _dir: dir,
    }
}

/// Create an app password scoped to the given prefix. Returns the raw password string.
pub fn create_app_password(pool: &db::DbPool, name: &str, scope: &str) -> String {
    let conn = pool.get().unwrap();
    auth::create_app_password(&conn, name, scope).unwrap()
}

/// Create an MCP bearer token. Returns the raw token string.
pub fn create_mcp_token(pool: &db::DbPool, name: &str, scopes: &str) -> String {
    let conn = pool.get().unwrap();
    auth::create_mcp_token(&conn, name, scopes, 100).unwrap()
}

/// Format a Basic auth header value for the given password (user is always "admin").
pub fn basic_auth_header(password: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", password));
    format!("Basic {}", encoded)
}
