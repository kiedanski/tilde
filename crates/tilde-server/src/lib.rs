//! tilde-server: axum app assembly and HTTP routing

pub mod tunnel;

use axum::{
    Router,
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{HeaderValue, Method, Request, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Json, Redirect},
    routing::{any, get, post},
};
use serde_json::json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tilde_core::{auth, config::Config, db::DbPool};
use tower_http::{compression::CompressionLayer, cors::CorsLayer, trace::TraceLayer};

/// Shared application state
pub struct AppState {
    pub config: arc_swap::ArcSwap<Config>,
    pub db: DbPool,
    pub start_time: Instant,
    pub mcp_state: tilde_mcp::SharedMcpState,
    pub tunnel_status: Option<tunnel::SharedTunnelStatus>,
}

impl AppState {
    /// Load the current configuration snapshot.
    /// The returned guard auto-derefs to `Config`.
    pub fn config(&self) -> arc_swap::Guard<Arc<Config>> {
        self.config.load()
    }
}

pub type SharedState = Arc<AppState>;

/// Build the axum router with all routes
pub fn build_router(
    state: SharedState,
    dav_state: tilde_dav::SharedDavState,
    caldav_state: tilde_cal::SharedCalDavState,
    carddav_state: tilde_card::SharedCardDavState,
) -> Router {
    // WebDAV routes
    let dav_router = tilde_dav::build_dav_router(dav_state.clone());
    let uploads_router = tilde_dav::build_uploads_router(dav_state.clone());

    // Notes DAV — separate DavState pointing to notes directory (sibling of files, like photos)
    let notes_root = dav_state
        .files_root
        .parent()
        .map(|p| p.join("notes"))
        .unwrap_or_else(|| dav_state.files_root.join("../notes"));
    let notes_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: dav_state.db.clone(),
        files_root: notes_root,
        uploads_root: dav_state.uploads_root.clone(),
        db_path_prefix: "notes/".to_string(),
        scope_prefix: "/dav/".to_string(),
        organization_pattern: String::new(),
        allowed_symlink_targets: vec![],
    });
    let notes_router = tilde_dav::build_dav_router(notes_state);

    // Photos DAV — points to photos directory under data dir
    let photos_root = dav_state
        .files_root
        .parent()
        .map(|p| p.join("photos"))
        .unwrap_or_else(|| dav_state.files_root.join("../photos"));
    let cache_thumbnails_dir = state.config().cache_dir().join("thumbnails");
    let photos_state: tilde_dav::SharedDavState = Arc::new(tilde_dav::DavState {
        db: dav_state.db.clone(),
        files_root: photos_root,
        uploads_root: dav_state.uploads_root.clone(),
        db_path_prefix: "photos/".to_string(),
        scope_prefix: "/dav/".to_string(),
        organization_pattern: state.config().photos.organization_pattern.clone(),
        allowed_symlink_targets: vec![cache_thumbnails_dir],
    });
    let photos_router = tilde_dav::build_dav_router(photos_state);

    // CalDAV and CardDAV routers
    let caldav_router = tilde_cal::build_caldav_router(caldav_state);
    let carddav_router = tilde_card::build_carddav_router(carddav_state);

    Router::new()
        // Root PROPFIND for DAV client discovery (DAVx5, etc.)
        .route("/", any(root_propfind_handler))
        // Public endpoints
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/status.php", get(status_php_handler))
        .route(
            "/ocs/v2.php/cloud/capabilities",
            get(ocs_capabilities_handler),
        )
        .route(
            "/ocs/v1.php/cloud/capabilities",
            get(ocs_capabilities_handler),
        )
        .route("/ocs/v1.php/cloud/user", get(ocs_user_handler))
        .route("/ocs/v2.php/cloud/user", get(ocs_user_handler))
        .route("/.well-known/caldav", any(well_known_caldav))
        .route("/.well-known/carddav", any(well_known_carddav))
        // Apple .mobileconfig profile for easy iOS/macOS CalDAV+CardDAV setup
        .route("/apple-mobileconfig", get(apple_mobileconfig_handler))
        // Nextcloud compat redirects
        .route("/remote.php/dav/{*path}", any(remote_php_dav_redirect))
        .route(
            "/remote.php/webdav/{*path}",
            any(remote_php_webdav_redirect),
        )
        // MCP endpoint
        .route("/mcp/", post(mcp_handler))
        .route("/mcp", post(mcp_handler))
        // OAuth Protected Resource Metadata (RFC 9728 stub)
        .route(
            "/.well-known/oauth-protected-resource",
            get(oauth_protected_resource),
        )
        // Webhook endpoint
        .route("/api/webhook/{token_prefix}", post(webhook_handler))
        // Principals (RFC 5397)
        .route("/principals/{*path}", any(principals_handler))
        // CalDAV and CardDAV
        .nest_service("/caldav", caldav_router)
        .nest_service("/carddav", carddav_router)
        // WebDAV
        .nest_service("/dav/files", dav_router)
        .nest_service("/dav/notes", notes_router)
        .nest_service("/dav/photos", photos_router)
        .nest_service("/dav/uploads", uploads_router)
        // Middleware
        .layer(
            CorsLayer::new()
                .allow_origin([
                    "app://obsidian.md".parse().unwrap(),
                    "capacitor://localhost".parse().unwrap(),
                    "http://localhost".parse().unwrap(),
                ])
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any)
                .expose_headers(tower_http::cors::Any),
        )
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn(add_request_id))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            host_filter_middleware,
        ))
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(state)
}

/// Add X-Request-Id header to all requests/responses
async fn add_request_id(req: Request<axum::body::Body>, next: Next) -> axum::response::Response {
    let request_id = uuid::Uuid::new_v4().to_string();
    let mut response = next.run(req).await;
    response.headers_mut().insert(
        header::HeaderName::from_static("x-request-id"),
        HeaderValue::from_str(&request_id).unwrap(),
    );
    response
}

/// Add security headers to all responses
async fn add_security_headers(mut response: axum::response::Response) -> axum::response::Response {
    let headers = response.headers_mut();
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains; preload"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

/// GET /health — Health check endpoint
async fn health_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let uptime_secs = state.start_time.elapsed().as_secs();

    // Check database connectivity
    let db_status = match state.db.get() {
        Ok(conn) => match conn.query_row("SELECT 1", [], |_| Ok(())) {
            Ok(_) => "ok",
            Err(_) => "error",
        },
        Err(_) => "error",
    };

    let tunnel = state.tunnel_status.as_ref().map(|ts| {
        json!({
            "status": ts.summary(),
            "connected": ts.connected.load(std::sync::atomic::Ordering::Relaxed),
            "consecutive_ping_failures": ts.consecutive_ping_failures.load(std::sync::atomic::Ordering::Relaxed),
            "restart_count": ts.restart_count.load(std::sync::atomic::Ordering::Relaxed),
            "last_connected_at": ts.last_connected_at.load(std::sync::atomic::Ordering::Relaxed),
        })
    });

    let body = json!({
        "status": if db_status == "ok" { "healthy" } else { "unhealthy" },
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_secs,
        "database": db_status,
        "tunnel": tunnel,
    });

    let status = if db_status == "ok" {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (status, Json(body))
}

/// GET /metrics — Prometheus metrics (localhost-only)
async fn metrics_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> axum::response::Response {
    if !addr.ip().is_loopback() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "metrics endpoint is localhost-only"})),
        )
            .into_response();
    }
    let uptime = state.start_time.elapsed().as_secs();

    let db_size = state
        .config()
        .db_path()
        .metadata()
        .map(|m| m.len())
        .unwrap_or(0);

    let metrics = format!(
        "# HELP tilde_uptime_seconds Server uptime in seconds\n\
         # TYPE tilde_uptime_seconds gauge\n\
         tilde_uptime_seconds {}\n\
         # HELP tilde_db_size_bytes SQLite database file size\n\
         # TYPE tilde_db_size_bytes gauge\n\
         tilde_db_size_bytes {}\n",
        uptime, db_size
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        metrics,
    )
        .into_response()
}

/// GET /status.php — Nextcloud status stub
async fn status_php_handler() -> impl IntoResponse {
    Json(json!({
        "installed": true,
        "maintenance": false,
        "needsDbUpgrade": false,
        "version": "28.0.0.0",
        "versionstring": "28.0.0",
        "edition": "",
        "productname": "tilde",
        "extendedSupport": false
    }))
}

/// GET /ocs/v2.php/cloud/capabilities — OCS capabilities stub
async fn ocs_capabilities_handler() -> impl IntoResponse {
    Json(json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 200,
                "message": "OK"
            },
            "data": {
                "version": {
                    "major": 28,
                    "minor": 0,
                    "micro": 0,
                    "string": "28.0.0",
                    "edition": "",
                    "extendedSupport": false
                },
                "capabilities": {
                    "dav": {
                        "chunking": "1.0",
                        "bulkupload": "1.0"
                    },
                    "files": {
                        "bigfilechunking": true,
                        "versioning": false
                    }
                }
            }
        }
    }))
}

/// GET /ocs/v1.php/cloud/user — OCS user info stub for Nextcloud client
async fn ocs_user_handler() -> impl IntoResponse {
    Json(json!({
        "ocs": {
            "meta": {
                "status": "ok",
                "statuscode": 200,
                "message": "OK"
            },
            "data": {
                "id": "admin",
                "display-name": "admin",
                "email": "",
                "quota": {
                    "free": 10_000_000_000_i64,
                    "used": 0,
                    "total": 10_000_000_000_i64,
                    "relative": 0.0,
                    "quota": -3
                }
            }
        }
    }))
}

/// PROPFIND / — Root handler for DAV client discovery (DAVx5, etc.)
async fn root_propfind_handler(method: Method) -> axum::response::Response {
    if method.as_str() == "PROPFIND" {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>/</d:href>
    <d:propstat>
      <d:prop>
        <d:current-user-principal>
          <d:href>/principals/admin/</d:href>
        </d:current-user-principal>
        <d:resourcetype>
          <d:collection/>
        </d:resourcetype>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;
        return (
            StatusCode::MULTI_STATUS,
            [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
            xml.to_string(),
        )
            .into_response();
    }
    // For GET /, return a simple redirect or empty response
    StatusCode::NO_CONTENT.into_response()
}

/// GET /.well-known/caldav — Redirect to /caldav/
async fn well_known_caldav() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/caldav/")],
    )
}

/// GET /.well-known/carddav — Redirect to /carddav/
async fn well_known_carddav() -> impl IntoResponse {
    (
        StatusCode::MOVED_PERMANENTLY,
        [(header::LOCATION, "/carddav/")],
    )
}

/// GET /apple-mobileconfig — Generate Apple .mobileconfig profile for CalDAV + CardDAV
async fn apple_mobileconfig_handler(State(state): State<SharedState>) -> axum::response::Response {
    let cfg = state.config();
    let hostname = if cfg.server.hostname.is_empty() {
        "localhost".to_string()
    } else {
        cfg.server.hostname.clone()
    };

    let profile_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let caldav_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();
    let carddav_uuid = uuid::Uuid::new_v4().to_string().to_uppercase();

    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>CalDAVAccountDescription</key>
            <string>tilde CalDAV</string>
            <key>CalDAVHostName</key>
            <string>{hostname}</string>
            <key>CalDAVPort</key>
            <integer>443</integer>
            <key>CalDAVPrincipalURL</key>
            <string>/caldav/admin/</string>
            <key>CalDAVUseSSL</key>
            <true/>
            <key>PayloadDescription</key>
            <string>CalDAV account for tilde</string>
            <key>PayloadDisplayName</key>
            <string>tilde CalDAV</string>
            <key>PayloadIdentifier</key>
            <string>com.tilde.caldav.{caldav_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.caldav.account</string>
            <key>PayloadUUID</key>
            <string>{caldav_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
        <dict>
            <key>CardDAVAccountDescription</key>
            <string>tilde CardDAV</string>
            <key>CardDAVHostName</key>
            <string>{hostname}</string>
            <key>CardDAVPort</key>
            <integer>443</integer>
            <key>CardDAVPrincipalURL</key>
            <string>/carddav/admin/</string>
            <key>CardDAVUseSSL</key>
            <true/>
            <key>PayloadDescription</key>
            <string>CardDAV account for tilde</string>
            <key>PayloadDisplayName</key>
            <string>tilde CardDAV</string>
            <key>PayloadIdentifier</key>
            <string>com.tilde.carddav.{carddav_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.carddav.account</string>
            <key>PayloadUUID</key>
            <string>{carddav_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Configure CalDAV and CardDAV accounts for tilde personal cloud</string>
    <key>PayloadDisplayName</key>
    <string>tilde — {hostname}</string>
    <key>PayloadIdentifier</key>
    <string>com.tilde.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>tilde</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"#,
        hostname = hostname,
        profile_uuid = profile_uuid,
        caldav_uuid = caldav_uuid,
        carddav_uuid = carddav_uuid,
    );

    (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                "application/x-apple-aspen-config; charset=utf-8",
            ),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"tilde.mobileconfig\"",
            ),
        ],
        xml,
    )
        .into_response()
}

/// /remote.php/dav/* → redirect to /dav/*
/// Strips Nextcloud-style username prefix: /remote.php/dav/files/admin/foo → /dav/files/foo
async fn remote_php_dav_redirect(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    let stripped = if let Some(after_files) = path.strip_prefix("files/") {
        // Strip username segment: files/<user>/rest → files/rest
        if let Some(pos) = after_files.find('/') {
            format!("files/{}", &after_files[pos + 1..])
        } else {
            // files/<user> with no trailing path — map to files root
            "files/".to_string()
        }
    } else {
        path
    };
    Redirect::permanent(&format!("/dav/{}", stripped))
}

/// /remote.php/webdav/* → redirect to /dav/files/*
async fn remote_php_webdav_redirect(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    Redirect::permanent(&format!("/dav/files/{}", path))
}

/// PROPFIND /principals/<user>/ — current-user-principal (RFC 5397)
async fn principals_handler(
    method: Method,
    path: Option<AxumPath<String>>,
) -> axum::response::Response {
    if method == Method::OPTIONS {
        return axum::response::Response::builder()
            .status(StatusCode::OK)
            .header("Allow", "OPTIONS, PROPFIND")
            .header("DAV", "1, 2, 3, calendar-access, addressbook")
            .body(axum::body::Body::empty())
            .unwrap()
            .into_response();
    }

    if method.as_str() != "PROPFIND" {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let _path = path.map(|AxumPath(p)| p).unwrap_or_default();

    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/principals/admin/</d:href>
    <d:propstat>
      <d:prop>
        <d:current-user-principal>
          <d:href>/principals/admin/</d:href>
        </d:current-user-principal>
        <d:resourcetype>
          <d:principal/>
        </d:resourcetype>
        <cal:calendar-home-set>
          <d:href>/caldav/admin/</d:href>
        </cal:calendar-home-set>
        <card:addressbook-home-set>
          <d:href>/carddav/admin/</d:href>
        </card:addressbook-home-set>
      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml.to_string(),
    )
        .into_response()
}

/// Host header filter — reject requests for unknown hostnames
async fn host_filter_middleware(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let cfg = state.config();
    let configured_hostname = &cfg.server.hostname;

    // Skip host filtering if no hostname is configured
    if configured_hostname.is_empty() {
        return Ok(next.run(req).await);
    }

    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            // Strip port from Host header if present
            h.split(':').next().unwrap_or(h)
        });

    match host {
        Some(h) if h == configured_hostname || h == "localhost" || h == "127.0.0.1" => {
            Ok(next.run(req).await)
        }
        _ => {
            tracing::warn!(
                host = ?host,
                expected = configured_hostname,
                "Rejected request with unknown Host header"
            );
            Err(StatusCode::FORBIDDEN)
        }
    }
}

/// GET /.well-known/oauth-protected-resource — OAuth Protected Resource Metadata (RFC 9728 stub)
async fn oauth_protected_resource(State(state): State<SharedState>) -> impl IntoResponse {
    let cfg = state.config();
    let resource = if cfg.server.hostname.is_empty() {
        "http://localhost".to_string()
    } else {
        format!("https://{}", cfg.server.hostname)
    };

    Json(json!({
        "resource": resource,
        "bearer_methods_supported": ["header"],
        "resource_documentation": "Use CLI-issued bearer tokens: tilde mcp token create --name <name> --scopes <scopes>",
        "resource_signing_alg_values_supported": []
    }))
}

// ─── MCP Streamable HTTP endpoint ────────────────────────────────────────

/// POST /mcp/ — MCP Streamable HTTP endpoint (JSON-RPC 2.0)
async fn mcp_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request<axum::body::Body>,
) -> axum::response::Response {
    // Extract auth header before consuming the request
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let source_ip = addr.ip().to_string();

    // Authenticate — must be a valid MCP token
    let (token_name, token_scopes, rate_limit) = match auth_header {
        Some(ref h) if h.starts_with("Bearer mcp_prod_") => {
            let token = &h[7..];
            let db = state.db.get().unwrap();
            match auth::validate_mcp_token(&db, token) {
                Ok(Some((name, scopes))) => {
                    // Get rate limit for this token
                    let rl = db
                        .query_row(
                            "SELECT rate_limit FROM mcp_tokens WHERE token_hash = ?1",
                            [&auth::hash_token(token)],
                            |row| row.get::<_, u32>(0),
                        )
                        .unwrap_or(state.config().mcp.default_rate_limit);
                    (name, scopes, rl)
                }
                _ => {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": "invalid or revoked token"}})),
                    ).into_response();
                }
            }
        }
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                [(header::WWW_AUTHENTICATE, "Bearer")],
                Json(json!({"jsonrpc": "2.0", "error": {"code": -32000, "message": "MCP bearer token required"}})),
            ).into_response();
        }
    };

    // Read body
    let body = match axum::body::to_bytes(req.into_body(), 1_048_576).await {
        Ok(b) => b,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                Json(json!({"jsonrpc": "2.0", "error": {"code": -32700, "message": "request too large"}})),
            ).into_response();
        }
    };

    // Parse JSON-RPC request
    let rpc_request: tilde_mcp::JsonRpcRequest = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"jsonrpc": "2.0", "id": null, "error": {"code": -32700, "message": format!("parse error: {}", e)}})),
            ).into_response();
        }
    };

    let response = tilde_mcp::handle_mcp_request(
        &state.mcp_state,
        &rpc_request,
        &token_name,
        &token_scopes,
        rate_limit,
        &source_ip,
        state.config().mcp.audit_log_retention_days,
    );

    (StatusCode::OK, Json(json!(response))).into_response()
}

// ─── Webhook endpoint ────────────────────────────────────────────────────

/// POST /api/webhook/<token_prefix> — Inbound webhook handler
async fn webhook_handler(
    State(state): State<SharedState>,
    AxumPath(token_prefix): AxumPath<String>,
    headers: axum::http::HeaderMap,
    raw_body: axum::body::Bytes,
) -> axum::response::Response {
    // Look up token by prefix
    let db = state.db.get().unwrap();

    let result = db.query_row(
        "SELECT name, scopes, rate_limit, revoked, hmac_secret FROM webhook_tokens WHERE token_prefix = ?1",
        [&token_prefix],
        |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, i32>(2)?,
                row.get::<_, bool>(3)?,
                row.get::<_, Option<String>>(4)?,
            ))
        },
    );

    let (name, scopes, _rate_limit, revoked, hmac_secret) = match result {
        Ok(r) => r,
        Err(_) => {
            return (
                StatusCode::NOT_FOUND,
                Json(json!({"error": "unknown webhook token"})),
            )
                .into_response();
        }
    };

    if revoked {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "webhook token revoked"})),
        )
            .into_response();
    }

    // HMAC verification: require a secret and valid signature
    if hmac_secret.is_none() {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({"error": "webhook has no HMAC secret configured — refusing unauthenticated payload"})),
        )
            .into_response();
    }
    if let Some(ref secret) = hmac_secret {
        let signature = headers
            .get("X-Tilde-Signature")
            .and_then(|v| v.to_str().ok());

        match signature {
            Some(sig) => {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;
                type HmacSha256 = Hmac<Sha256>;

                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .expect("HMAC accepts any key length");
                mac.update(&raw_body);
                let expected = hex::encode(mac.finalize().into_bytes());
                let provided = sig.strip_prefix("sha256=").unwrap_or(sig);

                if !constant_time_eq(expected.as_bytes(), provided.as_bytes()) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        Json(json!({"error": "invalid signature"})),
                    )
                        .into_response();
                }
            }
            None => {
                return (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({"error": "X-Tilde-Signature header required"})),
                )
                    .into_response();
            }
        }
    }

    // Parse body as JSON
    let body: serde_json::Value = match serde_json::from_slice(&raw_body) {
        Ok(v) => v,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid JSON body"})),
            )
                .into_response();
        }
    };

    // Update last_used_at
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db.execute(
        "UPDATE webhook_tokens SET last_used_at = ?1 WHERE token_prefix = ?2",
        rusqlite::params![now, token_prefix],
    );

    // Process based on scopes
    // Scopes like "tracker:weight:write" or "calendar:default:write"
    let scope_parts: Vec<&str> = scopes.split(':').collect();

    if scope_parts.first() == Some(&"tracker") && scope_parts.len() >= 2 {
        let collection_name = scope_parts[1];

        // Look up collection
        let collection_result = db.query_row(
            "SELECT id, schema_json FROM collections WHERE name = ?1",
            [collection_name],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        );

        match collection_result {
            Ok((collection_id, _schema_json)) => {
                let id = uuid::Uuid::new_v4().to_string();
                let data_str = serde_json::to_string(&body).unwrap_or_default();

                let result = db.execute(
                    "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    rusqlite::params![id, collection_id, data_str, now, now, now],
                );

                match result {
                    Ok(_) => {
                        tracing::info!(webhook = %name, collection = collection_name, "Webhook data ingested");
                        (StatusCode::OK, Json(json!({"id": id, "status": "ok"}))).into_response()
                    }
                    Err(e) => (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({"error": e.to_string()})),
                    )
                        .into_response(),
                }
            }
            Err(_) => (
                StatusCode::NOT_FOUND,
                Json(json!({"error": format!("collection '{}' not found", collection_name)})),
            )
                .into_response(),
        }
    } else {
        // Generic webhook — just log it
        tracing::info!(webhook = %name, scopes = %scopes, "Webhook received");
        (
            StatusCode::OK,
            Json(json!({"status": "ok", "webhook": name})),
        )
            .into_response()
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
