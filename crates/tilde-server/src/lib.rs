//! tilde-server: axum app assembly and HTTP routing

use axum::{
    Router,
    extract::{ConnectInfo, Path as AxumPath, State},
    http::{StatusCode, header, HeaderValue, Request},
    middleware::Next,
    response::{IntoResponse, Json, Redirect},
    routing::{any, get, post},
};
use base64::Engine;
use rusqlite::Connection;
use serde_json::json;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::trace::TraceLayer;
use tilde_core::{config::Config, auth};
use tilde_dav;

/// Per-IP rate limit tracking for auth endpoints
#[derive(Debug, Clone)]
pub struct RateLimitEntry {
    pub attempts: Vec<Instant>,
}

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub db: Arc<Mutex<Connection>>,
    pub start_time: Instant,
    pub login_attempts: Mutex<HashMap<String, RateLimitEntry>>,
}

pub type SharedState = Arc<AppState>;

/// Build the axum router with all routes
pub fn build_router(state: SharedState, dav_state: tilde_dav::SharedDavState) -> Router {
    // Routes that require authentication
    let authenticated = Router::new()
        .route("/api/auth/verify", get(auth_verify_handler))
        .route("/api/auth/session", get(session_info_handler))
        .layer(axum::middleware::from_fn_with_state(state.clone(), auth_middleware));

    // WebDAV routes
    let dav_router = tilde_dav::build_dav_router(dav_state);

    Router::new()
        // Public endpoints
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .route("/status.php", get(status_php_handler))
        .route("/ocs/v2.php/cloud/capabilities", get(ocs_capabilities_handler))
        .route("/.well-known/caldav", get(well_known_caldav))
        .route("/.well-known/carddav", get(well_known_carddav))
        // Nextcloud compat redirects
        .route("/remote.php/dav/{*path}", any(remote_php_dav_redirect))
        .route("/remote.php/webdav/{*path}", any(remote_php_webdav_redirect))
        // Auth endpoints (public)
        .route("/api/auth/login", post(login_handler))
        // Authenticated routes
        .merge(authenticated)
        // WebDAV
        .nest_service("/dav/files", dav_router)
        // Middleware
        .layer(TraceLayer::new_for_http())
        .layer(axum::middleware::from_fn_with_state(state.clone(), host_filter_middleware))
        .layer(axum::middleware::map_response(add_security_headers))
        .with_state(state)
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
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    response
}

/// GET /health — Health check endpoint
async fn health_handler(State(state): State<SharedState>) -> impl IntoResponse {
    let uptime_secs = state.start_time.elapsed().as_secs();

    // Check database connectivity
    let db_status = match state.db.lock() {
        Ok(conn) => {
            match conn.query_row("SELECT 1", [], |_| Ok(())) {
                Ok(_) => "ok",
                Err(_) => "error",
            }
        }
        Err(_) => "error",
    };

    let body = json!({
        "status": if db_status == "ok" { "healthy" } else { "unhealthy" },
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_seconds": uptime_secs,
        "database": db_status,
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
        return (StatusCode::FORBIDDEN, Json(json!({"error": "metrics endpoint is localhost-only"}))).into_response();
    }
    let uptime = state.start_time.elapsed().as_secs();

    let db_size = state.config.db_path()
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
    ).into_response()
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

/// GET /.well-known/caldav — Redirect to /caldav/
async fn well_known_caldav() -> impl IntoResponse {
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "/caldav/")])
}

/// GET /.well-known/carddav — Redirect to /carddav/
async fn well_known_carddav() -> impl IntoResponse {
    (StatusCode::MOVED_PERMANENTLY, [(header::LOCATION, "/carddav/")])
}

/// POST /api/auth/login — Authenticate with admin password, returns session token
async fn login_handler(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(body): Json<serde_json::Value>,
) -> axum::response::Response {
    let password = match body.get("password").and_then(|v| v.as_str()) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, Json(json!({"error": "password required"}))).into_response(),
    };

    let client_ip = body.get("source_ip")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| addr.ip().to_string());

    let max_attempts = state.config.auth.max_login_attempts;
    let lockout_minutes = state.config.auth.lockout_duration_minutes;
    let window = std::time::Duration::from_secs(lockout_minutes as u64 * 60);

    // Check rate limit
    {
        let mut attempts = state.login_attempts.lock().unwrap();
        if let Some(entry) = attempts.get_mut(&client_ip) {
            let now = Instant::now();
            entry.attempts.retain(|t| now.duration_since(*t) < window);
            if entry.attempts.len() >= max_attempts as usize {
                let oldest = entry.attempts.first().unwrap();
                let retry_after = window.as_secs() - now.duration_since(*oldest).as_secs();
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    [(header::HeaderName::from_static("retry-after"),
                      HeaderValue::from_str(&retry_after.to_string()).unwrap())],
                    Json(json!({"error": "too many login attempts", "retry_after_seconds": retry_after})),
                ).into_response();
            }
        }
    }

    let user_agent = body.get("user_agent").and_then(|v| v.as_str());
    let db = state.db.lock().unwrap();

    match auth::verify_admin_password(&db, password) {
        Ok(true) => {
            // Clear rate limit on success
            {
                let mut attempts = state.login_attempts.lock().unwrap();
                attempts.remove(&client_ip);
            }
            match auth::create_session(&db, user_agent, Some(&client_ip), state.config.auth.session_ttl_hours) {
                Ok(token) => (StatusCode::OK, Json(json!({
                    "token": token,
                    "token_prefix": &token[..std::cmp::min(22, token.len())],
                    "expires_in_hours": state.config.auth.session_ttl_hours,
                }))).into_response(),
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
            }
        }
        Ok(false) => {
            // Record failed attempt
            {
                let mut attempts = state.login_attempts.lock().unwrap();
                let entry = attempts.entry(client_ip.clone()).or_insert(RateLimitEntry {
                    attempts: Vec::new(),
                });
                entry.attempts.push(Instant::now());
            }
            tracing::warn!(ip = %client_ip, "Failed login attempt");
            (StatusCode::UNAUTHORIZED, Json(json!({"error": "invalid password"}))).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({"error": e.to_string()}))).into_response(),
    }
}

/// Auth middleware — checks Bearer token (session or MCP) or Basic auth (app password)
async fn auth_middleware(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let authenticated = match auth_header {
        Some(ref h) if h.starts_with("Bearer ") => {
            let token = &h[7..];
            let db = state.db.lock().unwrap();
            if token.starts_with("tilde_session_") {
                auth::validate_session(&db, token, state.config.auth.session_ttl_hours)
                    .unwrap_or(false)
            } else if token.starts_with("mcp_prod_") {
                auth::validate_mcp_token(&db, token)
                    .map(|opt| opt.is_some())
                    .unwrap_or(false)
            } else {
                false
            }
        }
        Some(ref h) if h.starts_with("Basic ") => {
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(&h[6..])
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok());
            if let Some(creds) = decoded {
                if let Some((_user, password)) = creds.split_once(':') {
                    let path = req.uri().path().to_string();
                    let db = state.db.lock().unwrap();
                    auth::verify_app_password(&db, password, &path).unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    };

    if authenticated {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

/// GET /api/auth/verify — Simple auth verification endpoint
async fn auth_verify_handler() -> impl IntoResponse {
    Json(json!({"authenticated": true}))
}

/// GET /api/auth/session — Get session info (requires auth)
async fn session_info_handler(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
) -> impl IntoResponse {
    let auth_header = req.headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok());

    if let Some(h) = auth_header {
        if h.starts_with("Bearer ") && h[7..].starts_with("tilde_session_") {
            let token = &h[7..];
            let token_hash = auth::hash_token(token);
            let db = state.db.lock().unwrap();
            let result = db.query_row(
                "SELECT token_prefix, created_at, last_used_at, expires_at FROM auth_sessions WHERE id = ?1",
                [&token_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                    ))
                },
            );
            match result {
                Ok((prefix, created, last_used, expires)) => {
                    return Json(json!({
                        "token_prefix": prefix,
                        "created_at": created,
                        "last_used_at": last_used,
                        "expires_at": expires,
                    }));
                }
                Err(_) => {}
            }
        }
    }
    Json(json!({"error": "session info unavailable"}))
}

/// /remote.php/dav/* → redirect to /dav/*
async fn remote_php_dav_redirect(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    Redirect::permanent(&format!("/dav/{}", path))
}

/// /remote.php/webdav/* → redirect to /dav/files/*
async fn remote_php_webdav_redirect(AxumPath(path): AxumPath<String>) -> impl IntoResponse {
    Redirect::permanent(&format!("/dav/files/{}", path))
}

/// Host header filter — reject requests for unknown hostnames
async fn host_filter_middleware(
    State(state): State<SharedState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<axum::response::Response, StatusCode> {
    let configured_hostname = &state.config.server.hostname;

    // Skip host filtering if no hostname is configured
    if configured_hostname.is_empty() {
        return Ok(next.run(req).await);
    }

    let host = req.headers()
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
