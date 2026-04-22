//! tilde-server: axum app assembly and HTTP routing

use axum::{
    Router,
    extract::State,
    http::{StatusCode, header, HeaderValue},
    response::{IntoResponse, Json},
    routing::get,
};
use rusqlite::Connection;
use serde_json::json;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tower_http::trace::TraceLayer;
use tilde_core::config::Config;

/// Shared application state
pub struct AppState {
    pub config: Config,
    pub db: Mutex<Connection>,
    pub start_time: Instant,
}

pub type SharedState = Arc<AppState>;

/// Build the axum router with all routes
pub fn build_router(state: SharedState) -> Router {
    Router::new()
        // Operational endpoints
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        // Nextcloud compatibility stubs
        .route("/status.php", get(status_php_handler))
        .route("/ocs/v2.php/cloud/capabilities", get(ocs_capabilities_handler))
        // Well-known redirects
        .route("/.well-known/caldav", get(well_known_caldav))
        .route("/.well-known/carddav", get(well_known_carddav))
        // Middleware
        .layer(TraceLayer::new_for_http())
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

/// GET /metrics — Prometheus metrics (minimal stub)
async fn metrics_handler(State(state): State<SharedState>) -> impl IntoResponse {
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
    )
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
