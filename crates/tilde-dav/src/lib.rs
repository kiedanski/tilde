//! tilde-dav: WebDAV Class 1 file serving
//!
//! Handles OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
pub mod versions;

use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use tilde_core::auth;
use tilde_core::db::DbPool;
use tracing::{info, warn};
use uuid::Uuid;

/// State needed by DAV handlers
pub struct DavState {
    pub db: DbPool,
    pub files_root: PathBuf,
    pub uploads_root: PathBuf,
    /// Prefix to add to rel_path for DB lookups (e.g., "photos/" for the photos router)
    pub db_path_prefix: String,
    /// The scope prefix used for app-password authorization (e.g., "/dav/")
    pub scope_prefix: String,
    /// Photo organization pattern (only used by photos mount)
    pub organization_pattern: String,
    /// Extra directories that symlinks are allowed to resolve into.
    /// Used by the photos mount to allow thumbnail symlinks pointing to the cache dir.
    pub allowed_symlink_targets: Vec<PathBuf>,
    /// Cache directory for thumbnails. When set (photos mount), DELETE will
    /// clean up thumbnails and photo DB records alongside the file.
    pub cache_dir: Option<PathBuf>,
    /// Content-addressed store of overwritten file versions, shared by all
    /// mounts. Supplies the base version for three-way merge (plan.md §5).
    pub blobs_root: PathBuf,
}

pub type SharedDavState = Arc<DavState>;

impl DavState {
    /// URL prefix this mount is served at, e.g. "/dav/files" or "/dav/notes".
    ///
    /// `scope_prefix` is the literal "/dav/" for every mount, so it cannot be
    /// used to authorize a request — see `check_auth`.
    fn mount_prefix(&self) -> String {
        if self.db_path_prefix.is_empty() {
            "/dav/files".to_string()
        } else {
            format!("/dav/{}", self.db_path_prefix.trim_end_matches('/'))
        }
    }

    /// Get the database path for a relative URL path by prepending db_path_prefix
    fn db_path(&self, rel_path: &str) -> String {
        if self.db_path_prefix.is_empty() {
            rel_path.to_string()
        } else {
            format!("{}{}", self.db_path_prefix, rel_path)
        }
    }
}

/// Check authorization and return the id of the credential that authenticated.
///
/// The id (not just a yes/no) is needed because merge-base tracking is keyed per
/// client — see `record_base_version` and plan.md §5.
fn check_auth(state: &SharedDavState, headers: &HeaderMap, request_path: &str) -> Option<String> {
    let auth_header = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        Some(ref h) if h.starts_with("Basic ") => {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &h[6..])
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
            if let Some(creds) = decoded {
                if let Some((_user, password)) = creds.split_once(':') {
                    let db = state.db.get().unwrap();
                    // Only app passwords accepted — each scoped to its service
                    auth::authenticate_app_password(&db, password, request_path).unwrap_or(None)
                } else {
                    None
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Remember which content version a client was handed.
///
/// A GET is the moment a client takes possession of a version, so it is the
/// ancestor any later write from that client is based on. Recorded per
/// credential: a password shared across devices makes this meaningless, which is
/// why each device should have its own.
fn record_base_version(state: &SharedDavState, credential_id: &str, rel_path: &str, sha256: &str) {
    let Ok(db) = state.db.get() else { return };
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db.execute(
        "INSERT INTO client_base_versions (credential_id, path, sha256, served_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(credential_id, path) DO UPDATE SET
            sha256 = excluded.sha256,
            served_at = excluded.served_at",
        rusqlite::params![credential_id, state.db_path(rel_path), sha256, now],
    );
}

/// Full sha256 of a path from the stat cache, refreshing it if stale.
fn current_sha256(state: &SharedDavState, rel_path: &str) -> Option<String> {
    resolve_file_identity(state, rel_path)?;
    let db = state.db.get().ok()?;
    db.query_row(
        "SELECT sha256 FROM files WHERE path = ?1",
        [&state.db_path(rel_path)],
        |r| r.get::<_, Option<String>>(0),
    )
    .ok()
    .flatten()
}

/// Validate that a relative path doesn't escape the root directory.
/// Rejects paths containing `..` segments.
fn is_safe_path(rel_path: &str) -> bool {
    !rel_path.split('/').any(|segment| segment == "..")
}

/// Ensure a disk path resolves to within the allowed root directory.
/// Prevents symlink escape by canonicalizing and checking the prefix.
fn ensure_within_root(
    root: &std::path::Path,
    target: &std::path::Path,
    allowed_extras: &[PathBuf],
) -> bool {
    let canon_root = match root.canonicalize() {
        Ok(p) => p,
        Err(_) => return false,
    };

    let check = |resolved: &std::path::Path| -> bool {
        if resolved.starts_with(&canon_root) {
            return true;
        }
        allowed_extras.iter().any(|extra| {
            extra
                .canonicalize()
                .is_ok_and(|ce| resolved.starts_with(&ce))
        })
    };

    // If target exists, canonicalize it directly (follows symlinks)
    if target.exists() {
        return match target.canonicalize() {
            Ok(p) => check(&p),
            Err(_) => false,
        };
    }

    // Target doesn't exist yet — canonicalize the nearest existing ancestor
    let mut ancestor = target.to_path_buf();
    while !ancestor.exists() {
        if !ancestor.pop() {
            return false;
        }
    }
    match ancestor.canonicalize() {
        Ok(p) => check(&p),
        Err(_) => false,
    }
}

/// Escape SQL LIKE wildcard characters so user-supplied paths
/// don't match unrelated rows.
fn escape_like(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('%', "\\%")
        .replace('_', "\\_")
}

fn unauthorized_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(
            axum::http::header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Basic realm=\"tilde\""),
        )],
        "Unauthorized",
    )
        .into_response()
}

/// Build the WebDAV router — mount at /dav/files/
pub fn build_dav_router(state: SharedDavState) -> Router {
    Router::new()
        .route("/", any(dav_handler))
        .route("/{*path}", any(dav_handler))
        .with_state(state)
}

/// Build the uploads router — mount at /dav/uploads/
pub fn build_uploads_router(state: SharedDavState) -> Router {
    Router::new()
        .route("/{*path}", any(uploads_handler))
        .with_state(state)
}

/// Main WebDAV dispatch handler
async fn dav_handler(
    State(state): State<SharedDavState>,
    method: Method,
    path: Option<Path<String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    // OPTIONS is allowed without auth (DAV discovery)
    if method == Method::OPTIONS {
        return handle_options().await;
    }

    let path_str = path.map(|Path(p)| p).unwrap_or_default();
    let rel_path = path_str.trim_start_matches('/');

    // Authorize against the URL actually being accessed. Previously every mount
    // passed the constant "/dav/", so `request_path.starts_with(scope)` compared
    // a constant against itself: a "/dav/*" credential was accepted on /caldav/
    // and /carddav/ too, and a "/caldav/" credential was rejected everywhere.
    let request_path = format!("{}/{}", state.mount_prefix(), rel_path);
    let Some(credential_id) = check_auth(&state, &headers, &request_path) else {
        return unauthorized_response();
    };

    if !is_safe_path(rel_path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    match method.as_str() {
        "OPTIONS" => handle_options().await,
        // HEAD serves no body, so it does not give the client a version to hold.
        "HEAD" => handle_get(&state, rel_path, true, None, &headers).await,
        "GET" => handle_get(&state, rel_path, false, Some(&credential_id), &headers).await,
        "PUT" => handle_put(&state, rel_path, &headers, body, Some(&credential_id)).await,
        "DELETE" => handle_delete(&state, rel_path).await,
        "MKCOL" => handle_mkcol(&state, rel_path).await,
        "MOVE" => handle_move(&state, rel_path, &headers).await,
        "COPY" => handle_copy(&state, rel_path, &headers).await,
        "PROPFIND" => handle_propfind(&state, rel_path, &headers).await,
        "PROPPATCH" => handle_proppatch(&state, rel_path, body).await,
        "LOCK" => {
            // Class-1 server does not support locking — return 405 per RFC 4918
            StatusCode::METHOD_NOT_ALLOWED.into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// OPTIONS — advertise DAV Class 1 support
async fn handle_options() -> Response {
    (
        StatusCode::OK,
        [
            ("DAV", "1"),
            (
                "Allow",
                "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH",
            ),
        ],
    )
        .into_response()
}

/// GET / HEAD — download a file
async fn handle_get(
    state: &SharedDavState,
    rel_path: &str,
    head_only: bool,
    credential_id: Option<&str>,
    request_headers: &HeaderMap,
) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Symlink escape check — canonicalize and verify within root
    if !ensure_within_root(
        &state.files_root,
        &disk_path,
        &state.allowed_symlink_targets,
    ) {
        warn!(path = rel_path, "Symlink escape blocked on GET");
        return StatusCode::FORBIDDEN.into_response();
    }

    if disk_path.is_dir() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let content_type = mime_from_path(rel_path);
    let metadata = match disk_path.metadata() {
        Ok(m) => m,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    // Resolve against disk, not the stored row: the file may have been written
    // out of band since the last DAV write.
    let etag = {
        let st = state.clone();
        let rp = rel_path.to_string();
        tokio::task::spawn_blocking(move || resolve_file_identity(&st, &rp))
            .await
            .ok()
            .flatten()
            .map(|(_, etag)| etag)
    };

    // Record the version this client now holds — the ancestor for any later
    // three-way merge of a write from the same credential.
    //
    // The version is archived here, not only on overwrite, because
    // archive-on-overwrite alone covers just the DAV write path. An agent, the
    // CLI, or rsync can displace a version without ever touching it — which is
    // exactly this project's central case — leaving a recorded base with no
    // retrievable content and no way to merge. Archiving at the moment a base is
    // recorded makes "every recorded base is retrievable" an invariant.
    //
    // Cost is one copy the first time a version is served; `archive_version` is
    // idempotent, so repeat reads are a single `exists()` check.
    if let Some(cred) = credential_id {
        let st = state.clone();
        let rp = rel_path.to_string();
        let dp = disk_path.clone();
        let cred = cred.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(sha) = current_sha256(&st, &rp) {
                // Pass the digest we already have: `archive_version` hashes the
                // whole file before its "already present" check, which on the
                // read path meant every GET re-read the entire file — defeating
                // range streaming on large video.
                if let Err(e) = versions::archive_version_known_sha(&st.blobs_root, &dp, &sha) {
                    warn!(path = rp, error = %e, "Could not archive served version");
                }
                record_base_version(&st, &cred, &rp, &sha);
            }
        })
        .await;
    }

    let total_len = metadata.len();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    if let Some(etag) = etag {
        headers.insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
        );
    }
    // Without this, players will not attempt to seek at all.
    headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));

    // RFC 9110 §14. Video playback depends on this: seeking needs 206 responses,
    // Safari/iOS probes with `Range: bytes=0-1` and refuses to play on a 200, and
    // MP4s with a trailing `moov` atom need a suffix range before they can start.
    let range = headers_range(request_headers).map(|h| parse_range(&h, total_len));

    let slice = match range {
        Some(RangeSpec::Unsatisfiable) => {
            let mut h = HeaderMap::new();
            h.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
            h.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes */{}", total_len)).unwrap(),
            );
            return (StatusCode::RANGE_NOT_SATISFIABLE, h).into_response();
        }
        Some(RangeSpec::Satisfiable(r)) => Some(r),
        Some(RangeSpec::Ignore) | None => None,
    };

    let (status, body_len) = match &slice {
        Some(r) => {
            headers.insert(
                header::CONTENT_RANGE,
                HeaderValue::from_str(&format!("bytes {}-{}/{}", r.start, r.end, total_len))
                    .unwrap(),
            );
            (StatusCode::PARTIAL_CONTENT, r.end - r.start + 1)
        }
        None => (StatusCode::OK, total_len),
    };
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(body_len));

    if head_only {
        return (status, headers).into_response();
    }

    // Stream the file instead of reading it all into memory
    match tokio::fs::File::open(&disk_path).await {
        Ok(mut file) => {
            if let Some(r) = &slice {
                use tokio::io::AsyncSeekExt;
                if let Err(e) = file.seek(std::io::SeekFrom::Start(r.start)).await {
                    warn!(path = rel_path, error = %e, "Failed to seek for range request");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }
            let reader = tokio::io::AsyncReadExt::take(file, body_len);
            let stream = tokio_util::io::ReaderStream::with_capacity(reader, 64 * 1024);
            let body = Body::from_stream(stream);
            (status, headers, body).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// PUT — upload a file atomically
async fn handle_put(
    state: &SharedDavState,
    rel_path: &str,
    headers: &HeaderMap,
    body: Body,
    credential_id: Option<&str>,
) -> Response {
    // PUT to a collection path (trailing slash) is invalid
    if rel_path.ends_with('/') || rel_path.is_empty() {
        return StatusCode::CONFLICT.into_response();
    }

    // Check If-Match precondition (RFC 7232)
    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        let expected_etag = if_match.trim_matches('"');
        let current = {
            let st = state.clone();
            let rp = rel_path.to_string();
            tokio::task::spawn_blocking(move || resolve_file_identity(&st, &rp))
                .await
                .ok()
                .flatten()
                .map(|(_, etag)| etag)
        };
        match current {
            Some(current_etag) if current_etag != expected_etag => {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            None => {
                // Resource doesn't exist — If-Match MUST fail (RFC 7232 §3.1)
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
            _ => {} // etag matches, proceed
        }
    }

    let disk_path = state.files_root.join(rel_path);

    // Symlink escape check
    if !ensure_within_root(
        &state.files_root,
        &disk_path,
        &state.allowed_symlink_targets,
    ) {
        warn!(path = rel_path, "Symlink escape blocked on PUT");
        return StatusCode::FORBIDDEN.into_response();
    }

    // Archive the version about to be displaced. This is what lets a later
    // stale write be merged against its true ancestor rather than clobbering —
    // including a version written out of band, which is otherwise unrecoverable.
    if disk_path.is_file() {
        let blobs = state.blobs_root.clone();
        let src = disk_path.clone();
        let rp = rel_path.to_string();
        let _ = tokio::task::spawn_blocking(move || {
            if let Err(e) = versions::archive_version(&blobs, &src) {
                warn!(path = rp, error = %e, "Could not archive version before overwrite");
            }
        })
        .await;
    }

    // Ensure parent directory exists
    if let Some(parent) = disk_path.parent()
        && !parent.exists()
    {
        return (StatusCode::CONFLICT, "Parent collection does not exist").into_response();
    }

    let exists = disk_path.exists();

    // Streaming write: stream body chunks directly to temp file (never buffer full file in memory)
    // UUID suffix prevents races between concurrent PUTs to the same path
    let tmp_path = disk_path.with_extension(format!("tmp_tilde_{}", Uuid::new_v4().as_simple()));
    let tmp_file = match tokio::fs::File::create(&tmp_path).await {
        Ok(f) => f,
        Err(e) => {
            warn!(error = %e, path = %tmp_path.display(), "Failed to create tmp file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    let mut writer = tokio::io::BufWriter::with_capacity(64 * 1024, tmp_file);
    let mut hasher = Sha256::new();
    let mut total_bytes: u64 = 0;

    use http_body_util::BodyExt;
    use tokio::io::AsyncWriteExt;

    let mut body = body;
    loop {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Ok(chunk) = frame.into_data() {
                    hasher.update(&chunk);
                    total_bytes += chunk.len() as u64;
                    if let Err(e) = writer.write_all(&chunk).await {
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        warn!(error = %e, "Failed to write chunk to tmp file");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }
            }
            Some(Err(_)) => {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return StatusCode::BAD_REQUEST.into_response();
            }
            None => break,
        }
    }

    if let Err(e) = writer.flush().await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        warn!(error = %e, "Failed to flush tmp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // fsync the ORIGINAL file handle (not a reopened one) for durability
    let inner_file = writer.into_inner();
    let _ = inner_file.sync_all().await;

    // The write may be based on a version this client no longer holds. If so,
    // merge instead of overwriting — the whole point of tracking base versions.
    let merge_result = if let Some(cred) = credential_id {
        let st = state.clone();
        let rp = rel_path.to_string();
        let dp = disk_path.clone();
        let tp = tmp_path.clone();
        let cred = cred.to_string();
        tokio::task::spawn_blocking(move || merge_if_stale(&st, &cred, &rp, &dp, &tp))
            .await
            .ok()
            .flatten()
    } else {
        None
    };

    // A merged result is not what the client sent, so its digest must be
    // recomputed and the response must not claim otherwise (see below).
    let (sha256, was_merged, had_conflicts) = match merge_result {
        Some((merged, conflicted)) => {
            if let Err(e) = tokio::fs::write(&tmp_path, &merged).await {
                let _ = tokio::fs::remove_file(&tmp_path).await;
                warn!(error = %e, "Failed to write merged content");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let mut h = Sha256::new();
            h.update(&merged);
            (format!("{:x}", h.finalize()), true, conflicted)
        }
        None => (format!("{:x}", hasher.finalize()), false, false),
    };

    // Atomic rename
    if let Err(e) = tokio::fs::rename(&tmp_path, &disk_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        warn!(error = %e, "Failed to rename tmp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // fsync parent directory
    if let Some(parent) = disk_path.parent()
        && let Ok(dir) = tokio::fs::File::open(parent).await
    {
        let _ = dir.sync_all().await;
    }

    let etag = sha256[..16].to_string();
    let _ = total_bytes; // used during streaming

    // Advance this client's base to what was actually stored.
    //
    // Without this, only GET ever moved the base, so a client issuing two writes
    // in a row — which is normal, since a sync client trusts the ETag its own PUT
    // returned — looked stale on the second one. The merge then ran against the
    // pre-first-write ancestor and diff3 fast-forwarded to the copy on disk,
    // silently resurrecting content the user had just deleted.
    //
    // After a successful PUT the client demonstrably holds what was stored, so
    // that is the correct ancestor for its next write. This applies to merged
    // writes too: the merged bytes are what the client will re-fetch.
    if let Some(cred) = credential_id {
        let st = state.clone();
        let rp = rel_path.to_string();
        let cred = cred.to_string();
        let stored_sha = sha256.clone();
        let dp = disk_path.clone();
        let _ = tokio::task::spawn_blocking(move || {
            // Keep the base retrievable, same invariant as the GET path.
            if let Err(e) = versions::archive_version_known_sha(&st.blobs_root, &dp, &stored_sha) {
                warn!(path = rp, error = %e, "Could not archive stored version");
            }
            record_base_version(&st, &cred, &rp, &stored_sha);
        })
        .await;
    }

    let content_type = mime_from_path(rel_path);
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    // Upsert into files table
    {
        let db = state.db.get().unwrap();
        let db_path = state.db_path(rel_path);
        let file_name = std::path::Path::new(rel_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let db_parent = std::path::Path::new(&db_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let existing_id: Option<String> = db
            .query_row("SELECT id FROM files WHERE path = ?1", [&db_path], |row| {
                row.get(0)
            })
            .ok();

        let id = existing_id.unwrap_or_else(|| Uuid::new_v4().to_string());

        db.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag, sha256, is_directory, created_at, modified_at, hlc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)
             ON CONFLICT(path) DO UPDATE SET
                size_bytes = excluded.size_bytes,
                content_type = excluded.content_type,
                etag = excluded.etag,
                sha256 = excluded.sha256,
                modified_at = excluded.modified_at,
                hlc = excluded.hlc",
            rusqlite::params![id, db_path, db_parent, file_name, total_bytes, content_type, etag, sha256, now, now, now],
        ).ok();
    }

    let status = if exists {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut resp_headers = HeaderMap::new();
    // RFC 9110 §9.3.4: a server MUST NOT send a validator in a successful PUT
    // response unless the representation was saved *without transformation*.
    // A merge is a transformation — sending the merged ETag would make the
    // client record "my local copy == this ETag", never re-fetch, and re-conflict
    // on its next edit forever. Omitting it makes conforming clients re-sync.
    if !was_merged {
        resp_headers.insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
        );
    } else if had_conflicts {
        // Surface the outcome for clients and humans reading logs; not a validator.
        resp_headers.insert(
            HeaderName::from_static("x-tilde-merge"),
            HeaderValue::from_static("conflicted"),
        );
    } else {
        resp_headers.insert(
            HeaderName::from_static("x-tilde-merge"),
            HeaderValue::from_static("clean"),
        );
    }
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    let dav_mount = if state.db_path_prefix.is_empty() {
        "/dav/files"
    } else {
        &format!("/dav/{}", state.db_path_prefix.trim_end_matches('/'))
    };
    if !exists && let Ok(loc) = HeaderValue::from_str(&format!("{}/{}", dav_mount, rel_path)) {
        resp_headers.insert(header::LOCATION, loc);
    }

    info!(path = rel_path, size = total_bytes, "WebDAV PUT");

    // For photos: if an existing file was overwritten, check if metadata (date) changed
    // and queue a reorganization if needed
    if exists && state.db_path_prefix == "photos/" {
        let ext = disk_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_lowercase();
        if is_media_ext(&ext) && !rel_path.starts_with("_") {
            let db = state.db.clone();
            let files_root = state.files_root.clone();
            let pattern = state.organization_pattern.clone();
            let rel = rel_path.to_string();
            tokio::task::spawn_blocking(move || {
                check_and_queue_reorganize(&db, &files_root, &pattern, &rel);
            });
        }
    }

    (status, resp_headers).into_response()
}

/// Check if a photo's metadata date changed after a PUT overwrite,
/// and reorganize it if the current path doesn't match the new date.
fn check_and_queue_reorganize(
    db: &DbPool,
    photos_base: &std::path::Path,
    organization_pattern: &str,
    rel_path: &str,
) {
    use tilde_photos::metadata;
    use tilde_photos::organize;

    let disk_path = photos_base.join(rel_path);
    let meta = match metadata::read_metadata(&disk_path) {
        Ok(m) => m,
        Err(_) => return,
    };

    let date_str = match &meta.date_time_original {
        Some(d) => d,
        None => return,
    };

    let filename = disk_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();

    let new_rel = match organize::compute_destination(organization_pattern, &meta, &filename) {
        Some(p) => p,
        None => return,
    };

    let new_rel_str = new_rel.to_string_lossy().to_string();

    // If the file is already at the correct path, nothing to do
    if rel_path == new_rel_str {
        return;
    }

    let new_dest = photos_base.join(&new_rel);

    // Defence in depth. `compute_destination` sanitises the attacker-controlled
    // XMP `trip:` value, but this sink joins the result straight onto the photos
    // root and then creates directories and renames into it — so verify
    // containment here too rather than relying on a helper in another crate
    // staying safe.
    if !ensure_within_root(photos_base, &new_dest, &[]) {
        warn!(
            dest = %new_dest.display(),
            "Refusing to organize photo outside the photos root"
        );
        return;
    }

    if let Some(parent) = new_dest.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    // Move the file
    if let Err(e) = std::fs::rename(&disk_path, &new_dest) {
        tracing::warn!(error = %e, from = rel_path, to = %new_rel_str, "Failed to reorganize photo after metadata change");
        return;
    }

    // Update DB
    let conn = db.get().unwrap();
    let old_db_path = format!("photos/{}", rel_path);
    let new_db_path = format!("photos/{}", new_rel_str);
    let new_parent = std::path::Path::new(&new_db_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    conn.execute(
        "UPDATE files SET path = ?1, parent_path = ?2 WHERE path = ?3",
        rusqlite::params![new_db_path, new_parent, old_db_path],
    )
    .ok();

    // Update photos.taken_at
    conn.execute(
        "UPDATE photos SET taken_at = ?1, updated_at = ?2 WHERE file_id = (SELECT id FROM files WHERE path = ?3)",
        rusqlite::params![date_str, jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(), new_db_path],
    ).ok();

    tracing::info!(from = rel_path, to = %new_rel_str, "Photo reorganized after metadata change");
}

fn is_media_ext(ext: &str) -> bool {
    matches!(
        ext,
        "jpg"
            | "jpeg"
            | "png"
            | "webp"
            | "heic"
            | "heif"
            | "tiff"
            | "tif"
            | "raw"
            | "cr2"
            | "nef"
            | "arw"
            | "mp4"
            | "mov"
            | "avi"
            | "mkv"
            | "webm"
    )
}

/// DELETE — remove a file or collection
async fn handle_delete(state: &SharedDavState, rel_path: &str) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Symlink escape check
    if !ensure_within_root(
        &state.files_root,
        &disk_path,
        &state.allowed_symlink_targets,
    ) {
        warn!(path = rel_path, "Symlink escape blocked on DELETE");
        return StatusCode::FORBIDDEN.into_response();
    }

    let db_path = state.db_path(rel_path);

    // Captured before the move to trash, which makes `disk_path` vanish.
    let was_dir = disk_path.is_dir();

    // Move to .trash/ instead of deleting permanently
    let trash_dir = state.files_root.join(".trash");
    let timestamp = jiff::Zoned::now().strftime("%Y%m%d-%H%M%S").to_string();
    let trash_dest = trash_dir.join(&timestamp).join(rel_path);

    if let Some(parent) = trash_dest.parent()
        && let Err(e) = tokio::fs::create_dir_all(parent).await
    {
        warn!(error = %e, "Failed to create trash directory");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if let Err(_rename_err) = tokio::fs::rename(&disk_path, &trash_dest).await {
        // Cross-filesystem fallback: copy + delete
        if disk_path.is_dir() {
            if let Err(e) = copy_dir_async(&disk_path, &trash_dest).await {
                warn!(error = %e, "Failed to move directory to trash");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let _ = tokio::fs::remove_dir_all(&disk_path).await;
        } else {
            if let Err(e) = tokio::fs::copy(&disk_path, &trash_dest).await {
                warn!(error = %e, "Failed to copy file to trash: {}", e);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
            let _ = tokio::fs::remove_file(&disk_path).await;
        }
    }

    // Clean up photo-specific records (thumbnails, photo_tags, photos row)
    if state.db_path_prefix == "photos/" && !rel_path.starts_with('_') {
        let db = state.db.get().unwrap();
        // Find the photo UUID via the file record
        let photo_info: Option<(String, String)> = db
            .query_row(
                "SELECT p.id, f.id FROM photos p JOIN files f ON p.file_id = f.id WHERE f.path = ?1",
                [&db_path],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            )
            .ok();

        if let Some((photo_id, _file_id)) = photo_info {
            // Delete thumbnail symlink: _thumbnails/{rel_path_stem}.webp
            let original = std::path::Path::new(rel_path);
            let stem = original
                .file_stem()
                .map(|s| s.to_string_lossy().to_string())
                .unwrap_or_default();
            let parent = original.parent().unwrap_or(std::path::Path::new(""));
            let symlink_path = state
                .files_root
                .join("_thumbnails")
                .join(parent)
                .join(format!("{}.webp", stem));
            if symlink_path.exists() || symlink_path.symlink_metadata().is_ok() {
                let _ = tokio::fs::remove_file(&symlink_path).await;
            }

            // Delete thumbnail cache directory
            if let Some(ref cache_dir) = state.cache_dir {
                let thumb_dir = cache_dir.join("thumbnails").join(&photo_id);
                if thumb_dir.exists() {
                    let _ = tokio::fs::remove_dir_all(&thumb_dir).await;
                }
            }

            // Delete photo_tags and photos row
            db.execute("DELETE FROM photo_tags WHERE photo_id = ?1", [&photo_id])
                .ok();
            db.execute("DELETE FROM photos WHERE id = ?1", [&photo_id])
                .ok();
            // Delete any pending thumbnail jobs for this photo
            let payload_match = format!("%{}%", photo_id);
            db.execute(
                "DELETE FROM jobs WHERE job_type = 'thumbnail' AND payload_json LIKE ?1 AND status = 'pending'",
                [&payload_match],
            ).ok();

            info!(photo_id = %photo_id, "Cleaned up photo record, thumbnails, and tags");
        }
    }

    // Remove from DB (file disappears from listings)
    //
    // `was_dir` is captured before the move to trash: checking `disk_path.is_dir()`
    // here always saw a path that no longer existed, so the child-row cleanup
    // never ran and every descendant row was orphaned.
    //
    // The pattern is `path/%`, not `path%`: the latter also matched siblings
    // whose names merely start with this one (a directory `photo` matching
    // `photos/...`).
    if was_dir {
        let db = state.db.get().unwrap();
        let pattern = format!("{}/%", escape_like(&db_path));
        let sql = format!(
            "DELETE FROM files WHERE (path = ?1 OR path LIKE ?2 ESCAPE '\\'){}",
            sibling_mount_exclusion(state)
        );
        db.execute(&sql, rusqlite::params![db_path, pattern]).ok();
    } else {
        let db = state.db.get().unwrap();
        db.execute("DELETE FROM files WHERE path = ?1", [&db_path])
            .ok();
    }

    info!(path = rel_path, trash = %trash_dest.display(), "WebDAV DELETE (moved to trash)");
    StatusCode::NO_CONTENT.into_response()
}

/// Recursively copy a directory (async)
async fn copy_dir_async(
    src: &std::path::Path,
    dst: &std::path::Path,
) -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().await?.is_dir() {
            Box::pin(copy_dir_async(&src_path, &dst_path)).await?;
        } else {
            tokio::fs::copy(&src_path, &dst_path).await?;
        }
    }
    Ok(())
}

/// Purge trash entries older than the given number of days.
/// Called periodically from the server's background tasks.
pub fn purge_trash(files_root: &std::path::Path, retention_days: u32) -> usize {
    let trash_dir = files_root.join(".trash");
    if !trash_dir.exists() {
        return 0;
    }

    let cutoff = jiff::Zoned::now()
        .checked_sub(jiff::SignedDuration::from_hours(retention_days as i64 * 24))
        .unwrap_or_else(|_| jiff::Zoned::now());
    let cutoff_str = cutoff.strftime("%Y%m%d-%H%M%S").to_string();

    let mut purged = 0;
    if let Ok(entries) = std::fs::read_dir(&trash_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            // Trash directories are named by timestamp: 20260427-104829
            if name <= cutoff_str
                && let Ok(meta) = entry.metadata()
                && meta.is_dir()
            {
                let _ = std::fs::remove_dir_all(entry.path());
                purged += 1;
            }
        }
    }

    if purged > 0 {
        info!(count = purged, root = %files_root.display(), "Purged old trash entries");
    }
    purged
}

/// MKCOL — create a collection (directory)
async fn handle_mkcol(state: &SharedDavState, rel_path: &str) -> Response {
    let disk_path = state.files_root.join(rel_path);

    // Symlink escape check (checks nearest existing ancestor)
    if !ensure_within_root(
        &state.files_root,
        &disk_path,
        &state.allowed_symlink_targets,
    ) {
        warn!(path = rel_path, "Symlink escape blocked on MKCOL");
        return StatusCode::FORBIDDEN.into_response();
    }

    if disk_path.exists() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    // Check parent exists
    if let Some(parent) = disk_path.parent()
        && !parent.exists()
    {
        return StatusCode::CONFLICT.into_response();
    }

    if let Err(e) = tokio::fs::create_dir(&disk_path).await {
        warn!(error = %e, "Failed to create directory");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Record in DB
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let id = Uuid::new_v4().to_string();
    let db_path = state.db_path(rel_path);
    let name = std::path::Path::new(rel_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let db_parent = std::path::Path::new(&db_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    {
        let db = state.db.get().unwrap();
        db.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag, is_directory, created_at, modified_at, hlc)
             VALUES (?1, ?2, ?3, ?4, 0, 'httpd/unix-directory', ?5, 1, ?6, ?7, ?8)",
            rusqlite::params![id, db_path, db_parent, name, id, now, now, now],
        ).ok();
    }

    info!(path = rel_path, "WebDAV MKCOL");
    StatusCode::CREATED.into_response()
}

/// MOVE — move/rename a resource
async fn handle_move(state: &SharedDavState, rel_path: &str, headers: &HeaderMap) -> Response {
    let dest = match get_destination(headers) {
        Some(d) => d,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let src_disk = state.files_root.join(rel_path);
    let dst_disk = state.files_root.join(&dest);

    if !src_disk.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Symlink escape check on both source and destination
    if !ensure_within_root(&state.files_root, &src_disk, &state.allowed_symlink_targets) {
        warn!(path = rel_path, "Symlink escape blocked on MOVE source");
        return StatusCode::FORBIDDEN.into_response();
    }
    if !ensure_within_root(&state.files_root, &dst_disk, &state.allowed_symlink_targets) {
        warn!(dest = %dest, "Symlink escape blocked on MOVE destination");
        return StatusCode::FORBIDDEN.into_response();
    }

    // Ensure destination parent exists
    if let Some(parent) = dst_disk.parent()
        && !parent.exists()
    {
        return StatusCode::CONFLICT.into_response();
    }

    let overwrite = dst_disk.exists();

    if let Err(e) = tokio::fs::rename(&src_disk, &dst_disk).await {
        warn!(error = %e, "Failed to move");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Update DB — preserve the UUID (oc:id)
    {
        let db = state.db.get().unwrap();
        let src_db_path = state.db_path(rel_path);
        let dst_db_path = state.db_path(&dest);
        let dest_name = std::path::Path::new(&dest)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let dst_db_parent = std::path::Path::new(&dst_db_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();

        // Get the file ID before updating path
        let file_id: Option<String> = db
            .query_row(
                "SELECT id FROM files WHERE path = ?1",
                [&src_db_path],
                |row| row.get(0),
            )
            .ok();

        db.execute(
            "UPDATE files SET path = ?1, parent_path = ?2, name = ?3, modified_at = ?4 WHERE path = ?5",
            rusqlite::params![dst_db_path, dst_db_parent, dest_name, now, src_db_path],
        ).ok();

        // If this file has a photos record, set manually_placed = 1
        // (user-initiated MOVE disables auto-organization)
        if let Some(ref fid) = file_id {
            db.execute(
                "UPDATE photos SET manually_placed = 1, updated_at = ?1 WHERE file_id = ?2",
                rusqlite::params![now, fid],
            )
            .ok();
        }

        // Update thumbnail symlink if this is a photo being moved
        if state.db_path_prefix == "photos/"
            && !rel_path.starts_with('_')
            && !dest.starts_with('_')
            && let Some(ref fid) = file_id
            && let Some(ref pid) = db
                .query_row("SELECT id FROM photos WHERE file_id = ?1", [fid], |row| {
                    row.get::<_, String>(0)
                })
                .ok()
            && let Some(ref cache_dir) = state.cache_dir
        {
            let thumb_source = cache_dir.join("thumbnails").join(pid).join("256.webp");
            if thumb_source.exists() {
                // Remove old symlink
                let old_stem = std::path::Path::new(rel_path)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let old_parent = std::path::Path::new(rel_path)
                    .parent()
                    .unwrap_or(std::path::Path::new(""));
                let old_link = state
                    .files_root
                    .join("_thumbnails")
                    .join(old_parent)
                    .join(format!("{}.webp", old_stem));
                let _ = std::fs::remove_file(&old_link);

                // Create new symlink
                let new_stem = std::path::Path::new(&dest)
                    .file_stem()
                    .map(|s| s.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_parent = std::path::Path::new(&dest)
                    .parent()
                    .unwrap_or(std::path::Path::new(""));
                let new_link = state
                    .files_root
                    .join("_thumbnails")
                    .join(new_parent)
                    .join(format!("{}.webp", new_stem));
                if let Some(dir) = new_link.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                #[cfg(unix)]
                {
                    let _ = std::os::unix::fs::symlink(&thumb_source, &new_link);
                }
            }
        }

        // If directory, update children paths too
        if dst_disk.is_dir() {
            let old_prefix = format!("{}/", src_db_path);
            let new_prefix = format!("{}/", dst_db_path);
            let like_pattern = format!("{}%", escape_like(&old_prefix));
            let select_sql = format!(
                "SELECT id, path FROM files WHERE path LIKE ?1 ESCAPE '\\'{}",
                sibling_mount_exclusion(state)
            );
            let mut stmt = db.prepare(&select_sql).unwrap();
            let children: Vec<(String, String)> = stmt
                .query_map([&like_pattern], |row| Ok((row.get(0)?, row.get(1)?)))
                .unwrap()
                .filter_map(|r| r.ok())
                .collect();

            for (child_id, child_path) in children {
                let new_path = child_path.replacen(&old_prefix, &new_prefix, 1);
                let new_parent = std::path::Path::new(&new_path)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();
                let new_name = std::path::Path::new(&new_path)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                db.execute(
                    "UPDATE files SET path = ?1, parent_path = ?2, name = ?3 WHERE id = ?4",
                    rusqlite::params![new_path, new_parent, new_name, child_id],
                )
                .ok();
            }
        }
    }

    info!(from = rel_path, to = %dest, "WebDAV MOVE");
    if overwrite {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    }
    .into_response()
}

/// COPY — copy a resource
async fn handle_copy(state: &SharedDavState, rel_path: &str, headers: &HeaderMap) -> Response {
    let dest = match get_destination(headers) {
        Some(d) => d,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let src_disk = state.files_root.join(rel_path);
    let dst_disk = state.files_root.join(&dest);

    if !src_disk.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Symlink escape check on both source and destination
    if !ensure_within_root(&state.files_root, &src_disk, &state.allowed_symlink_targets) {
        warn!(path = rel_path, "Symlink escape blocked on COPY source");
        return StatusCode::FORBIDDEN.into_response();
    }
    if !ensure_within_root(&state.files_root, &dst_disk, &state.allowed_symlink_targets) {
        warn!(dest = %dest, "Symlink escape blocked on COPY destination");
        return StatusCode::FORBIDDEN.into_response();
    }

    let overwrite = dst_disk.exists();

    // RFC 4918 §9.8.3: Depth:0 on a collection means create empty collection only
    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("infinity");

    if src_disk.is_dir() {
        if depth == "0" {
            // Depth:0 — create the collection but don't copy children
            tokio::fs::create_dir_all(&dst_disk).await.ok();
        } else {
            copy_dir_recursive(&src_disk, &dst_disk).await.ok();
        }
    } else if let Err(e) = tokio::fs::copy(&src_disk, &dst_disk).await {
        warn!(error = %e, "Failed to copy");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Create new DB record — stream SHA-256 instead of reading entire file into memory
    {
        let size = tokio::fs::metadata(&dst_disk)
            .await
            .map(|m| m.len())
            .unwrap_or(0);
        let sha256 = {
            let hash_path = dst_disk.clone();
            tokio::task::spawn_blocking(move || compute_file_sha256(&hash_path))
                .await
                .unwrap_or_else(|_| Ok(String::new()))
                .unwrap_or_default()
        };

        let db = state.db.get().unwrap();
        let dst_db_path = state.db_path(&dest);
        let etag = if sha256.len() >= 16 {
            sha256[..16].to_string()
        } else {
            sha256.clone()
        };
        let content_type = mime_from_path(&dest);
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        let id = Uuid::new_v4().to_string();
        let name = std::path::Path::new(&dest)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let db_parent = std::path::Path::new(&dst_db_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        db.execute(
            "INSERT OR REPLACE INTO files (id, path, parent_path, name, size_bytes, content_type, etag, sha256, is_directory, created_at, modified_at, hlc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)",
            rusqlite::params![id, dst_db_path, db_parent, name, size as i64, content_type, etag, sha256, now, now, now],
        ).ok();
    }

    info!(from = rel_path, to = %dest, "WebDAV COPY");
    if overwrite {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    }
    .into_response()
}

/// PROPFIND — return properties for a resource
async fn handle_propfind(state: &SharedDavState, rel_path: &str, headers: &HeaderMap) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() && !rel_path.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    // Symlink escape check
    if disk_path.exists()
        && !ensure_within_root(
            &state.files_root,
            &disk_path,
            &state.allowed_symlink_targets,
        )
    {
        warn!(path = rel_path, "Symlink escape blocked on PROPFIND");
        return StatusCode::FORBIDDEN.into_response();
    }

    let depth = headers
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0");

    // RFC 4918: servers MAY reject Depth: infinity with 403 + propfind-finite-depth
    if depth == "infinity" {
        return (
            StatusCode::FORBIDDEN,
            [(header::CONTENT_TYPE, HeaderValue::from_static("application/xml; charset=utf-8"))],
            "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<d:error xmlns:d=\"DAV:\"><d:propfind-finite-depth/></d:error>",
        ).into_response();
    }

    // Derive the URL prefix from db_path_prefix:
    // "" -> "/dav/files", "notes/" -> "/dav/notes", "photos/" -> "/dav/photos"
    let dav_mount = if state.db_path_prefix.is_empty() {
        "/dav/files".to_string()
    } else {
        format!("/dav/{}", state.db_path_prefix.trim_end_matches('/'))
    };

    // Add the requested resource itself
    let href = if rel_path.is_empty() {
        format!("{}/", dav_mount)
    } else {
        format!("{}/{}", dav_mount, rel_path)
    };
    // (rel_path, href) pairs to describe. Built first so every entry can be
    // resolved in one blocking hop — propfind_entry may hash a file whose stat
    // cache is cold, which must not run on the async runtime.
    let mut targets: Vec<(String, String)> = vec![(rel_path.to_string(), href)];

    // If Depth: 1 and it's a directory, add children
    if depth == "1" && (disk_path.is_dir() || rel_path.is_empty()) {
        let target = if rel_path.is_empty() {
            &state.files_root
        } else {
            &disk_path
        };
        if let Ok(mut entries) = tokio::fs::read_dir(target).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let child_name = entry.file_name().to_string_lossy().to_string();
                if child_name.starts_with('.') || child_name.ends_with(".tmp_tilde_upload") {
                    continue;
                }
                let child_rel = if rel_path.is_empty() {
                    child_name.clone()
                } else {
                    format!("{}/{}", rel_path, child_name)
                };
                let child_href = format!("{}/{}", dav_mount, child_rel);
                targets.push((child_rel, child_href));
            }
        }
    }

    let responses: Vec<PropfindResponse> = {
        let st = state.clone();
        match tokio::task::spawn_blocking(move || {
            targets
                .iter()
                .map(|(rel, href)| propfind_entry(&st, rel, href))
                .collect::<Vec<_>>()
        })
        .await
        {
            Ok(r) => r,
            Err(e) => {
                warn!(error = %e, "PROPFIND entry resolution panicked");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        }
    };

    let xml = build_multistatus_xml(&responses);
    let xml_bytes = xml.into_bytes();

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/xml; charset=utf-8"),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(xml_bytes.len()));

    (StatusCode::MULTI_STATUS, headers, xml_bytes).into_response()
}

/// PROPPATCH — set/remove custom properties
async fn handle_proppatch(state: &SharedDavState, rel_path: &str, body: Body) -> Response {
    let disk_path = state.files_root.join(rel_path);
    if !disk_path.exists() && !rel_path.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(b) => b,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Parse PROPPATCH XML to extract set/remove operations
    let ops = parse_proppatch_xml(&body_str);

    let dav_mount = if state.db_path_prefix.is_empty() {
        "/dav/files".to_string()
    } else {
        format!("/dav/{}", state.db_path_prefix.trim_end_matches('/'))
    };
    let href = if rel_path.is_empty() {
        format!("{}/", dav_mount)
    } else {
        format!("{}/{}", dav_mount, rel_path)
    };

    let mut prop_results = Vec::new();

    let db_path = state.db_path(rel_path);
    {
        let db = state.db.get().unwrap();
        for op in &ops {
            match op {
                PropPatchOp::Set {
                    namespace,
                    name,
                    value,
                } => {
                    db.execute(
                        "INSERT INTO file_properties (file_path, namespace, name, value) VALUES (?1, ?2, ?3, ?4)
                         ON CONFLICT(file_path, namespace, name) DO UPDATE SET value = excluded.value",
                        rusqlite::params![db_path, namespace, name, value],
                    ).ok();
                    prop_results.push((namespace.clone(), name.clone(), true));
                }
                PropPatchOp::Remove { namespace, name } => {
                    db.execute(
                        "DELETE FROM file_properties WHERE file_path = ?1 AND namespace = ?2 AND name = ?3",
                        rusqlite::params![db_path, namespace, name],
                    ).ok();
                    prop_results.push((namespace.clone(), name.clone(), true));
                }
            }
        }
    }

    // Build response XML
    let mut xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:href>{}</d:href>
    <d:propstat>
      <d:prop>
"#,
        escape_xml(&href)
    );

    for (ns, name, _) in &prop_results {
        if ns == "DAV:" {
            xml.push_str(&format!("        <d:{}/>\n", escape_xml(name)));
        } else {
            xml.push_str(&format!(
                "        <x:{} xmlns:x=\"{}\"/>\n",
                escape_xml(name),
                escape_xml(ns)
            ));
        }
    }

    xml.push_str(
        r#"      </d:prop>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#,
    );

    info!(path = rel_path, ops = ops.len(), "WebDAV PROPPATCH");

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
}

#[derive(Debug)]
enum PropPatchOp {
    Set {
        namespace: String,
        name: String,
        value: String,
    },
    Remove {
        namespace: String,
        name: String,
    },
}

/// Simple XML parser for PROPPATCH requests
fn parse_proppatch_xml(xml: &str) -> Vec<PropPatchOp> {
    let mut ops = Vec::new();
    let mut in_set = false;
    let mut in_remove = false;
    let mut in_prop = false;
    let mut current_ns = String::new();
    let mut current_name = String::new();
    let mut current_value = String::new();
    let mut in_value = false;

    // Track namespace prefixes
    let mut ns_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    ns_map.insert("d".to_string(), "DAV:".to_string());
    ns_map.insert("D".to_string(), "DAV:".to_string());

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                // Extract namespace declarations from any element
                for attr in e.attributes().flatten() {
                    let attr_key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let attr_val = String::from_utf8_lossy(&attr.value).to_string();
                    if attr_key.starts_with("xmlns:") {
                        let prefix = attr_key.strip_prefix("xmlns:").unwrap().to_string();
                        ns_map.insert(prefix, attr_val);
                    }
                }

                match local_name.as_str() {
                    "set" => {
                        in_set = true;
                        in_remove = false;
                    }
                    "remove" => {
                        in_remove = true;
                        in_set = false;
                    }
                    "prop" => {
                        in_prop = true;
                    }
                    _ if in_prop && (in_set || in_remove) => {
                        let prefix = e
                            .name()
                            .prefix()
                            .map(|p| String::from_utf8_lossy(p.as_ref()).to_string());

                        current_ns =
                            prefix
                                .and_then(|p| ns_map.get(&p).cloned())
                                .unwrap_or_else(|| {
                                    for attr in e.attributes().flatten() {
                                        let attr_key =
                                            String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                        if attr_key == "xmlns" {
                                            return String::from_utf8_lossy(&attr.value)
                                                .to_string();
                                        }
                                    }
                                    "custom:".to_string()
                                });
                        current_name = local_name.clone();
                        current_value.clear();
                        in_value = true;
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Empty(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();

                for attr in e.attributes().flatten() {
                    let attr_key = String::from_utf8_lossy(attr.key.as_ref()).to_string();
                    let attr_val = String::from_utf8_lossy(&attr.value).to_string();
                    if attr_key.starts_with("xmlns:") {
                        let prefix = attr_key.strip_prefix("xmlns:").unwrap().to_string();
                        ns_map.insert(prefix, attr_val);
                    }
                }

                if in_prop
                    && (in_set || in_remove)
                    && local_name != "prop"
                    && local_name != "set"
                    && local_name != "remove"
                {
                    let prefix = e
                        .name()
                        .prefix()
                        .map(|p| String::from_utf8_lossy(p.as_ref()).to_string());

                    let ns = prefix
                        .and_then(|p| ns_map.get(&p).cloned())
                        .unwrap_or_else(|| {
                            for attr in e.attributes().flatten() {
                                let attr_key =
                                    String::from_utf8_lossy(attr.key.as_ref()).to_string();
                                if attr_key == "xmlns" {
                                    return String::from_utf8_lossy(&attr.value).to_string();
                                }
                            }
                            "custom:".to_string()
                        });

                    if in_remove {
                        ops.push(PropPatchOp::Remove {
                            namespace: ns,
                            name: local_name,
                        });
                    } else if in_set {
                        ops.push(PropPatchOp::Set {
                            namespace: ns,
                            name: local_name,
                            value: String::new(),
                        });
                    }
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_value && let Ok(text) = e.unescape() {
                    current_value.push_str(&text);
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local_name = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                match local_name.as_str() {
                    "set" => {
                        in_set = false;
                    }
                    "remove" => {
                        in_remove = false;
                    }
                    "prop" => {
                        in_prop = false;
                    }
                    _ if in_value && local_name == current_name => {
                        in_value = false;
                        if in_set {
                            ops.push(PropPatchOp::Set {
                                namespace: current_ns.clone(),
                                name: current_name.clone(),
                                value: current_value.clone(),
                            });
                        } else if in_remove {
                            ops.push(PropPatchOp::Remove {
                                namespace: current_ns.clone(),
                                name: current_name.clone(),
                            });
                        }
                    }
                    _ => {}
                }
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(_) => break,
            _ => {}
        }
        buf.clear();
    }

    ops
}

// ─── Chunked Upload (Nextcloud v2 protocol) ─────────────────────────────────

/// Handler for /dav/uploads/<user>/<session>/*
async fn uploads_handler(
    State(state): State<SharedDavState>,
    method: Method,
    path: Option<Path<String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if check_auth(&state, &headers, "/dav/uploads").is_none() {
        return unauthorized_response();
    }

    let path_str = path.map(|Path(p)| p).unwrap_or_default();
    let rel_path = path_str.trim_start_matches('/');

    if !is_safe_path(rel_path) {
        return StatusCode::BAD_REQUEST.into_response();
    }

    // Parse the path: <user>/<session-id>[/<chunk-number>]
    let parts: Vec<&str> = rel_path.splitn(3, '/').collect();

    match method.as_str() {
        "MKCOL" => {
            // Create upload session: MKCOL /dav/uploads/<user>/<session-id>/
            if parts.len() < 2 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let session_id = parts[1];

            // Check disk space if OC-Total-Length header is present
            if let Some(total_len) = headers
                .get("oc-total-length")
                .or_else(|| headers.get("OC-Total-Length"))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<u64>().ok())
                && let Ok(stats) = fs2::available_space(&state.uploads_root)
                && stats < total_len + 1024 * 1024
            {
                // 1MB buffer
                return (StatusCode::INSUFFICIENT_STORAGE, "Insufficient disk space")
                    .into_response();
            }

            let staging_dir = state.uploads_root.join(session_id);
            if let Err(e) = tokio::fs::create_dir_all(&staging_dir).await {
                warn!(error = %e, "Failed to create upload staging dir");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // Record in DB
            let now = jiff::Zoned::now();
            let now_str = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            let expires = now
                .checked_add(jiff::SignedDuration::from_hours(24))
                .map(|e| e.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string())
                .unwrap_or_else(|_| now_str.clone());

            let total_size: Option<i64> = headers
                .get("oc-total-length")
                .or_else(|| headers.get("OC-Total-Length"))
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse().ok());

            {
                let db = state.db.get().unwrap();
                db.execute(
                    "INSERT OR REPLACE INTO chunked_uploads (session_id, destination_path, total_size, bytes_received, chunk_count, created_at, expires_at, staging_dir)
                     VALUES (?1, '', ?2, 0, 0, ?3, ?4, ?5)",
                    rusqlite::params![session_id, total_size, now_str, expires, staging_dir.to_string_lossy()],
                ).ok();
            }

            info!(session = session_id, "Chunked upload session created");
            StatusCode::CREATED.into_response()
        }
        "PUT" => {
            // Upload chunk: PUT /dav/uploads/<user>/<session-id>/<chunk-number>
            if parts.len() < 3 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let session_id = parts[1];
            let chunk_name = parts[2];

            let staging_dir = state.uploads_root.join(session_id);
            if !staging_dir.exists() {
                return StatusCode::NOT_FOUND.into_response();
            }

            let chunk_path = staging_dir.join(chunk_name);

            // Stream chunk to disk (never buffer entire chunk in memory)
            let chunk_file = match tokio::fs::File::create(&chunk_path).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(error = %e, "Failed to create chunk file");
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            };
            let mut writer = tokio::io::BufWriter::with_capacity(64 * 1024, chunk_file);
            let mut chunk_size: i64 = 0;

            use http_body_util::BodyExt as _;
            use tokio::io::AsyncWriteExt as _;

            let mut body = body;
            loop {
                match body.frame().await {
                    Some(Ok(frame)) => {
                        if let Ok(chunk) = frame.into_data() {
                            chunk_size += chunk.len() as i64;
                            if let Err(e) = writer.write_all(&chunk).await {
                                let _ = tokio::fs::remove_file(&chunk_path).await;
                                warn!(error = %e, "Failed to write chunk data");
                                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                            }
                        }
                    }
                    Some(Err(_)) => {
                        let _ = tokio::fs::remove_file(&chunk_path).await;
                        return StatusCode::BAD_REQUEST.into_response();
                    }
                    None => break,
                }
            }
            if let Err(e) = writer.flush().await {
                let _ = tokio::fs::remove_file(&chunk_path).await;
                warn!(error = %e, "Failed to flush chunk file");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // Update session tracking
            {
                let db = state.db.get().unwrap();
                db.execute(
                    "UPDATE chunked_uploads SET bytes_received = bytes_received + ?1, chunk_count = chunk_count + 1 WHERE session_id = ?2",
                    rusqlite::params![chunk_size, session_id],
                ).ok();
            }

            info!(
                session = session_id,
                chunk = chunk_name,
                size = chunk_size,
                "Chunk uploaded"
            );
            StatusCode::CREATED.into_response()
        }
        "MOVE" => {
            // Finalize: MOVE /dav/uploads/<user>/<session-id>/ to /dav/files/<destination>
            if parts.len() < 2 {
                return StatusCode::BAD_REQUEST.into_response();
            }
            let session_id = parts[1];
            let staging_dir = state.uploads_root.join(session_id);

            if !staging_dir.exists() {
                return StatusCode::NOT_FOUND.into_response();
            }

            // Get destination from headers (reuse get_destination which validates path traversal)
            let dest = match get_destination(&headers) {
                Some(d) => d,
                None => return StatusCode::BAD_REQUEST.into_response(),
            };

            // Assemble chunks in order
            let mut chunk_files: Vec<String> = Vec::new();
            if let Ok(mut entries) = tokio::fs::read_dir(&staging_dir).await {
                while let Ok(Some(entry)) = entries.next_entry().await {
                    chunk_files.push(entry.file_name().to_string_lossy().to_string());
                }
            }
            chunk_files.sort_by(|a, b| {
                let a_num: u64 = a.parse().unwrap_or(0);
                let b_num: u64 = b.parse().unwrap_or(0);
                a_num.cmp(&b_num)
            });

            let dest_path = state.files_root.join(&dest);

            // Symlink escape check on destination
            if !ensure_within_root(
                &state.files_root,
                &dest_path,
                &state.allowed_symlink_targets,
            ) {
                warn!(dest = %dest, "Symlink escape blocked on chunked upload destination");
                return StatusCode::FORBIDDEN.into_response();
            }

            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }

            // Assemble into destination file (UUID prevents temp file collisions)
            let tmp_path =
                dest_path.with_extension(format!("tmp_chunked_{}", Uuid::new_v4().as_simple()));
            let mut total_size: u64 = 0;
            let mut hasher = Sha256::new();

            {
                use tokio::io::AsyncWriteExt;
                let mut file = match tokio::fs::File::create(&tmp_path).await {
                    Ok(f) => f,
                    Err(e) => {
                        warn!(error = %e, "Failed to create assembled file");
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                };

                for chunk_name in &chunk_files {
                    let chunk_path = staging_dir.join(chunk_name);
                    let chunk_data = match tokio::fs::read(&chunk_path).await {
                        Ok(d) => d,
                        Err(e) => {
                            warn!(error = %e, chunk = %chunk_name, "Failed to read chunk");
                            let _ = tokio::fs::remove_file(&tmp_path).await;
                            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                        }
                    };
                    total_size += chunk_data.len() as u64;
                    hasher.update(&chunk_data);
                    if let Err(e) = file.write_all(&chunk_data).await {
                        warn!(error = %e, "Failed to write to assembled file");
                        let _ = tokio::fs::remove_file(&tmp_path).await;
                        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                    }
                }

                if let Err(e) = file.flush().await {
                    warn!(error = %e, "Failed to flush assembled file");
                    let _ = tokio::fs::remove_file(&tmp_path).await;
                    return StatusCode::INTERNAL_SERVER_ERROR.into_response();
                }
            }

            // Atomic rename to destination
            if let Err(e) = tokio::fs::rename(&tmp_path, &dest_path).await {
                warn!(error = %e, "Failed to rename assembled file to destination");
                let _ = tokio::fs::remove_file(&tmp_path).await;
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            let sha256 = format!("{:x}", hasher.finalize());
            let etag = sha256[..16].to_string();
            let content_type = mime_from_path(&dest);
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();

            // Record in files table
            {
                let db = state.db.get().unwrap();
                let file_name = std::path::Path::new(&dest)
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_default();
                let parent_path = std::path::Path::new(&dest)
                    .parent()
                    .map(|p| p.to_string_lossy().to_string())
                    .unwrap_or_default();

                let existing_id: Option<String> = db
                    .query_row("SELECT id FROM files WHERE path = ?1", [&dest], |row| {
                        row.get(0)
                    })
                    .ok();
                let id = existing_id.unwrap_or_else(|| Uuid::new_v4().to_string());

                db.execute(
                    "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag, sha256, is_directory, created_at, modified_at, hlc)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)
                     ON CONFLICT(path) DO UPDATE SET
                        size_bytes = excluded.size_bytes,
                        content_type = excluded.content_type,
                        etag = excluded.etag,
                        sha256 = excluded.sha256,
                        modified_at = excluded.modified_at,
                        hlc = excluded.hlc",
                    rusqlite::params![id, dest, parent_path, file_name, total_size, content_type, etag, sha256, now, now, now],
                ).ok();

                // Clean up upload session
                db.execute(
                    "DELETE FROM chunked_uploads WHERE session_id = ?1",
                    [session_id],
                )
                .ok();
            }

            // Remove staging directory
            tokio::fs::remove_dir_all(&staging_dir).await.ok();

            info!(session = session_id, dest = %dest, size = total_size, "Chunked upload finalized");

            let mut resp_headers = HeaderMap::new();
            resp_headers.insert(
                header::ETAG,
                HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
            );

            (StatusCode::CREATED, resp_headers).into_response()
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

// ---- Helper functions ----

/// Mount prefixes that share the `files` table with the files root.
///
/// Every DAV mount writes into one `files` table, distinguished only by a path
/// prefix (`DavState::db_path_prefix`). The files mount uses the *empty* prefix,
/// so a naive "prune everything under my prefix" would treat every photos and
/// notes row as an orphan and delete the lot. These are skipped when pruning the
/// files root.
const SIBLING_MOUNT_PREFIXES: &[&str] = &["photos/", "notes/"];

/// Delete archived versions nothing can still need.
///
/// Reachable means: the current content of some file, or a version some
/// credential is recorded as holding (and could therefore still merge against).
pub fn gc_versions_from_db(
    conn: &rusqlite::Connection,
    blobs_root: &std::path::Path,
) -> anyhow::Result<usize> {
    let mut referenced: Vec<String> = Vec::new();

    let mut stmt = conn.prepare("SELECT sha256 FROM files WHERE sha256 IS NOT NULL")?;
    referenced.extend(stmt.query_map([], |r| r.get::<_, String>(0))?.flatten());

    let mut stmt = conn.prepare("SELECT sha256 FROM client_base_versions")?;
    referenced.extend(stmt.query_map([], |r| r.get::<_, String>(0))?.flatten());

    Ok(versions::gc_versions(blobs_root, &referenced)?)
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ReindexStats {
    /// Files whose stat-cache row was written or refreshed.
    pub indexed: usize,
    /// Rows removed because the file is gone from disk (only with `prune`).
    pub pruned: usize,
}

/// Rebuild the `files` stat cache for a tree from disk.
///
/// Phase 1 made ETag resolution self-healing, so this is not required for
/// correctness — it is for warming the cache (so the first PROPFIND after an
/// upgrade or a restic restore does not pay to hash every file) and for pruning
/// rows whose files disappeared while the server was not running.
///
/// `db_prefix` matches `DavState::db_path_prefix`: `""` for the files mount,
/// `"notes/"` for notes, `"photos/"` for photos.
pub fn reindex_tree(
    conn: &rusqlite::Connection,
    root: &std::path::Path,
    db_prefix: &str,
    prune: bool,
) -> anyhow::Result<ReindexStats> {
    let mut stats = ReindexStats::default();
    if !root.exists() {
        return Ok(stats);
    }

    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    index_dir_recursive(conn, root, root, db_prefix, &mut stats, &mut seen, 0)?;

    if prune {
        let like = format!("{}%", escape_like(db_prefix));
        let orphans: Vec<String> = {
            let mut stmt = conn.prepare(
                "SELECT path FROM files WHERE path LIKE ?1 ESCAPE '\\' AND is_directory = 0",
            )?;
            let rows: Vec<String> = stmt
                .query_map([&like], |r| r.get::<_, String>(0))?
                .flatten()
                .collect();
            rows.into_iter()
                .filter(|path| {
                    // Never prune another mount's rows out from under it.
                    if db_prefix.is_empty()
                        && SIBLING_MOUNT_PREFIXES.iter().any(|p| path.starts_with(p))
                    {
                        return false;
                    }
                    !seen.contains(path)
                })
                .collect()
        };

        for path in &orphans {
            let rel = path.strip_prefix(db_prefix).unwrap_or(path);
            // Guard against a racing write: only prune what is really gone.
            if root.join(rel).exists() {
                continue;
            }
            if conn
                .execute("DELETE FROM files WHERE path = ?1", [path])
                .is_ok()
            {
                stats.pruned += 1;
            }
        }
    }

    Ok(stats)
}

#[allow(clippy::too_many_arguments)]
fn index_dir_recursive(
    conn: &rusqlite::Connection,
    root: &std::path::Path,
    dir: &std::path::Path,
    db_prefix: &str,
    stats: &mut ReindexStats,
    seen: &mut std::collections::HashSet<String>,
    depth: usize,
) -> anyhow::Result<()> {
    if depth > 64 {
        warn!(dir = %dir.display(), "reindex depth limit reached");
        return Ok(());
    }

    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            warn!(dir = %dir.display(), error = %e, "reindex could not read directory");
            return Ok(());
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        // PROPFIND hides dotfiles and in-flight uploads, so indexing them would
        // create rows no client can ever see.
        if name.starts_with('.') || name.ends_with(".tmp_tilde_upload") {
            continue;
        }
        let disk_path = entry.path();
        let Ok(md) = entry.metadata() else { continue };

        if md.is_dir() {
            index_dir_recursive(conn, root, &disk_path, db_prefix, stats, seen, depth + 1)?;
            continue;
        }
        if !md.is_file() {
            continue;
        }

        let Ok(rel) = disk_path.strip_prefix(root) else {
            continue;
        };
        let rel_path = rel.to_string_lossy().replace('\\', "/");
        let db_path = format!("{}{}", db_prefix, rel_path);

        if resolve_identity_conn(conn, &db_path, &rel_path, &disk_path, &md).is_some() {
            stats.indexed += 1;
            seen.insert(db_path);
        }
    }

    Ok(())
}

/// Decide whether an incoming write is based on a version the client no longer
/// holds, and if so merge it against the version now on disk.
///
/// Returns the content that should be written instead of the request body, plus
/// whether the merge had to leave conflict markers. `None` means "write the body
/// as-is": a new file, a client that is already current, a base we no longer
/// have, or content that cannot be merged (binary, oversized).
///
/// Safety: whatever this decides, `handle_put` has already archived the version
/// being displaced, so no path through here can make a version unrecoverable.
///
/// Blocking — call from `spawn_blocking`.
fn merge_if_stale(
    state: &SharedDavState,
    credential_id: &str,
    rel_path: &str,
    disk_path: &std::path::Path,
    tmp_path: &std::path::Path,
) -> Option<(Vec<u8>, bool)> {
    if !disk_path.is_file() {
        return None; // creating a new file — nothing to merge against
    }

    let db_path = state.db_path(rel_path);
    let base_sha: String = {
        let db = state.db.get().ok()?;
        db.query_row(
            "SELECT sha256 FROM client_base_versions WHERE credential_id = ?1 AND path = ?2",
            rusqlite::params![credential_id, &db_path],
            |r| r.get(0),
        )
        .ok()?
    };

    let current_sha = compute_file_sha256(disk_path).ok()?;
    if current_sha == base_sha {
        // The client is writing from the version that is still current.
        return None;
    }

    // Only merge against a base we actually archived for this content.
    let base = versions::read_version(&state.blobs_root, &base_sha)?;
    let ours = std::fs::read(disk_path).ok()?;
    let theirs = std::fs::read(tmp_path).ok()?;

    if ours == theirs {
        return None;
    }

    match versions::merge_three_way(&base, &ours, &theirs)? {
        versions::MergeOutcome::Clean(text) => {
            info!(path = rel_path, "Merged concurrent edits cleanly");
            Some((text.into_bytes(), false))
        }
        versions::MergeOutcome::Conflicted(text) => {
            warn!(
                path = rel_path,
                "Concurrent edits overlap — wrote conflict markers"
            );
            Some((text.into_bytes(), true))
        }
    }
}

/// Pull the `Range` header out of a request, if present and valid UTF-8.
fn headers_range(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// A single byte range resolved against a known content length.
#[derive(Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    /// Inclusive.
    pub end: u64,
}

/// Outcome of parsing a `Range` header (RFC 9110 §14.1).
#[derive(Debug, PartialEq, Eq)]
pub enum RangeSpec {
    /// Serve this slice as 206.
    Satisfiable(ByteRange),
    /// Syntactically valid but entirely past the end — 416.
    Unsatisfiable,
    /// Not a byte range we understand. RFC 9110 §14.2 says to ignore it and
    /// serve the whole representation.
    Ignore,
}

/// Parse a `Range` header for a resource of `len` bytes.
///
/// Supports the forms video players actually send: `bytes=N-M`, `bytes=N-`
/// (remainder) and `bytes=-N` (suffix — needed by MP4s whose `moov` atom sits at
/// the end). Multi-range requests are deliberately ignored rather than answered
/// with multipart, which no media player requires.
pub fn parse_range(header: &str, len: u64) -> RangeSpec {
    let Some(spec) = header.trim().strip_prefix("bytes=") else {
        return RangeSpec::Ignore;
    };
    if spec.contains(',') {
        return RangeSpec::Ignore; // multi-range: serve whole body instead
    }
    let Some((start_s, end_s)) = spec.split_once('-') else {
        return RangeSpec::Ignore;
    };
    let (start_s, end_s) = (start_s.trim(), end_s.trim());

    // Suffix form: bytes=-N means "the last N bytes".
    if start_s.is_empty() {
        let Ok(n) = end_s.parse::<u64>() else {
            return RangeSpec::Ignore;
        };
        if n == 0 {
            return RangeSpec::Unsatisfiable;
        }
        if len == 0 {
            return RangeSpec::Unsatisfiable;
        }
        let n = n.min(len);
        return RangeSpec::Satisfiable(ByteRange {
            start: len - n,
            end: len - 1,
        });
    }

    let Ok(start) = start_s.parse::<u64>() else {
        return RangeSpec::Ignore;
    };
    if start >= len {
        return RangeSpec::Unsatisfiable;
    }
    let end = if end_s.is_empty() {
        len - 1
    } else {
        match end_s.parse::<u64>() {
            Ok(e) => e.min(len - 1),
            Err(_) => return RangeSpec::Ignore,
        }
    };
    if end < start {
        return RangeSpec::Unsatisfiable;
    }
    RangeSpec::Satisfiable(ByteRange { start, end })
}

/// SQL fragment excluding sibling mounts' rows from a bulk path operation.
///
/// All mounts share the `files` table and are distinguished only by a path
/// prefix — and the files mount's prefix is the empty string, so a directory
/// named `photos` or `notes` under `files/` collides with another mount's entire
/// namespace. Without this, a MOVE or DELETE of such a directory rewrites or
/// removes that mount's index (and, through `ON DELETE CASCADE`, its
/// user-applied photo tags, which unlike EXIF cannot be re-derived from disk).
fn sibling_mount_exclusion(state: &SharedDavState) -> String {
    if !state.db_path_prefix.is_empty() {
        return String::new();
    }
    SIBLING_MOUNT_PREFIXES
        .iter()
        .map(|p| format!(" AND path NOT LIKE '{}%'", p))
        .collect()
}

/// Nanosecond mtime, for cache-key comparison only.
///
/// HTTP `Last-Modified` stays second-granular per RFC 9110; this value is only
/// ever compared against a previously stored copy of itself.
fn mtime_nanos(md: &std::fs::Metadata) -> i64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(unix)]
fn inode_of(md: &std::fs::Metadata) -> i64 {
    use std::os::unix::fs::MetadataExt;
    md.ino() as i64
}

#[cfg(not(unix))]
fn inode_of(_md: &std::fs::Metadata) -> i64 {
    0
}

/// A matching `(mtime, size)` only proves "unchanged" once the file is old
/// enough that no later write could share its timestamp.
///
/// Coarse-granularity filesystems — and tools like `tar` and `rsync` that stamp
/// whole seconds — can give two different writes the same mtime. A same-length
/// edit inside one tick would then be indistinguishable from no edit at all.
/// Git calls such index entries "racily clean" and re-hashes them; so do we.
const RACY_WINDOW_NANOS: i64 = 2_000_000_000;

fn is_racily_clean(mtime: i64) -> bool {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(i64::MAX);
    now.saturating_sub(mtime) < RACY_WINDOW_NANOS
}

/// Write (or refresh) the stat-cache row for a path, preserving `oc_id`.
#[allow(clippy::too_many_arguments)]
fn upsert_file_row_conn(
    db: &rusqlite::Connection,
    db_path: &str,
    rel_path: &str,
    id: &str,
    etag: &str,
    sha256: Option<&str>,
    md: &std::fs::Metadata,
) {
    let is_dir = md.is_dir();
    let name = rel_path.rsplit('/').next().unwrap_or(rel_path).to_string();
    let parent = match db_path.rfind('/') {
        Some(idx) => db_path[..idx].to_string(),
        None => String::new(),
    };
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let content_type = if is_dir {
        "httpd/unix-directory".to_string()
    } else {
        mime_from_path(rel_path)
    };

    let _ = db.execute(
        "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag,
                            sha256, is_directory, created_at, modified_at, hlc,
                            mtime_nanos, inode)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?10, ?10, ?11, ?12)
         ON CONFLICT(path) DO UPDATE SET
            size_bytes = excluded.size_bytes,
            etag = excluded.etag,
            sha256 = excluded.sha256,
            modified_at = excluded.modified_at,
            hlc = excluded.hlc,
            mtime_nanos = excluded.mtime_nanos,
            inode = excluded.inode",
        rusqlite::params![
            id,
            db_path,
            parent,
            name,
            md.len() as i64,
            content_type,
            etag,
            sha256,
            is_dir as i32,
            now,
            mtime_nanos(md),
            inode_of(md),
        ],
    );
}

/// Resolve `(oc_id, etag)` for a path, treating **disk** as authoritative.
///
/// The `files` row is a cache, not the source of truth: when its
/// `(mtime_nanos, size_bytes)` still match what is on disk, the stored `etag` is
/// reused; otherwise the file is re-hashed and the row refreshed. That is what
/// makes out-of-band writes — `notes.append`, the CLI, rsync, a restic restore —
/// visible to sync clients without every writer having to remember to update the
/// index.
///
/// `oc_id` is persisted on first sight and never regenerated: Nextcloud-protocol
/// clients use it as stable file identity, so a fresh value makes every poll look
/// like a different file.
///
/// Returns `None` if the path does not exist on disk.
///
/// Blocking: may hash the file. Call from `spawn_blocking`, not the async runtime.
fn resolve_file_identity(state: &SharedDavState, rel_path: &str) -> Option<(String, String)> {
    let disk_path = state.files_root.join(rel_path);
    let md = disk_path.metadata().ok()?;
    resolve_from_metadata(state, rel_path, &disk_path, &md)
}

/// `resolve_file_identity` for a caller that already holds the metadata
/// (e.g. a directory listing), avoiding a second `stat`.
fn resolve_from_metadata(
    state: &SharedDavState,
    rel_path: &str,
    disk_path: &std::path::Path,
    md: &std::fs::Metadata,
) -> Option<(String, String)> {
    let db = state.db.get().ok()?;
    resolve_identity_conn(&db, &state.db_path(rel_path), rel_path, disk_path, md)
}

/// `resolve_from_metadata` against a plain connection, for callers outside the
/// server (the `reindex` CLI command).
fn resolve_identity_conn(
    db: &rusqlite::Connection,
    db_path: &str,
    rel_path: &str,
    disk_path: &std::path::Path,
    md: &std::fs::Metadata,
) -> Option<(String, String)> {
    let cached: Option<(String, String, Option<i64>, i64)> = {
        db.query_row(
            "SELECT id, etag, mtime_nanos, size_bytes FROM files WHERE path = ?1",
            [db_path],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<i64>>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            },
        )
        .ok()
    };

    // Directories are never hashed here — PROPFIND composes their ETag from
    // their children. All we need is a stable oc_id.
    if md.is_dir() {
        if let Some((id, etag, _, _)) = cached {
            return Some((id, etag));
        }
        let id = Uuid::new_v4().to_string();
        upsert_file_row_conn(db, db_path, rel_path, &id, "", None, md);
        return Some((id, String::new()));
    }

    let disk_mtime = mtime_nanos(md);
    let disk_size = md.len() as i64;

    if let Some((id, etag, Some(cached_mtime), cached_size)) = &cached
        && *cached_mtime == disk_mtime
        && *cached_size == disk_size
        && !is_racily_clean(disk_mtime)
    {
        return Some((id.clone(), etag.clone()));
    }

    let sha256 = compute_file_sha256(disk_path).ok()?;
    let etag = sha256[..16].to_string();
    let id = cached
        .map(|(id, _, _, _)| id)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    upsert_file_row_conn(db, db_path, rel_path, &id, &etag, Some(&sha256), md);
    Some((id, etag))
}

fn get_destination(headers: &HeaderMap) -> Option<String> {
    headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .and_then(|dest| {
            // Extract relative path from full URL or path
            // Support all DAV mount points: /dav/files/, /dav/photos/, /dav/notes/
            let path = {
                let mut result = None;
                for prefix in &["/dav/files/", "/dav/photos/", "/dav/notes/"] {
                    if let Some(idx) = dest.find(prefix) {
                        result = Some(dest[idx + prefix.len()..].trim_end_matches('/').to_string());
                        break;
                    }
                }
                result.unwrap_or_else(|| {
                    dest.trim_start_matches('/')
                        .trim_end_matches('/')
                        .to_string()
                })
            };
            // URL-decode the path (spaces, special characters)
            let decoded = urlencoding::decode(&path)
                .map(|s| s.into_owned())
                .unwrap_or(path);
            // Validate the decoded destination path against traversal attacks
            if is_safe_path(&decoded) {
                Some(decoded)
            } else {
                warn!(dest = %dest, "Path traversal blocked in Destination header");
                None
            }
        })
}

fn mime_from_path(path: &str) -> String {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" => "text/plain",
        "html" | "htm" => "text/html",
        "css" => "text/css",
        "js" => "application/javascript",
        "json" => "application/json",
        "xml" => "application/xml",
        "pdf" => "application/pdf",
        "zip" => "application/zip",
        "gz" | "gzip" => "application/gzip",
        "jpg" | "jpeg" => "image/jpeg",
        "png" => "image/png",
        "gif" => "image/gif",
        "webp" => "image/webp",
        "svg" => "image/svg+xml",
        // Keep in step with tilde_photos::VIDEO_EXTENSIONS — anything ingested as
        // video but served as application/octet-stream is downloaded by the
        // browser instead of played.
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "mkv" => "video/x-matroska",
        "avi" => "video/x-msvideo",
        "m4v" => "video/x-m4v",
        "mp3" => "audio/mpeg",
        "m4a" => "audio/mp4",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "flac" => "audio/flac",
        "wav" => "audio/wav",
        "md" | "markdown" => "text/markdown",
        "toml" => "application/toml",
        "yaml" | "yml" => "text/yaml",
        "heic" | "heif" => "image/heic",
        _ => "application/octet-stream",
    }
    .to_string()
}

struct PropfindResponse {
    href: String,
    is_dir: bool,
    size: u64,
    content_type: String,
    etag: String,
    modified: String,
    oc_id: String,
    custom_properties: Vec<(String, String, String)>, // (namespace, name, value)
}

fn propfind_entry(state: &SharedDavState, rel_path: &str, href: &str) -> PropfindResponse {
    let disk_path = state.files_root.join(rel_path);
    let is_dir = disk_path.is_dir() || rel_path.is_empty();

    let metadata = disk_path.metadata().ok();
    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

    let modified = metadata
        .as_ref()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let ts = jiff::Timestamp::from_second(duration.as_secs() as i64)
                .unwrap_or(jiff::Timestamp::UNIX_EPOCH);
            ts.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string()
        })
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());

    // Resolve identity against disk. A missing row is repaired rather than
    // papered over with a throwaway UUID and a size-derived ETag.
    let db_path = state.db_path(rel_path);
    let (oc_id, mut etag) = match metadata
        .as_ref()
        .and_then(|md| resolve_from_metadata(state, rel_path, &disk_path, md))
    {
        Some(pair) => pair,
        // Path vanished between the directory listing and this stat. Fall back
        // to a path-derived id so at least it is stable across requests.
        None => (
            format!("{:x}", Sha256::digest(db_path.as_bytes()))[..32].to_string(),
            String::new(),
        ),
    };

    // For directories, compute ETag from child names + their content ETags.
    // This changes when files are added, removed, OR modified — which is what
    // WebDAV clients (e.g. the webgallery app) rely on to detect changes.
    // Cost: one readdir + one DB query per directory.
    if is_dir {
        let target = if rel_path.is_empty() {
            &state.files_root
        } else {
            &disk_path
        };

        let mut hasher = Sha256::new();
        if let Ok(entries) = std::fs::read_dir(target) {
            let mut children: Vec<(String, std::path::PathBuf, std::fs::Metadata)> = entries
                .flatten()
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.starts_with('.') {
                        return None;
                    }
                    let meta = e.metadata().ok()?;
                    Some((name, e.path(), meta))
                })
                .collect();
            children.sort_by(|a, b| a.0.cmp(&b.0));
            for (name, child_disk, meta) in &children {
                hasher.update(name.as_bytes());
                if meta.is_dir() {
                    // For subdirectories, include mtime so changes inside
                    // propagate up (e.g. adding a file in 05/ changes 2026/ ETag)
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    hasher.update(mtime.to_le_bytes());
                } else {
                    // For files, include the content ETag so modifications
                    // propagate. Resolved against disk rather than read from the
                    // `files` table: a child with no row (or a stale one) used to
                    // contribute nothing here, so edits to it were invisible.
                    let child_rel = if rel_path.is_empty() {
                        name.clone()
                    } else {
                        format!("{}/{}", rel_path, name)
                    };
                    if let Some((_, child_etag)) =
                        resolve_from_metadata(state, &child_rel, child_disk, meta)
                    {
                        hasher.update(child_etag.as_bytes());
                    }
                }
                hasher.update(b"\0");
            }
        }
        let hash = format!("{:x}", hasher.finalize());
        etag = hash[..16].to_string();
    }

    // Load custom properties
    let custom_properties = {
        let db = state.db.get().unwrap();
        let mut stmt = db
            .prepare("SELECT namespace, name, value FROM file_properties WHERE file_path = ?1")
            .ok();
        match stmt.as_mut() {
            Some(stmt) => stmt
                .query_map([&db_path], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                    ))
                })
                .ok()
                .map(|rows| rows.filter_map(|r| r.ok()).collect())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    };

    PropfindResponse {
        href: href.to_string(),
        is_dir,
        size,
        content_type: if is_dir {
            "httpd/unix-directory".to_string()
        } else {
            mime_from_path(rel_path)
        },
        etag,
        modified,
        oc_id,
        custom_properties,
    }
}

fn build_multistatus_xml(responses: &[PropfindResponse]) -> String {
    let mut xml = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
"#,
    );

    for resp in responses {
        xml.push_str("  <d:response>\n");
        xml.push_str(&format!(
            "    <d:href>{}</d:href>\n",
            escape_xml(&resp.href)
        ));
        xml.push_str("    <d:propstat>\n");
        xml.push_str("      <d:prop>\n");

        if resp.is_dir {
            xml.push_str("        <d:resourcetype><d:collection/></d:resourcetype>\n");
        } else {
            xml.push_str("        <d:resourcetype/>\n");
            xml.push_str(&format!(
                "        <d:getcontentlength>{}</d:getcontentlength>\n",
                resp.size
            ));
            xml.push_str(&format!(
                "        <d:getcontenttype>{}</d:getcontenttype>\n",
                escape_xml(&resp.content_type)
            ));
        }

        xml.push_str(&format!(
            "        <d:getetag>\"{}\"</d:getetag>\n",
            escape_xml(&resp.etag)
        ));
        xml.push_str(&format!(
            "        <d:getlastmodified>{}</d:getlastmodified>\n",
            escape_xml(&resp.modified)
        ));
        xml.push_str(&format!(
            "        <oc:id>{}</oc:id>\n",
            escape_xml(&resp.oc_id)
        ));
        xml.push_str(&format!(
            "        <oc:fileid>{}</oc:fileid>\n",
            escape_xml(&resp.oc_id)
        ));
        xml.push_str("        <oc:permissions>RDNVCK</oc:permissions>\n");
        xml.push_str(&format!("        <oc:size>{}</oc:size>\n", resp.size));

        // Custom properties
        for (ns, name, value) in &resp.custom_properties {
            if ns == "DAV:" {
                xml.push_str(&format!(
                    "        <d:{}>{}</d:{}>\n",
                    escape_xml(name),
                    escape_xml(value),
                    escape_xml(name)
                ));
            } else {
                xml.push_str(&format!(
                    "        <x:{} xmlns:x=\"{}\">{}</x:{}>\n",
                    escape_xml(name),
                    escape_xml(ns),
                    escape_xml(value),
                    escape_xml(name)
                ));
            }
        }

        xml.push_str("      </d:prop>\n");
        xml.push_str("      <d:status>HTTP/1.1 200 OK</d:status>\n");
        xml.push_str("    </d:propstat>\n");
        xml.push_str("  </d:response>\n");
    }

    xml.push_str("</d:multistatus>\n");
    xml
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

/// Compute SHA-256 of a file using streaming reads (no full-file allocation)
fn compute_file_sha256(path: &std::path::Path) -> Result<String, std::io::Error> {
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

async fn copy_dir_recursive(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    tokio::fs::create_dir_all(dst).await?;
    let mut entries = tokio::fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let src_child = entry.path();
        let dst_child = dst.join(entry.file_name());
        if src_child.is_dir() {
            Box::pin(copy_dir_recursive(&src_child, &dst_child)).await?;
        } else {
            tokio::fs::copy(&src_child, &dst_child).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    // ─── parse_range ─────────────────────────────────────────────────────────

    #[test]
    fn parse_range_explicit_bounds() {
        assert_eq!(
            parse_range("bytes=0-9", 100),
            RangeSpec::Satisfiable(ByteRange { start: 0, end: 9 })
        );
    }

    #[test]
    fn parse_range_open_ended_runs_to_the_end() {
        assert_eq!(
            parse_range("bytes=90-", 100),
            RangeSpec::Satisfiable(ByteRange { start: 90, end: 99 })
        );
    }

    #[test]
    fn parse_range_suffix_takes_the_tail() {
        assert_eq!(
            parse_range("bytes=-10", 100),
            RangeSpec::Satisfiable(ByteRange { start: 90, end: 99 })
        );
    }

    #[test]
    fn parse_range_suffix_larger_than_file_clamps_to_whole_file() {
        assert_eq!(
            parse_range("bytes=-500", 100),
            RangeSpec::Satisfiable(ByteRange { start: 0, end: 99 })
        );
    }

    #[test]
    fn parse_range_end_past_eof_clamps() {
        assert_eq!(
            parse_range("bytes=50-9999", 100),
            RangeSpec::Satisfiable(ByteRange { start: 50, end: 99 })
        );
    }

    #[test]
    fn parse_range_start_past_eof_is_unsatisfiable() {
        assert_eq!(parse_range("bytes=100-200", 100), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=-0", 100), RangeSpec::Unsatisfiable);
    }

    #[test]
    fn parse_range_reversed_bounds_are_unsatisfiable() {
        assert_eq!(parse_range("bytes=50-10", 100), RangeSpec::Unsatisfiable);
    }

    /// RFC 9110 §14.2: an unrecognised range unit is ignored, not rejected.
    #[test]
    fn parse_range_unknown_unit_is_ignored() {
        assert_eq!(parse_range("furlongs=1-2", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("bytes=abc-def", 100), RangeSpec::Ignore);
        assert_eq!(parse_range("nonsense", 100), RangeSpec::Ignore);
    }

    /// Multi-range would require a multipart/byteranges body; no media player
    /// needs it, so we serve the whole representation instead.
    #[test]
    fn parse_range_multi_range_is_ignored() {
        assert_eq!(parse_range("bytes=0-9,20-29", 100), RangeSpec::Ignore);
    }

    #[test]
    fn parse_range_on_empty_file_is_unsatisfiable() {
        assert_eq!(parse_range("bytes=0-10", 0), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range("bytes=-5", 0), RangeSpec::Unsatisfiable);
    }

    // ─── version store GC ────────────────────────────────────────────────────

    #[test]
    fn gc_from_db_keeps_current_and_base_versions() {
        let (dir, conn) = test_db();
        let blobs = dir.path().join("blobs");
        let src = dir.path().join("scratch");

        std::fs::write(&src, "current").unwrap();
        let current = versions::archive_version(&blobs, &src).unwrap();
        std::fs::write(&src, "someones base").unwrap();
        let base = versions::archive_version(&blobs, &src).unwrap();
        std::fs::write(&src, "nobody wants this").unwrap();
        let orphan = versions::archive_version(&blobs, &src).unwrap();

        conn.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type,
                                etag, sha256, is_directory, created_at, modified_at, hlc)
             VALUES ('i', 'a.txt', '', 'a.txt', 7, 'text/plain', 'e', ?1, 0,
                     '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00',
                     '2026-01-01T00:00:00+00:00')",
            [&current],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO client_base_versions (credential_id, path, sha256, served_at)
             VALUES ('cred', 'a.txt', ?1, '2026-01-01T00:00:00+00:00')",
            [&base],
        )
        .unwrap();

        let removed = gc_versions_from_db(&conn, &blobs).unwrap();

        assert_eq!(removed, 1, "only the unreferenced blob should go");
        assert!(versions::read_version(&blobs, &current).is_some());
        assert!(
            versions::read_version(&blobs, &base).is_some(),
            "a client's recorded base must survive GC or its next write cannot merge"
        );
        assert!(versions::read_version(&blobs, &orphan).is_none());
    }

    // ─── reindex_tree ────────────────────────────────────────────────────────
    //
    // Phase 3.2: rebuild the `files` stat cache from disk. Needed after a restic
    // restore or any bulk out-of-band change, and to warm the cache after the
    // 009 migration so the first PROPFIND does not pay for every hash.

    fn test_db() -> (TempDir, rusqlite::Connection) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = tilde_core::db::init_db(db_path.to_str().unwrap()).unwrap();
        tilde_core::db::run_embedded_migrations(&conn).unwrap();
        (dir, conn)
    }

    fn row_for(conn: &rusqlite::Connection, path: &str) -> Option<(String, Option<i64>)> {
        conn.query_row(
            "SELECT etag, mtime_nanos FROM files WHERE path = ?1",
            [path],
            |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<i64>>(1)?)),
        )
        .ok()
    }

    #[test]
    fn reindex_tree_indexes_files_not_yet_in_db() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("a.txt"), "alpha").unwrap();
        fs::write(root.join("sub/b.txt"), "beta").unwrap();

        let stats = reindex_tree(&conn, &root, "", false).unwrap();

        assert_eq!(stats.indexed, 2, "both files should be indexed");
        assert!(row_for(&conn, "a.txt").is_some());
        assert!(row_for(&conn, "sub/b.txt").is_some());
    }

    /// The stat-cache row must carry the *full* sha256, not just the 16-char
    /// ETag: it is the content-addressed key the merge base store uses.
    #[test]
    fn reindex_tree_persists_full_sha256() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), "alpha").unwrap();

        reindex_tree(&conn, &root, "", false).unwrap();

        let sha: Option<String> = conn
            .query_row("SELECT sha256 FROM files WHERE path = 'a.txt'", [], |r| {
                r.get(0)
            })
            .unwrap();
        let sha = sha.expect("sha256 must be persisted");
        assert_eq!(sha.len(), 64, "full sha256 hex, got {:?}", sha);
        // sha256("alpha"), cross-checked against sha256sum and python hashlib
        assert_eq!(
            sha, "8ed3f6ad685b959ead7022518e1af76cd816f8e8ec7ccdda1ed4018e8f2223f8",
            "digest must be the real sha256 of the file content"
        );
    }

    #[test]
    fn reindex_tree_warms_the_stat_cache() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.txt"), "alpha").unwrap();

        reindex_tree(&conn, &root, "", false).unwrap();

        let (_etag, mtime) = row_for(&conn, "a.txt").unwrap();
        assert!(
            mtime.is_some(),
            "mtime_nanos must be populated, otherwise the next PROPFIND re-hashes"
        );
    }

    #[test]
    fn reindex_tree_applies_db_prefix() {
        let (dir, conn) = test_db();
        let root = dir.path().join("notes");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("n.md"), "# note").unwrap();

        reindex_tree(&conn, &root, "notes/", false).unwrap();

        assert!(
            row_for(&conn, "notes/n.md").is_some(),
            "notes mount rows are stored with the notes/ prefix"
        );
        assert!(row_for(&conn, "n.md").is_none());
    }

    #[test]
    fn reindex_tree_prunes_rows_for_deleted_files() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("kept.txt"), "here").unwrap();

        reindex_tree(&conn, &root, "", false).unwrap();

        // A row whose file no longer exists — e.g. deleted while the server was down.
        conn.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type,
                                etag, is_directory, created_at, modified_at, hlc)
             VALUES ('x', 'gone.txt', '', 'gone.txt', 4, 'text/plain', 'deadbeef', 0,
                     '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00',
                     '2026-01-01T00:00:00+00:00')",
            [],
        )
        .unwrap();

        let stats = reindex_tree(&conn, &root, "", true).unwrap();

        assert_eq!(stats.pruned, 1, "the orphaned row should be pruned");
        assert!(row_for(&conn, "gone.txt").is_none());
        assert!(
            row_for(&conn, "kept.txt").is_some(),
            "live rows must survive"
        );
    }

    #[test]
    fn reindex_tree_without_prune_keeps_orphans() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();

        conn.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type,
                                etag, is_directory, created_at, modified_at, hlc)
             VALUES ('x', 'gone.txt', '', 'gone.txt', 4, 'text/plain', 'deadbeef', 0,
                     '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00',
                     '2026-01-01T00:00:00+00:00')",
            [],
        )
        .unwrap();

        let stats = reindex_tree(&conn, &root, "", false).unwrap();

        assert_eq!(stats.pruned, 0);
        assert!(row_for(&conn, "gone.txt").is_some());
    }

    /// Every mount shares the `files` table, distinguished only by path prefix,
    /// and the files mount's prefix is empty. Pruning it must not sweep away the
    /// photos and notes mounts' rows.
    #[test]
    fn reindex_tree_prune_does_not_touch_sibling_mounts() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();

        for path in ["photos/2024/img.jpg", "notes/journal.md"] {
            conn.execute(
                "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type,
                                    etag, is_directory, created_at, modified_at, hlc)
                 VALUES (?1, ?1, '', 'x', 1, 'text/plain', 'abc', 0,
                         '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00',
                         '2026-01-01T00:00:00+00:00')",
                [path],
            )
            .unwrap();
        }

        let stats = reindex_tree(&conn, &root, "", true).unwrap();

        assert_eq!(stats.pruned, 0, "sibling mounts must be left alone");
        assert!(row_for(&conn, "photos/2024/img.jpg").is_some());
        assert!(row_for(&conn, "notes/journal.md").is_some());
    }

    #[test]
    fn reindex_tree_skips_hidden_files() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join(".hidden"), "x").unwrap();
        fs::write(root.join("visible.txt"), "y").unwrap();

        let stats = reindex_tree(&conn, &root, "", false).unwrap();

        // PROPFIND skips dotfiles, so indexing them would create rows no client
        // can ever see.
        assert_eq!(stats.indexed, 1);
        assert!(row_for(&conn, ".hidden").is_none());
    }

    #[test]
    fn reindex_tree_refreshes_a_stale_row() {
        let (dir, conn) = test_db();
        let root = dir.path().join("files");
        fs::create_dir_all(&root).unwrap();
        let f = root.join("a.txt");
        fs::write(&f, "before").unwrap();

        reindex_tree(&conn, &root, "", false).unwrap();
        let (etag1, _) = row_for(&conn, "a.txt").unwrap();

        fs::write(&f, "after").unwrap();
        reindex_tree(&conn, &root, "", false).unwrap();
        let (etag2, _) = row_for(&conn, "a.txt").unwrap();

        assert_ne!(etag1, etag2, "a changed file must get a fresh ETag");
    }

    // ─── is_safe_path ────────────────────────────────────────────────────────

    #[test]
    fn is_safe_path_normal_paths() {
        assert!(is_safe_path("file.txt"));
        assert!(is_safe_path("dir/file.txt"));
        assert!(is_safe_path("a/b/c/deep.txt"));
        assert!(is_safe_path(""));
    }

    #[test]
    fn is_safe_path_rejects_dot_dot() {
        assert!(!is_safe_path(".."));
        assert!(!is_safe_path("../etc/passwd"));
        assert!(!is_safe_path("a/../../etc/passwd"));
        assert!(!is_safe_path("a/b/../../../secret"));
    }

    #[test]
    fn is_safe_path_allows_dots_in_names() {
        // ".." as a segment is bad, but dots in filenames are fine
        assert!(is_safe_path("file..txt"));
        assert!(is_safe_path(".hidden"));
        assert!(is_safe_path("dir/.hidden/file"));
        assert!(is_safe_path("..."));
    }

    // ─── escape_like ─────────────────────────────────────────────────────────

    #[test]
    fn escape_like_no_special_chars() {
        assert_eq!(escape_like("photos/2024/img.jpg"), "photos/2024/img.jpg");
    }

    #[test]
    fn escape_like_percent() {
        assert_eq!(escape_like("100%done"), "100\\%done");
    }

    #[test]
    fn escape_like_underscore() {
        assert_eq!(escape_like("file_name"), "file\\_name");
    }

    #[test]
    fn escape_like_backslash() {
        assert_eq!(escape_like("path\\to\\file"), "path\\\\to\\\\file");
    }

    #[test]
    fn escape_like_all_special() {
        assert_eq!(escape_like("a%b_c\\d"), "a\\%b\\_c\\\\d");
    }

    // ─── ensure_within_root ──────────────────────────────────────────────────

    #[test]
    fn ensure_within_root_normal_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let file = root.join("hello.txt");
        fs::write(&file, "hi").unwrap();

        assert!(ensure_within_root(root, &file, &[]));
    }

    #[test]
    fn ensure_within_root_nested_file() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        let dir = root.join("sub/dir");
        fs::create_dir_all(&dir).unwrap();
        let file = dir.join("file.txt");
        fs::write(&file, "nested").unwrap();

        assert!(ensure_within_root(root, &file, &[]));
    }

    #[test]
    fn ensure_within_root_nonexistent_within() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path();
        // Target doesn't exist but ancestor does -- should still be within root
        let target = root.join("new_file.txt");

        assert!(ensure_within_root(root, &target, &[]));
    }

    #[test]
    fn ensure_within_root_rejects_outside() {
        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("webdav");
        fs::create_dir_all(&root).unwrap();
        // Try to escape via ..
        let target = root.join("../../../etc/passwd");

        assert!(!ensure_within_root(&root, &target, &[]));
    }

    // ─── get_destination ──────────────────────────────────────────────────────

    #[test]
    fn get_destination_extracts_relative_path() {
        let mut headers = HeaderMap::new();
        headers.insert("destination", "/dav/files/subdir/file.txt".parse().unwrap());
        assert_eq!(
            get_destination(&headers),
            Some("subdir/file.txt".to_string())
        );
    }

    #[test]
    fn get_destination_handles_full_url() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "destination",
            "https://example.com/dav/files/foo/bar.txt".parse().unwrap(),
        );
        assert_eq!(get_destination(&headers), Some("foo/bar.txt".to_string()));
    }

    #[test]
    fn get_destination_rejects_traversal() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "destination",
            "/dav/files/../../../etc/passwd".parse().unwrap(),
        );
        assert_eq!(get_destination(&headers), None);
    }

    #[test]
    fn get_destination_url_decodes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "destination",
            "/dav/files/my%20file%20name.txt".parse().unwrap(),
        );
        assert_eq!(
            get_destination(&headers),
            Some("my file name.txt".to_string())
        );
    }

    #[cfg(unix)]
    #[test]
    fn ensure_within_root_rejects_symlink_escape() {
        use std::os::unix::fs as unix_fs;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("webdav");
        fs::create_dir_all(&root).unwrap();

        // Create a symlink inside root that points outside
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), "secret").unwrap();

        let link = root.join("escape");
        unix_fs::symlink(&outside, &link).unwrap();

        let target = link.join("secret.txt");
        assert!(!ensure_within_root(&root, &target, &[]));
    }

    #[cfg(unix)]
    #[test]
    fn ensure_within_root_allows_symlink_to_allowlisted_dir() {
        use std::os::unix::fs as unix_fs;

        let tmp = TempDir::new().unwrap();
        let root = tmp.path().join("photos");
        fs::create_dir_all(&root).unwrap();

        // Simulate cache dir outside root with a thumbnail
        let cache = tmp.path().join("cache");
        let thumb_dir = cache.join("thumbnails").join("abc123");
        fs::create_dir_all(&thumb_dir).unwrap();
        fs::write(thumb_dir.join("256.webp"), "thumb").unwrap();

        // Create symlink inside root pointing to cache
        let link = root.join("thumb.webp");
        unix_fs::symlink(thumb_dir.join("256.webp"), &link).unwrap();

        // Without allowlist: blocked
        assert!(!ensure_within_root(&root, &link, &[]));
        // With allowlist: allowed
        assert!(ensure_within_root(&root, &link, &[cache.clone()]));
    }
}
