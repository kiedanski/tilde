//! tilde-dav: WebDAV Class 1 file serving
//!
//! Handles OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, Method, StatusCode, header, HeaderValue},
    response::{IntoResponse, Response},
    routing::any,
};
use rusqlite::Connection;
use sha2::{Sha256, Digest};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

/// State needed by DAV handlers
pub struct DavState {
    pub db: Arc<Mutex<Connection>>,
    pub files_root: PathBuf,
}

pub type SharedDavState = Arc<DavState>;

/// Build the WebDAV router — mount at /dav/files/
pub fn build_dav_router(state: SharedDavState) -> Router {
    Router::new()
        .route("/", any(dav_handler))
        .route("/{*path}", any(dav_handler))
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
    let path_str = path.map(|Path(p)| p).unwrap_or_default();
    let rel_path = path_str.trim_start_matches('/');

    match method.as_str() {
        "OPTIONS" => handle_options().await,
        "HEAD" => handle_get(&state, rel_path, true).await,
        "GET" => handle_get(&state, rel_path, false).await,
        "PUT" => handle_put(&state, rel_path, &headers, body).await,
        "DELETE" => handle_delete(&state, rel_path).await,
        "MKCOL" => handle_mkcol(&state, rel_path).await,
        "MOVE" => handle_move(&state, rel_path, &headers).await,
        "COPY" => handle_copy(&state, rel_path, &headers).await,
        "PROPFIND" => handle_propfind(&state, rel_path, &headers).await,
        "PROPPATCH" => handle_proppatch(&state, rel_path, body).await,
        "LOCK" => {
            // macOS Finder sends LOCK — respond 200 OK (FakeLs pattern)
            StatusCode::OK.into_response()
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
            ("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH"),
        ],
    ).into_response()
}

/// GET / HEAD — download a file
async fn handle_get(state: &SharedDavState, rel_path: &str, head_only: bool) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    if disk_path.is_dir() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    let content_type = mime_from_path(rel_path);
    let metadata = match disk_path.metadata() {
        Ok(m) => m,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let etag = get_etag_for_file(state, rel_path);

    let mut headers = HeaderMap::new();
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(&content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(metadata.len()));
    if let Some(etag) = etag {
        headers.insert(header::ETAG, HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap());
    }

    if head_only {
        return (StatusCode::OK, headers).into_response();
    }

    match tokio::fs::read(&disk_path).await {
        Ok(content) => (StatusCode::OK, headers, content).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

/// PUT — upload a file atomically
async fn handle_put(state: &SharedDavState, rel_path: &str, headers: &HeaderMap, body: Body) -> Response {
    // Check If-Match precondition
    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        let expected_etag = if_match.trim_matches('"');
        if let Some(current_etag) = get_etag_for_file(state, rel_path) {
            if current_etag != expected_etag {
                return StatusCode::PRECONDITION_FAILED.into_response();
            }
        }
    }

    let disk_path = state.files_root.join(rel_path);

    // Ensure parent directory exists
    if let Some(parent) = disk_path.parent() {
        if !parent.exists() {
            return (StatusCode::CONFLICT, "Parent collection does not exist").into_response();
        }
    }

    let exists = disk_path.exists();

    // Read body
    let content = match axum::body::to_bytes(body, 10 * 1024 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return StatusCode::BAD_REQUEST.into_response(),
    };

    // Atomic write: write to tmp, then rename
    let tmp_path = disk_path.with_extension("tmp_tilde_upload");
    if let Err(e) = tokio::fs::write(&tmp_path, &content).await {
        warn!(error = %e, path = %disk_path.display(), "Failed to write tmp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    if let Err(e) = tokio::fs::rename(&tmp_path, &disk_path).await {
        let _ = tokio::fs::remove_file(&tmp_path).await;
        warn!(error = %e, "Failed to rename tmp file");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Compute SHA-256 and ETag
    let mut hasher = Sha256::new();
    hasher.update(&content);
    let sha256 = format!("{:x}", hasher.finalize());
    let etag = sha256[..16].to_string();

    let content_type = mime_from_path(rel_path);
    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    // Upsert into files table
    {
        let db = state.db.lock().unwrap();
        let file_name = std::path::Path::new(rel_path)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let parent_path = std::path::Path::new(rel_path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();

        let existing_id: Option<String> = db.query_row(
            "SELECT id FROM files WHERE path = ?1",
            [rel_path],
            |row| row.get(0),
        ).ok();

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
            rusqlite::params![id, rel_path, parent_path, file_name, content.len(), content_type, etag, sha256, now, now, now],
        ).ok();
    }

    let status = if exists { StatusCode::NO_CONTENT } else { StatusCode::CREATED };
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(header::ETAG, HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap());
    resp_headers.insert(header::CONTENT_TYPE, HeaderValue::from_str(&content_type).unwrap_or(HeaderValue::from_static("application/octet-stream")));
    if !exists {
        if let Ok(loc) = HeaderValue::from_str(&format!("/dav/files/{}", rel_path)) {
            resp_headers.insert(header::LOCATION, loc);
        }
    }

    info!(path = rel_path, size = content.len(), "WebDAV PUT");
    (status, resp_headers).into_response()
}

/// DELETE — remove a file or collection
async fn handle_delete(state: &SharedDavState, rel_path: &str) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() {
        return StatusCode::NOT_FOUND.into_response();
    }

    if disk_path.is_dir() {
        if let Err(e) = tokio::fs::remove_dir_all(&disk_path).await {
            warn!(error = %e, "Failed to remove directory");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        // Remove from DB recursively
        let db = state.db.lock().unwrap();
        let pattern = format!("{}%", rel_path);
        db.execute("DELETE FROM files WHERE path = ?1 OR path LIKE ?2", rusqlite::params![rel_path, pattern]).ok();
    } else {
        if let Err(e) = tokio::fs::remove_file(&disk_path).await {
            warn!(error = %e, "Failed to remove file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let db = state.db.lock().unwrap();
        db.execute("DELETE FROM files WHERE path = ?1", [rel_path]).ok();
    }

    info!(path = rel_path, "WebDAV DELETE");
    StatusCode::NO_CONTENT.into_response()
}

/// MKCOL — create a collection (directory)
async fn handle_mkcol(state: &SharedDavState, rel_path: &str) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if disk_path.exists() {
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    // Check parent exists
    if let Some(parent) = disk_path.parent() {
        if !parent.exists() {
            return StatusCode::CONFLICT.into_response();
        }
    }

    if let Err(e) = tokio::fs::create_dir(&disk_path).await {
        warn!(error = %e, "Failed to create directory");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Record in DB
    let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let id = Uuid::new_v4().to_string();
    let name = std::path::Path::new(rel_path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_path = std::path::Path::new(rel_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    {
        let db = state.db.lock().unwrap();
        db.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag, is_directory, created_at, modified_at, hlc)
             VALUES (?1, ?2, ?3, ?4, 0, 'httpd/unix-directory', ?5, 1, ?6, ?7, ?8)",
            rusqlite::params![id, rel_path, parent_path, name, id, now, now, now],
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

    // Ensure destination parent exists
    if let Some(parent) = dst_disk.parent() {
        if !parent.exists() {
            return StatusCode::CONFLICT.into_response();
        }
    }

    let overwrite = dst_disk.exists();

    if let Err(e) = tokio::fs::rename(&src_disk, &dst_disk).await {
        warn!(error = %e, "Failed to move");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Update DB — preserve the UUID (oc:id)
    {
        let db = state.db.lock().unwrap();
        let dest_name = std::path::Path::new(&dest)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let dest_parent = std::path::Path::new(&dest)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

        db.execute(
            "UPDATE files SET path = ?1, parent_path = ?2, name = ?3, modified_at = ?4 WHERE path = ?5",
            rusqlite::params![dest, dest_parent, dest_name, now, rel_path],
        ).ok();

        // If directory, update children paths too
        if dst_disk.is_dir() {
            let old_prefix = format!("{}/", rel_path);
            let new_prefix = format!("{}/", dest);
            let mut stmt = db.prepare("SELECT id, path FROM files WHERE path LIKE ?1").unwrap();
            let children: Vec<(String, String)> = stmt.query_map([format!("{}%", old_prefix)], |row| {
                Ok((row.get(0)?, row.get(1)?))
            }).unwrap().filter_map(|r| r.ok()).collect();

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
                ).ok();
            }
        }
    }

    info!(from = rel_path, to = %dest, "WebDAV MOVE");
    if overwrite { StatusCode::NO_CONTENT } else { StatusCode::CREATED }.into_response()
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

    let overwrite = dst_disk.exists();

    if src_disk.is_dir() {
        copy_dir_recursive(&src_disk, &dst_disk).await.ok();
    } else {
        if let Err(e) = tokio::fs::copy(&src_disk, &dst_disk).await {
            warn!(error = %e, "Failed to copy");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    }

    // Create new DB record with new UUID
    {
        let db = state.db.lock().unwrap();
        if let Ok(content) = std::fs::read(&dst_disk) {
            let mut hasher = Sha256::new();
            hasher.update(&content);
            let sha256 = format!("{:x}", hasher.finalize());
            let etag = sha256[..16].to_string();
            let content_type = mime_from_path(&dest);
            let now = jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
            let id = Uuid::new_v4().to_string();
            let name = std::path::Path::new(&dest)
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            let parent_path = std::path::Path::new(&dest)
                .parent()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            db.execute(
                "INSERT OR REPLACE INTO files (id, path, parent_path, name, size_bytes, content_type, etag, sha256, is_directory, created_at, modified_at, hlc)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)",
                rusqlite::params![id, dest, parent_path, name, content.len(), content_type, etag, sha256, now, now, now],
            ).ok();
        }
    }

    info!(from = rel_path, to = %dest, "WebDAV COPY");
    if overwrite { StatusCode::NO_CONTENT } else { StatusCode::CREATED }.into_response()
}

/// PROPFIND — return properties for a resource
async fn handle_propfind(state: &SharedDavState, rel_path: &str, headers: &HeaderMap) -> Response {
    let disk_path = state.files_root.join(rel_path);

    if !disk_path.exists() && !rel_path.is_empty() {
        return StatusCode::NOT_FOUND.into_response();
    }

    let depth = headers.get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0");

    let mut responses = Vec::new();

    // Add the requested resource itself
    let href = if rel_path.is_empty() {
        "/dav/files/".to_string()
    } else {
        format!("/dav/files/{}", rel_path)
    };
    responses.push(propfind_entry(state, rel_path, &href));

    // If Depth: 1 and it's a directory, add children
    if depth == "1" && (disk_path.is_dir() || rel_path.is_empty()) {
        let target = if rel_path.is_empty() { &state.files_root } else { &disk_path };
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
                let child_href = format!("/dav/files/{}", child_rel);
                responses.push(propfind_entry(state, &child_rel, &child_href));
            }
        }
    }

    let xml = build_multistatus_xml(&responses);

    (
        StatusCode::MULTI_STATUS,
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
        ],
        xml,
    ).into_response()
}

/// PROPPATCH — set/remove custom properties (minimal stub)
async fn handle_proppatch(_state: &SharedDavState, _rel_path: &str, _body: Body) -> Response {
    // Minimal implementation — acknowledge the request
    let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:">
  <d:response>
    <d:propstat>
      <d:status>HTTP/1.1 200 OK</d:status>
    </d:propstat>
  </d:response>
</d:multistatus>"#;

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml.to_string(),
    ).into_response()
}

// ---- Helper functions ----

fn get_etag_for_file(state: &SharedDavState, rel_path: &str) -> Option<String> {
    let db = state.db.lock().unwrap();
    db.query_row(
        "SELECT etag FROM files WHERE path = ?1",
        [rel_path],
        |row| row.get(0),
    ).ok()
}

fn get_destination(headers: &HeaderMap) -> Option<String> {
    headers.get("destination")
        .and_then(|v| v.to_str().ok())
        .map(|dest| {
            // Extract relative path from full URL or path
            if let Some(idx) = dest.find("/dav/files/") {
                dest[idx + "/dav/files/".len()..].trim_end_matches('/').to_string()
            } else {
                dest.trim_start_matches('/').trim_end_matches('/').to_string()
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
        "mp4" => "video/mp4",
        "webm" => "video/webm",
        "mp3" => "audio/mpeg",
        "md" | "markdown" => "text/markdown",
        "toml" => "application/toml",
        "yaml" | "yml" => "text/yaml",
        "heic" | "heif" => "image/heic",
        _ => "application/octet-stream",
    }.to_string()
}

struct PropfindResponse {
    href: String,
    is_dir: bool,
    size: u64,
    content_type: String,
    etag: String,
    modified: String,
    oc_id: String,
}

fn propfind_entry(state: &SharedDavState, rel_path: &str, href: &str) -> PropfindResponse {
    let disk_path = state.files_root.join(rel_path);
    let is_dir = disk_path.is_dir() || rel_path.is_empty();

    let metadata = disk_path.metadata().ok();
    let size = metadata.as_ref().map(|m| m.len()).unwrap_or(0);

    let modified = metadata.as_ref()
        .and_then(|m| m.modified().ok())
        .map(|t| {
            let duration = t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default();
            let ts = jiff::Timestamp::from_second(duration.as_secs() as i64).unwrap_or(jiff::Timestamp::UNIX_EPOCH);
            ts.strftime("%a, %d %b %Y %H:%M:%S GMT").to_string()
        })
        .unwrap_or_else(|| "Thu, 01 Jan 1970 00:00:00 GMT".to_string());

    // Try to get oc:id and etag from DB
    let (oc_id, etag) = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT id, etag FROM files WHERE path = ?1",
            [rel_path],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).unwrap_or_else(|_| (Uuid::new_v4().to_string(), format!("{:x}", size)))
    };

    PropfindResponse {
        href: href.to_string(),
        is_dir,
        size,
        content_type: if is_dir { "httpd/unix-directory".to_string() } else { mime_from_path(rel_path) },
        etag,
        modified,
        oc_id,
    }
}

fn build_multistatus_xml(responses: &[PropfindResponse]) -> String {
    let mut xml = String::from(r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns" xmlns:nc="http://nextcloud.org/ns">
"#);

    for resp in responses {
        xml.push_str("  <d:response>\n");
        xml.push_str(&format!("    <d:href>{}</d:href>\n", escape_xml(&resp.href)));
        xml.push_str("    <d:propstat>\n");
        xml.push_str("      <d:prop>\n");

        if resp.is_dir {
            xml.push_str("        <d:resourcetype><d:collection/></d:resourcetype>\n");
        } else {
            xml.push_str("        <d:resourcetype/>\n");
            xml.push_str(&format!("        <d:getcontentlength>{}</d:getcontentlength>\n", resp.size));
            xml.push_str(&format!("        <d:getcontenttype>{}</d:getcontenttype>\n", escape_xml(&resp.content_type)));
        }

        xml.push_str(&format!("        <d:getetag>\"{}\"</d:getetag>\n", escape_xml(&resp.etag)));
        xml.push_str(&format!("        <d:getlastmodified>{}</d:getlastmodified>\n", escape_xml(&resp.modified)));
        xml.push_str(&format!("        <oc:id>{}</oc:id>\n", escape_xml(&resp.oc_id)));
        xml.push_str(&format!("        <oc:fileid>{}</oc:fileid>\n", escape_xml(&resp.oc_id)));
        xml.push_str("        <oc:permissions>RDNVCK</oc:permissions>\n");
        xml.push_str(&format!("        <oc:size>{}</oc:size>\n", resp.size));

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
