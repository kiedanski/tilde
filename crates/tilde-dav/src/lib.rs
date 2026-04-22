//! tilde-dav: WebDAV Class 1 file serving
//!
//! Handles OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH

use axum::{
    Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::any,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use uuid::Uuid;

/// State needed by DAV handlers
pub struct DavState {
    pub db: Arc<Mutex<Connection>>,
    pub files_root: PathBuf,
    pub uploads_root: PathBuf,
}

pub type SharedDavState = Arc<DavState>;

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
            (
                "Allow",
                "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH",
            ),
        ],
    )
        .into_response()
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
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    headers.insert(header::CONTENT_LENGTH, HeaderValue::from(metadata.len()));
    if let Some(etag) = etag {
        headers.insert(
            header::ETAG,
            HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
        );
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
async fn handle_put(
    state: &SharedDavState,
    rel_path: &str,
    headers: &HeaderMap,
    body: Body,
) -> Response {
    // Check If-Match precondition
    if let Some(if_match) = headers.get("if-match").and_then(|v| v.to_str().ok()) {
        let expected_etag = if_match.trim_matches('"');
        if let Some(current_etag) = get_etag_for_file(state, rel_path)
            && current_etag != expected_etag
        {
            return StatusCode::PRECONDITION_FAILED.into_response();
        }
    }

    let disk_path = state.files_root.join(rel_path);

    // Ensure parent directory exists
    if let Some(parent) = disk_path.parent()
        && !parent.exists()
    {
        return (StatusCode::CONFLICT, "Parent collection does not exist").into_response();
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
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

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

        let existing_id: Option<String> = db
            .query_row("SELECT id FROM files WHERE path = ?1", [rel_path], |row| {
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
            rusqlite::params![id, rel_path, parent_path, file_name, content.len(), content_type, etag, sha256, now, now, now],
        ).ok();
    }

    let status = if exists {
        StatusCode::NO_CONTENT
    } else {
        StatusCode::CREATED
    };
    let mut resp_headers = HeaderMap::new();
    resp_headers.insert(
        header::ETAG,
        HeaderValue::from_str(&format!("\"{}\"", etag)).unwrap(),
    );
    resp_headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_str(&content_type)
            .unwrap_or(HeaderValue::from_static("application/octet-stream")),
    );
    if !exists && let Ok(loc) = HeaderValue::from_str(&format!("/dav/files/{}", rel_path)) {
        resp_headers.insert(header::LOCATION, loc);
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
        db.execute(
            "DELETE FROM files WHERE path = ?1 OR path LIKE ?2",
            rusqlite::params![rel_path, pattern],
        )
        .ok();
    } else {
        if let Err(e) = tokio::fs::remove_file(&disk_path).await {
            warn!(error = %e, "Failed to remove file");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let db = state.db.lock().unwrap();
        db.execute("DELETE FROM files WHERE path = ?1", [rel_path])
            .ok();
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
        let db = state.db.lock().unwrap();
        let dest_name = std::path::Path::new(&dest)
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        let dest_parent = std::path::Path::new(&dest)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();

        db.execute(
            "UPDATE files SET path = ?1, parent_path = ?2, name = ?3, modified_at = ?4 WHERE path = ?5",
            rusqlite::params![dest, dest_parent, dest_name, now, rel_path],
        ).ok();

        // If directory, update children paths too
        if dst_disk.is_dir() {
            let old_prefix = format!("{}/", rel_path);
            let new_prefix = format!("{}/", dest);
            let mut stmt = db
                .prepare("SELECT id, path FROM files WHERE path LIKE ?1")
                .unwrap();
            let children: Vec<(String, String)> = stmt
                .query_map([format!("{}%", old_prefix)], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
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

    let overwrite = dst_disk.exists();

    if src_disk.is_dir() {
        copy_dir_recursive(&src_disk, &dst_disk).await.ok();
    } else if let Err(e) = tokio::fs::copy(&src_disk, &dst_disk).await {
        warn!(error = %e, "Failed to copy");
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
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
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
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

    let depth = headers
        .get("depth")
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
                let child_href = format!("/dav/files/{}", child_rel);
                responses.push(propfind_entry(state, &child_rel, &child_href));
            }
        }
    }

    let xml = build_multistatus_xml(&responses);

    (
        StatusCode::MULTI_STATUS,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        xml,
    )
        .into_response()
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

    let href = if rel_path.is_empty() {
        "/dav/files/".to_string()
    } else {
        format!("/dav/files/{}", rel_path)
    };

    let mut prop_results = Vec::new();

    {
        let db = state.db.lock().unwrap();
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
                        rusqlite::params![rel_path, namespace, name, value],
                    ).ok();
                    prop_results.push((namespace.clone(), name.clone(), true));
                }
                PropPatchOp::Remove { namespace, name } => {
                    db.execute(
                        "DELETE FROM file_properties WHERE file_path = ?1 AND namespace = ?2 AND name = ?3",
                        rusqlite::params![rel_path, namespace, name],
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
    let path_str = path.map(|Path(p)| p).unwrap_or_default();
    let rel_path = path_str.trim_start_matches('/');

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
                let db = state.db.lock().unwrap();
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

            // Stream chunk to disk
            let content = match axum::body::to_bytes(body, 10 * 1024 * 1024 * 1024).await {
                Ok(bytes) => bytes,
                Err(_) => return StatusCode::BAD_REQUEST.into_response(),
            };

            let chunk_size = content.len() as i64;
            if let Err(e) = tokio::fs::write(&chunk_path, &content).await {
                warn!(error = %e, "Failed to write chunk");
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }

            // Update session tracking
            {
                let db = state.db.lock().unwrap();
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

            // Get destination from headers
            let dest = match headers.get("destination").and_then(|v| v.to_str().ok()) {
                Some(d) => {
                    if let Some(idx) = d.find("/dav/files/") {
                        d[idx + "/dav/files/".len()..]
                            .trim_end_matches('/')
                            .to_string()
                    } else {
                        d.trim_start_matches('/').trim_end_matches('/').to_string()
                    }
                }
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
            if let Some(parent) = dest_path.parent() {
                tokio::fs::create_dir_all(parent).await.ok();
            }

            // Assemble into destination file
            let tmp_path = dest_path.with_extension("tmp_tilde_chunked");
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
                let db = state.db.lock().unwrap();
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

fn get_etag_for_file(state: &SharedDavState, rel_path: &str) -> Option<String> {
    let db = state.db.lock().unwrap();
    db.query_row(
        "SELECT etag FROM files WHERE path = ?1",
        [rel_path],
        |row| row.get(0),
    )
    .ok()
}

fn get_destination(headers: &HeaderMap) -> Option<String> {
    headers
        .get("destination")
        .and_then(|v| v.to_str().ok())
        .map(|dest| {
            // Extract relative path from full URL or path
            if let Some(idx) = dest.find("/dav/files/") {
                dest[idx + "/dav/files/".len()..]
                    .trim_end_matches('/')
                    .to_string()
            } else {
                dest.trim_start_matches('/')
                    .trim_end_matches('/')
                    .to_string()
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

    // Try to get oc:id and etag from DB
    let (oc_id, etag) = {
        let db = state.db.lock().unwrap();
        db.query_row(
            "SELECT id, etag FROM files WHERE path = ?1",
            [rel_path],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        )
        .unwrap_or_else(|_| (Uuid::new_v4().to_string(), format!("{:x}", size)))
    };

    // Load custom properties
    let custom_properties = {
        let db = state.db.lock().unwrap();
        let mut stmt = db
            .prepare("SELECT namespace, name, value FROM file_properties WHERE file_path = ?1")
            .ok();
        match stmt.as_mut() {
            Some(stmt) => stmt
                .query_map([rel_path], |row| {
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
