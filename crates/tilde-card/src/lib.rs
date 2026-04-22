//! tilde-card: CardDAV handler (RFC 6352)

use axum::{
    Router,
    extract::{Path as AxumPath, State},
    http::{HeaderValue, Method, StatusCode, header},
    response::IntoResponse,
    routing::any,
};
use rusqlite::Connection;
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};
use tilde_core::auth;

pub struct CardDavState {
    pub db: Arc<Mutex<Connection>>,
    pub session_ttl_hours: u32,
}

pub type SharedCardDavState = Arc<CardDavState>;

pub fn build_carddav_router(state: SharedCardDavState) -> Router {
    Router::new()
        .route("/", any(carddav_root_handler))
        .route("/{*path}", any(carddav_handler))
        .with_state(state)
}

pub fn ensure_default_addressbook(db: &Connection) {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db.execute(
        "INSERT OR IGNORE INTO addressbooks (id, name, display_name, ctag, sync_token, created_at, updated_at)
         VALUES (?1, 'default', 'Contacts', '1', 0, ?2, ?3)",
        rusqlite::params![uuid::Uuid::new_v4().to_string(), now, now],
    );
}

fn compute_etag(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
        .chars()
        .take(16)
        .collect()
}

fn xml_response(status: StatusCode, body: String) -> axum::response::Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn carddav_root_handler(
    method: Method,
    State(state): State<SharedCardDavState>,
    req: axum::extract::Request,
) -> axum::response::Response {
    handle_request(&state, method, "", req).await
}

async fn carddav_handler(
    method: Method,
    State(state): State<SharedCardDavState>,
    AxumPath(path): AxumPath<String>,
    req: axum::extract::Request,
) -> axum::response::Response {
    handle_request(&state, method, &path, req).await
}

fn check_auth(
    state: &SharedCardDavState,
    req: &axum::extract::Request,
    scope_prefix: &str,
) -> bool {
    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    match auth_header {
        Some(ref h) if h.starts_with("Bearer ") => {
            let token = &h[7..];
            let db = state.db.lock().unwrap();
            if token.starts_with("tilde_session_") {
                auth::validate_session(&db, token, state.session_ttl_hours).unwrap_or(false)
            } else {
                false
            }
        }
        Some(ref h) if h.starts_with("Basic ") => {
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &h[6..])
                    .ok()
                    .and_then(|bytes| String::from_utf8(bytes).ok());
            if let Some(creds) = decoded {
                if let Some((_user, password)) = creds.split_once(':') {
                    let db = state.db.lock().unwrap();
                    if auth::verify_admin_password(&db, password).unwrap_or(false) {
                        return true;
                    }
                    auth::verify_app_password(&db, password, scope_prefix).unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

async fn handle_request(
    state: &SharedCardDavState,
    method: Method,
    path: &str,
    req: axum::extract::Request,
) -> axum::response::Response {
    if !check_auth(state, &req, "/carddav/") {
        return (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"tilde\"")],
        )
            .into_response();
    }
    let depth = req
        .headers()
        .get("depth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("0")
        .to_string();
    let if_match = req
        .headers()
        .get(header::IF_MATCH)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let body = match axum::body::to_bytes(req.into_body(), 10_485_760).await {
        Ok(b) => String::from_utf8_lossy(&b).to_string(),
        Err(_) => return StatusCode::PAYLOAD_TOO_LARGE.into_response(),
    };

    match method.as_str() {
        "OPTIONS" => {
            let mut resp = StatusCode::OK.into_response();
            resp.headers_mut().insert(
                header::HeaderName::from_static("dav"),
                HeaderValue::from_static("1, 2, 3, addressbook"),
            );
            resp.headers_mut().insert(
                header::HeaderName::from_static("allow"),
                HeaderValue::from_static(
                    "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCOL",
                ),
            );
            resp
        }
        "PROPFIND" => handle_propfind(state, path, &depth),
        "PROPPATCH" => handle_proppatch(state, path, &body),
        "MKCOL" => handle_mkcol(state, path, &body),
        "PUT" => handle_put(state, path, &body, if_match.as_deref()),
        "GET" => handle_get(state, path),
        "DELETE" => handle_delete(state, path),
        "REPORT" => handle_report(state, path, &body),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

fn parse_path(path: &str) -> (Option<&str>, Option<&str>, Option<&str>) {
    let path = path.trim_start_matches('/');
    let parts: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    match parts.len() {
        0 => (None, None, None),
        1 => (Some(parts[0]), None, None),
        2 => (Some(parts[0]), Some(parts[1]), None),
        _ => (Some(parts[0]), Some(parts[1]), Some(parts[2])),
    }
}

fn handle_propfind(
    state: &SharedCardDavState,
    path: &str,
    depth: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (principal, ab_name, contact_name) = parse_path(path);

    if principal.is_none() || (principal.is_some() && ab_name.is_none()) {
        let mut responses = String::new();
        let href = if let Some(p) = principal {
            format!("/carddav/{}/", p)
        } else {
            "/carddav/".to_string()
        };
        responses.push_str(&format!(
            r#"<d:response>
  <d:href>{}</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/></d:resourcetype>
      <d:current-user-principal><d:href>/principals/admin/</d:href></d:current-user-principal>
      <d:displayname>CardDAV</d:displayname>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
            href
        ));

        if depth == "1" {
            let p = principal.unwrap_or("admin");
            let mut stmt = db
                .prepare(
                    "SELECT name, display_name, ctag, description, sync_token FROM addressbooks",
                )
                .unwrap();
            let abs = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, i64>(4)?,
                    ))
                })
                .unwrap();
            for ab in abs.flatten() {
                let (name, display_name, ctag, desc, sync_token) = ab;
                let desc_xml = desc
                    .map(|d| {
                        format!(
                            "<card:addressbook-description>{}</card:addressbook-description>",
                            escape_xml(&d)
                        )
                    })
                    .unwrap_or_default();
                responses.push_str(&format!(
                    r#"
<d:response>
  <d:href>/carddav/{}/{}/</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
      <d:displayname>{}</d:displayname>
      <cs:getctag xmlns:cs="http://calendarserver.org/ns/">{}</cs:getctag>
      <d:sync-token>http://tilde.local/sync/{}</d:sync-token>
      {}
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                    p,
                    name,
                    escape_xml(&display_name),
                    ctag,
                    sync_token,
                    desc_xml
                ));
            }
        }

        return xml_response(
            StatusCode::MULTI_STATUS,
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
{}</d:multistatus>"#,
                responses
            ),
        );
    }

    if let Some(ab_name) = ab_name {
        if let Some(contact_name) = contact_name {
            let uid = contact_name.trim_end_matches(".vcf");
            match db.query_row(
                "SELECT c.uid, c.etag FROM contacts c JOIN addressbooks a ON c.addressbook_id = a.id
                 WHERE a.name = ?1 AND c.uid = ?2 AND c.deleted = 0",
                rusqlite::params![ab_name, uid],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ) {
                Ok((uid, etag)) => {
                    let p = principal.unwrap_or("admin");
                    xml_response(StatusCode::MULTI_STATUS, format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <d:getcontenttype>text/vcard; charset=utf-8</d:getcontenttype>
      <d:resourcetype/>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>
</d:multistatus>"#, p, ab_name, uid, etag))
                }
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        } else {
            // Addressbook PROPFIND
            match db.query_row(
                "SELECT id, display_name, ctag, description, sync_token FROM addressbooks WHERE name = ?1",
                [ab_name], |row| Ok((
                    row.get::<_, String>(0)?, row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?, row.get::<_, Option<String>>(3)?,
                    row.get::<_, i64>(4)?,
                )),
            ) {
                Ok((ab_id, display_name, ctag, desc, sync_token)) => {
                    let p = principal.unwrap_or("admin");
                    let desc_xml = desc.map(|d| format!("<card:addressbook-description>{}</card:addressbook-description>", escape_xml(&d))).unwrap_or_default();
                    let mut responses = format!(
                        r#"<d:response>
  <d:href>/carddav/{}/{}/</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
      <d:displayname>{}</d:displayname>
      <cs:getctag xmlns:cs="http://calendarserver.org/ns/">{}</cs:getctag>
      <d:sync-token>http://tilde.local/sync/{}</d:sync-token>
      {}
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#, p, ab_name, escape_xml(&display_name), ctag, sync_token, desc_xml);

                    if depth == "1" {
                        let mut stmt = db.prepare(
                            "SELECT uid, etag FROM contacts WHERE addressbook_id = ?1 AND deleted = 0"
                        ).unwrap();
                        for obj in stmt.query_map([&ab_id], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).unwrap().flatten() {
                            let (uid, etag) = obj;
                            responses.push_str(&format!(
                                r#"
<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <d:getcontenttype>text/vcard; charset=utf-8</d:getcontenttype>
      <d:resourcetype/>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#, p, ab_name, uid, etag));
                        }
                    }

                    xml_response(StatusCode::MULTI_STATUS, format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" xmlns:cs="http://calendarserver.org/ns/">
{}</d:multistatus>"#, responses))
                }
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn handle_proppatch(
    state: &SharedCardDavState,
    path: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_, ab_name, _) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    if let Some(display_name) = extract_xml_value(body, "displayname") {
        let updated = db.execute(
            "UPDATE addressbooks SET display_name = ?1, updated_at = ?2, ctag = CAST(CAST(ctag AS INTEGER) + 1 AS TEXT) WHERE name = ?3",
            rusqlite::params![display_name, now, ab_name],
        ).unwrap_or(0);
        if updated > 0 {
            return xml_response(
                StatusCode::MULTI_STATUS,
                format!(
                    r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:">
<d:response>
  <d:href>/carddav/admin/{}/</d:href>
  <d:propstat>
    <d:prop><d:displayname/></d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>
</d:multistatus>"#,
                    ab_name
                ),
            );
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

fn handle_mkcol(state: &SharedCardDavState, path: &str, body: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_, ab_name, _) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let exists: bool = db
        .query_row(
            "SELECT COUNT(*) FROM addressbooks WHERE name = ?1",
            [ab_name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;
    if exists {
        return (StatusCode::CONFLICT, "Addressbook already exists").into_response();
    }

    let display_name =
        extract_xml_value(body, "displayname").unwrap_or_else(|| ab_name.to_string());
    let description = extract_xml_value(body, "addressbook-description");
    let id = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    match db.execute(
        "INSERT INTO addressbooks (id, name, display_name, description, ctag, sync_token, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, '1', 0, ?5, ?6)",
        rusqlite::params![id, ab_name, display_name, description, now, now],
    ) {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => { tracing::error!(error = %e, "Failed to create addressbook"); StatusCode::INTERNAL_SERVER_ERROR.into_response() }
    }
}

fn handle_put(
    state: &SharedCardDavState,
    path: &str,
    body: &str,
    if_match: Option<&str>,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_, ab_name, contact_name) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let contact_name = match contact_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let uid = contact_name.trim_end_matches(".vcf");

    let ab_id: String = match db.query_row(
        "SELECT id FROM addressbooks WHERE name = ?1",
        [ab_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let existing = db.query_row(
        "SELECT etag FROM contacts WHERE addressbook_id = ?1 AND uid = ?2 AND deleted = 0",
        rusqlite::params![ab_id, uid],
        |row| row.get::<_, String>(0),
    );

    if let Some(expected) = if_match {
        match &existing {
            Ok(current) => {
                if current != expected.trim_matches('"') {
                    return StatusCode::PRECONDITION_FAILED.into_response();
                }
            }
            Err(_) => return StatusCode::PRECONDITION_FAILED.into_response(),
        }
    }

    let etag = compute_etag(body);
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let fn_name = extract_vcard_field(body, "FN");
    let email = extract_vcard_field(body, "EMAIL");
    let phone = extract_vcard_field(body, "TEL");
    let org = extract_vcard_field(body, "ORG");
    let is_new = existing.is_err();

    if is_new {
        db.execute(
            "INSERT INTO contacts (id, addressbook_id, uid, vcard_data, etag, fn_name, email, phone, org, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            rusqlite::params![uuid::Uuid::new_v4().to_string(), ab_id, uid, body, etag, fn_name, email, phone, org, now, now],
        ).unwrap();
    } else {
        db.execute(
            "UPDATE contacts SET vcard_data = ?1, etag = ?2, fn_name = ?3, email = ?4, phone = ?5, org = ?6, updated_at = ?7
             WHERE addressbook_id = ?8 AND uid = ?9 AND deleted = 0",
            rusqlite::params![body, etag, fn_name, email, phone, org, now, ab_id, uid],
        ).unwrap();
    }

    let new_st: i64 = db
        .query_row(
            "SELECT sync_token FROM addressbooks WHERE id = ?1",
            [&ab_id],
            |row| row.get(0),
        )
        .unwrap_or(0)
        + 1;
    db.execute("UPDATE addressbooks SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![new_st, now, ab_id]).unwrap();

    let change_type = if is_new { "created" } else { "modified" };
    db.execute(
        "INSERT INTO sync_changes (collection_type, collection_id, object_uri, change_type, sync_token, created_at)
         VALUES ('addressbook', ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![ab_id, format!("{}.vcf", uid), change_type, new_st, now],
    ).unwrap();

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    };
    (status, [(header::ETAG, format!("\"{}\"", etag))]).into_response()
}

fn handle_get(state: &SharedCardDavState, path: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_, ab_name, contact_name) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let contact_name = match contact_name {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let uid = contact_name.trim_end_matches(".vcf");

    match db.query_row(
        "SELECT c.vcard_data, c.etag FROM contacts c JOIN addressbooks a ON c.addressbook_id = a.id
         WHERE a.name = ?1 AND c.uid = ?2 AND c.deleted = 0",
        rusqlite::params![ab_name, uid],
        |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
    ) {
        Ok((vcard, etag)) => (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    "text/vcard; charset=utf-8".to_string(),
                ),
                (header::ETAG, format!("\"{}\"", etag)),
            ],
            vcard,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

fn handle_delete(state: &SharedCardDavState, path: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_, ab_name, contact_name) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    match contact_name {
        Some(name) => {
            let uid = name.trim_end_matches(".vcf");
            let ab_id: String = match db.query_row(
                "SELECT id FROM addressbooks WHERE name = ?1",
                [ab_name],
                |row| row.get(0),
            ) {
                Ok(id) => id,
                Err(_) => return StatusCode::NOT_FOUND.into_response(),
            };

            let affected = db.execute(
                "UPDATE contacts SET deleted = 1, updated_at = ?1 WHERE addressbook_id = ?2 AND uid = ?3 AND deleted = 0",
                rusqlite::params![now, ab_id, uid],
            ).unwrap_or(0);
            if affected == 0 {
                return StatusCode::NOT_FOUND.into_response();
            }

            let new_st: i64 = db
                .query_row(
                    "SELECT sync_token FROM addressbooks WHERE id = ?1",
                    [&ab_id],
                    |row| row.get(0),
                )
                .unwrap_or(0)
                + 1;
            db.execute("UPDATE addressbooks SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![new_st, now, ab_id]).unwrap();
            db.execute(
                "INSERT INTO sync_changes (collection_type, collection_id, object_uri, change_type, sync_token, created_at)
                 VALUES ('addressbook', ?1, ?2, 'deleted', ?3, ?4)",
                rusqlite::params![ab_id, format!("{}.vcf", uid), new_st, now],
            ).unwrap();
            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            let affected = db
                .execute("DELETE FROM addressbooks WHERE name = ?1", [ab_name])
                .unwrap_or(0);
            if affected == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
    }
}

fn handle_report(state: &SharedCardDavState, path: &str, body: &str) -> axum::response::Response {
    let (_, ab_name, _) = parse_path(path);
    let ab_name = match ab_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let principal = "admin";

    if body.contains("addressbook-multiget") {
        handle_multiget(state, ab_name, principal, body)
    } else if body.contains("sync-collection") {
        handle_sync_collection(state, ab_name, principal, body)
    } else {
        StatusCode::BAD_REQUEST.into_response()
    }
}

fn handle_multiget(
    state: &SharedCardDavState,
    ab_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let hrefs = extract_hrefs(body);
    let ab_id: String = match db.query_row(
        "SELECT id FROM addressbooks WHERE name = ?1",
        [ab_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut responses = String::new();
    for href in &hrefs {
        let uid = href
            .rsplit('/')
            .next()
            .unwrap_or("")
            .trim_end_matches(".vcf");
        match db.query_row(
            "SELECT uid, etag, vcard_data FROM contacts WHERE addressbook_id = ?1 AND uid = ?2 AND deleted = 0",
            rusqlite::params![ab_id, uid],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        ) {
            Ok((uid, etag, vcard)) => {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <card:address-data>{}</card:address-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#, principal, ab_name, uid, etag, escape_xml(&vcard)));
            }
            Err(_) => {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>{}</d:href>
  <d:status>HTTP/1.1 404 Not Found</d:status>
</d:response>"#, escape_xml(href)));
            }
        }
    }

    xml_response(
        StatusCode::MULTI_STATUS,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
{}</d:multistatus>"#,
            responses
        ),
    )
}

fn handle_sync_collection(
    state: &SharedCardDavState,
    ab_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let ab_id: String = match db.query_row(
        "SELECT id FROM addressbooks WHERE name = ?1",
        [ab_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let sync_token = extract_xml_value(body, "sync-token")
        .and_then(|t| t.rsplit('/').next().and_then(|n| n.parse::<i64>().ok()))
        .unwrap_or(0);

    let current_st: i64 = db
        .query_row(
            "SELECT sync_token FROM addressbooks WHERE id = ?1",
            [&ab_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut responses = String::new();

    if sync_token == 0 {
        let mut stmt = db.prepare(
            "SELECT uid, etag, vcard_data FROM contacts WHERE addressbook_id = ?1 AND deleted = 0"
        ).unwrap();
        for obj in stmt
            .query_map([&ab_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .flatten()
        {
            let (uid, etag, vcard) = obj;
            responses.push_str(&format!(
                r#"<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <card:address-data>{}</card:address-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                principal,
                ab_name,
                uid,
                etag,
                escape_xml(&vcard)
            ));
        }
    } else {
        let mut stmt = db.prepare(
            "SELECT object_uri, change_type FROM sync_changes
             WHERE collection_type = 'addressbook' AND collection_id = ?1 AND sync_token > ?2 ORDER BY sync_token"
        ).unwrap();
        for change in stmt
            .query_map(rusqlite::params![ab_id, sync_token], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .flatten()
        {
            let (object_uri, change_type) = change;
            let uid = object_uri.trim_end_matches(".vcf");
            if change_type == "deleted" {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:status>HTTP/1.1 404 Not Found</d:status>
</d:response>"#, principal, ab_name, uid));
            } else if let Ok((uid, etag, vcard)) = db.query_row(
                "SELECT uid, etag, vcard_data FROM contacts WHERE addressbook_id = ?1 AND uid = ?2 AND deleted = 0",
                rusqlite::params![ab_id, uid],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
            ) {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>/carddav/{}/{}/{}.vcf</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <card:address-data>{}</card:address-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#, principal, ab_name, uid, etag, escape_xml(&vcard)));
            }
        }
    }

    xml_response(
        StatusCode::MULTI_STATUS,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
{}
<d:sync-token>http://tilde.local/sync/{}</d:sync-token>
</d:multistatus>"#,
            responses, current_st
        ),
    )
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn extract_xml_value(xml: &str, tag_name: &str) -> Option<String> {
    for prefix in &["", "d:", "D:", "card:", "C:"] {
        let pat = format!("<{}{}>", prefix, tag_name);
        if let Some(start) = xml.find(&pat) {
            let content_start = start + pat.len();
            if let Some(end) = xml[content_start..].find("</") {
                return Some(xml[content_start..content_start + end].trim().to_string());
            }
        }
    }
    let search = format!(":{}>", tag_name);
    if let Some(pos) = xml.find(&search) {
        let content_start = pos + search.len();
        if let Some(end) = xml[content_start..].find("</") {
            return Some(xml[content_start..content_start + end].trim().to_string());
        }
    }
    None
}

fn extract_hrefs(xml: &str) -> Vec<String> {
    let mut hrefs = Vec::new();
    let mut search_from = 0;
    loop {
        let mut found = None;
        for pat in &["<d:href>", "<D:href>", "<href>"] {
            if let Some(pos) = xml[search_from..].find(pat) {
                found = Some((search_from + pos + pat.len(),));
                break;
            }
        }
        match found {
            Some((content_start,)) => {
                if let Some(end) = xml[content_start..].find("</") {
                    hrefs.push(xml[content_start..content_start + end].trim().to_string());
                    search_from = content_start + end;
                } else {
                    break;
                }
            }
            None => break,
        }
    }
    hrefs
}

fn extract_vcard_field(vcard: &str, field: &str) -> Option<String> {
    for line in vcard.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix(field) {
            if let Some(value) = rest.strip_prefix(':') {
                return Some(value.to_string());
            } else if rest.starts_with(';')
                && let Some(colon_pos) = rest.find(':')
            {
                return Some(rest[colon_pos + 1..].to_string());
            }
        }
    }
    None
}

// ─── Public query API for CLI/MCP ──────────────────────────────────────────

type ContactRecord = (
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub fn search_contacts(db: &Connection, query: &str) -> Vec<ContactRecord> {
    let pattern = format!("%{}%", query);
    let mut stmt = db
        .prepare(
            "SELECT uid, fn_name, email, phone, org FROM contacts
         WHERE deleted = 0 AND (fn_name LIKE ?1 OR email LIKE ?1 OR phone LIKE ?1 OR org LIKE ?1)",
        )
        .unwrap();
    stmt.query_map([&pattern], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}

pub fn list_contacts(db: &Connection) -> Vec<ContactRecord> {
    let mut stmt = db
        .prepare("SELECT uid, fn_name, email, phone, org FROM contacts WHERE deleted = 0")
        .unwrap();
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}

pub fn list_addressbooks(db: &Connection) -> Vec<(String, String, Option<String>)> {
    let mut stmt = db
        .prepare("SELECT name, display_name, description FROM addressbooks")
        .unwrap();
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}
