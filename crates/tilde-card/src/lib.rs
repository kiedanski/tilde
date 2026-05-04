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
use std::sync::Arc;
use tilde_core::auth;
use tilde_core::db::DbPool;

pub struct CardDavState {
    pub db: DbPool,
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
            let db = state.db.get().unwrap();
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
                    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    let db = state.db.get().unwrap();
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
    } else if body.contains("addressbook-query") {
        handle_addressbook_query(state, ab_name, principal, body)
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
    let db = state.db.get().unwrap();
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

fn handle_addressbook_query(
    state: &SharedCardDavState,
    ab_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.get().unwrap();
    let ab_id: String = match db.query_row(
        "SELECT id FROM addressbooks WHERE name = ?1",
        [ab_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    // Parse prop-filters including text-match children and filter test mode
    let prop_filters = extract_prop_filters(body);
    let filter_test = extract_filter_test(body);

    let mut stmt = db
        .prepare("SELECT uid, etag, vcard_data FROM contacts WHERE addressbook_id = ?1 AND deleted = 0")
        .unwrap();
    let contacts: Vec<(String, String, String)> = stmt
        .query_map([&ab_id], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .unwrap()
        .flatten()
        .collect();

    let mut responses = String::new();
    for (uid, etag, vcard) in &contacts {
        // Apply prop-filters with anyof/allof logic
        if !prop_filters.is_empty() {
            let passes = match filter_test {
                FilterTest::AnyOf => prop_filters
                    .iter()
                    .any(|pf| vcard_matches_prop_filter(vcard, pf)),
                FilterTest::AllOf => prop_filters
                    .iter()
                    .all(|pf| vcard_matches_prop_filter(vcard, pf)),
            };
            if !passes {
                continue;
            }
        }

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
            escape_xml(vcard)
        ));
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
    let db = state.db.get().unwrap();
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
                    let raw = xml[content_start..content_start + end].trim();
                    // URL-decode: clients may percent-encode UIDs with @/:
                    let decoded = urlencoding::decode(raw)
                        .map(|s| s.into_owned())
                        .unwrap_or_else(|_| raw.to_string());
                    hrefs.push(decoded);
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

// ─── Prop-filter types for addressbook-query ─────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum MatchType {
    Contains,
    StartsWith,
    EndsWith,
    Equals,
}

#[derive(Debug, Clone)]
struct TextMatch {
    value: String,
    match_type: MatchType,
    negate: bool,
}

#[derive(Debug, Clone)]
struct PropFilter {
    name: String,
    text_match: Option<TextMatch>,
}

/// Whether prop-filters combine with anyof (OR) or allof (AND).
#[derive(Debug, Clone, PartialEq)]
enum FilterTest {
    AnyOf,
    AllOf,
}

/// Extract the `test` attribute from the `<filter>` element.
fn extract_filter_test(xml: &str) -> FilterTest {
    // Look for <...filter ... test="anyof" ...>
    // We search for a `filter` tag (could be `card:filter` or `CR:filter`)
    // that is NOT `prop-filter` or `param-filter`.
    let lower = xml.to_lowercase();
    // Find occurrences of "filter" that are not preceded by "prop-" or "param-"
    let mut search_from = 0;
    while let Some(pos) = lower[search_from..].find("filter") {
        let abs = search_from + pos;
        // Check this isn't prop-filter or param-filter
        let prefix = if abs >= 5 { &lower[abs - 5..abs] } else { "" };
        let is_prop = prefix.ends_with("prop-");
        let is_param = if abs >= 6 {
            lower[abs - 6..abs].ends_with("param-")
        } else {
            false
        };
        if !is_prop && !is_param {
            // Find the end of this tag
            if let Some(tag_end) = xml[abs..].find('>') {
                let tag_content = &xml[abs..abs + tag_end];
                if let Some(test_pos) = tag_content.to_lowercase().find("test=\"") {
                    let val_start = test_pos + 6;
                    if let Some(end) = tag_content[val_start..].find('"') {
                        let val = &tag_content[val_start..val_start + end];
                        if val.eq_ignore_ascii_case("anyof") {
                            return FilterTest::AnyOf;
                        }
                    }
                }
            }
        }
        search_from = abs + 6;
    }
    FilterTest::AllOf
}

/// Parse `<prop-filter name="...">` elements including optional `<text-match>` children.
fn extract_prop_filters(xml: &str) -> Vec<PropFilter> {
    let mut filters = Vec::new();
    let mut search_from = 0;
    while let Some(pos) = xml[search_from..].find("prop-filter") {
        let abs_pos = search_from + pos;

        // Find name="..." attribute after "prop-filter"
        let name = if let Some(name_pos) = xml[abs_pos..].find("name=\"") {
            let val_start = abs_pos + name_pos + 6;
            if let Some(end) = xml[val_start..].find('"') {
                xml[val_start..val_start + end].to_string()
            } else {
                search_from = abs_pos + 11;
                continue;
            }
        } else {
            search_from = abs_pos + 11;
            continue;
        };

        // Determine the span of this prop-filter element to look for text-match children.
        // Find the closing </...prop-filter> or a self-closing />
        let after_tag = abs_pos + 11; // skip past "prop-filter"
        let prop_filter_end = xml[after_tag..]
            .find("prop-filter>")
            .map(|p| after_tag + p + 12)
            .unwrap_or(xml.len());
        let self_close = xml[after_tag..prop_filter_end].find("/>");
        let element_span = if let Some(sc) = self_close {
            // Check if self-close comes before any child elements
            let child_start = xml[after_tag..prop_filter_end].find('<');
            if child_start.map_or(true, |cs| sc < cs) {
                &xml[after_tag..after_tag + sc]
            } else {
                &xml[after_tag..prop_filter_end]
            }
        } else {
            &xml[after_tag..prop_filter_end]
        };

        // Look for <text-match ...>value</text-match> inside this prop-filter
        let text_match = parse_text_match(element_span);

        filters.push(PropFilter { name, text_match });
        search_from = after_tag + element_span.len();
    }
    filters
}

/// Parse a `<text-match>` element within a given XML fragment.
fn parse_text_match(xml_fragment: &str) -> Option<TextMatch> {
    let tm_marker = xml_fragment.find("text-match")?;
    let tm_start = tm_marker;

    // Find the opening tag's closing >
    let tag_end = xml_fragment[tm_start..].find('>')?;
    let tag_content = &xml_fragment[tm_start..tm_start + tag_end];

    // Parse match-type attribute (default: "contains")
    let match_type = if let Some(mt_pos) = tag_content.to_lowercase().find("match-type=\"") {
        let val_start = mt_pos + 12;
        if let Some(end) = tag_content[val_start..].find('"') {
            match tag_content[val_start..val_start + end]
                .to_lowercase()
                .as_str()
            {
                "starts-with" => MatchType::StartsWith,
                "ends-with" => MatchType::EndsWith,
                "equals" => MatchType::Equals,
                _ => MatchType::Contains,
            }
        } else {
            MatchType::Contains
        }
    } else {
        MatchType::Contains
    };

    // Parse negate-condition attribute (default: false)
    let negate = if let Some(nc_pos) = tag_content.to_lowercase().find("negate-condition=\"") {
        let val_start = nc_pos + 18;
        if let Some(end) = tag_content[val_start..].find('"') {
            tag_content[val_start..val_start + end].eq_ignore_ascii_case("yes")
        } else {
            false
        }
    } else {
        false
    };

    // Extract text content between > and </...text-match>
    let content_start = tm_start + tag_end + 1;
    let content_end = xml_fragment[content_start..]
        .find("text-match>")
        .map(|p| {
            // Back up past the `</` or `</card:` etc. before `text-match>`
            let before = &xml_fragment[..content_start + p];
            before.rfind('<').unwrap_or(content_start + p)
        })
        .unwrap_or(xml_fragment.len());

    let value = xml_fragment[content_start..content_end].trim().to_string();
    if value.is_empty() {
        return None;
    }

    Some(TextMatch {
        value,
        match_type,
        negate,
    })
}

/// Extract all values for a given vCard property name (case-insensitive).
///
/// Handles both `PROP:value` and `PROP;params:value` forms.
fn extract_vcard_property(vcard: &str, prop_name: &str) -> Vec<String> {
    let prop_upper = prop_name.to_uppercase();
    vcard
        .lines()
        .filter_map(|line| {
            let line = line.trim_end_matches('\r');
            let upper = line.to_uppercase();
            if upper.starts_with(&prop_upper) {
                let rest = &line[prop_upper.len()..];
                if rest.starts_with(':') {
                    Some(rest[1..].trim().to_string())
                } else if rest.starts_with(';') {
                    rest.find(':').map(|i| rest[i + 1..].trim().to_string())
                } else {
                    None
                }
            } else {
                None
            }
        })
        .collect()
}

/// Check if a contact's vCard matches a single prop-filter.
fn vcard_matches_prop_filter(vcard: &str, pf: &PropFilter) -> bool {
    let values = extract_vcard_property(vcard, &pf.name);

    match &pf.text_match {
        None => {
            // No text-match child: filter is a presence test (property must exist)
            !values.is_empty()
        }
        Some(tm) => {
            let needle = tm.value.to_lowercase();
            let matched = values.iter().any(|val| {
                let haystack = val.to_lowercase();
                match tm.match_type {
                    MatchType::Contains => haystack.contains(&needle),
                    MatchType::StartsWith => haystack.starts_with(&needle),
                    MatchType::EndsWith => haystack.ends_with(&needle),
                    MatchType::Equals => haystack == needle,
                }
            });
            if tm.negate { !matched } else { matched }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const VCARD_JOHN: &str = "\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:John Doe\r\n\
EMAIL;TYPE=WORK:john@example.com\r\n\
TEL;TYPE=CELL:+1234567890\r\n\
ORG:Acme Corp\r\n\
END:VCARD";

    const VCARD_JANE: &str = "\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:Jane Smith\r\n\
EMAIL:jane@example.org\r\n\
END:VCARD";

    const VCARD_NO_EMAIL: &str = "\
BEGIN:VCARD\r\n\
VERSION:3.0\r\n\
FN:Bob NoEmail\r\n\
TEL:+9999999999\r\n\
END:VCARD";

    // ── extract_vcard_property ──────────────────────────────────────────

    #[test]
    fn extract_vcard_property_simple() {
        let vals = extract_vcard_property(VCARD_JOHN, "FN");
        assert_eq!(vals, vec!["John Doe"]);
    }

    #[test]
    fn extract_vcard_property_with_params() {
        let vals = extract_vcard_property(VCARD_JOHN, "EMAIL");
        assert_eq!(vals, vec!["john@example.com"]);
    }

    #[test]
    fn extract_vcard_property_case_insensitive() {
        let vals = extract_vcard_property(VCARD_JOHN, "fn");
        assert_eq!(vals, vec!["John Doe"]);
        let vals = extract_vcard_property(VCARD_JOHN, "Fn");
        assert_eq!(vals, vec!["John Doe"]);
    }

    #[test]
    fn extract_vcard_property_missing() {
        let vals = extract_vcard_property(VCARD_NO_EMAIL, "EMAIL");
        assert!(vals.is_empty());
    }

    #[test]
    fn extract_vcard_property_tel_with_params() {
        let vals = extract_vcard_property(VCARD_JOHN, "TEL");
        assert_eq!(vals, vec!["+1234567890"]);
    }

    // ── extract_prop_filters ────────────────────────────────────────────

    #[test]
    fn extract_prop_filters_presence_only() {
        let xml = r#"<card:filter><card:prop-filter name="EMAIL"/></card:filter>"#;
        let filters = extract_prop_filters(xml);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].name, "EMAIL");
        assert!(filters[0].text_match.is_none());
    }

    #[test]
    fn extract_prop_filters_with_text_match() {
        let xml = r#"<card:filter test="anyof">
  <card:prop-filter name="FN">
    <card:text-match collation="i;unicode-casemap" match-type="contains">john</card:text-match>
  </card:prop-filter>
</card:filter>"#;
        let filters = extract_prop_filters(xml);
        assert_eq!(filters.len(), 1);
        assert_eq!(filters[0].name, "FN");
        let tm = filters[0].text_match.as_ref().unwrap();
        assert_eq!(tm.value, "john");
        assert_eq!(tm.match_type, MatchType::Contains);
        assert!(!tm.negate);
    }

    #[test]
    fn extract_prop_filters_starts_with() {
        let xml = r#"<card:prop-filter name="FN">
    <card:text-match match-type="starts-with">Jo</card:text-match>
  </card:prop-filter>"#;
        let filters = extract_prop_filters(xml);
        assert_eq!(filters.len(), 1);
        let tm = filters[0].text_match.as_ref().unwrap();
        assert_eq!(tm.match_type, MatchType::StartsWith);
        assert_eq!(tm.value, "Jo");
    }

    #[test]
    fn extract_prop_filters_ends_with() {
        let xml = r#"<card:prop-filter name="EMAIL">
    <card:text-match match-type="ends-with">example.com</card:text-match>
  </card:prop-filter>"#;
        let filters = extract_prop_filters(xml);
        let tm = filters[0].text_match.as_ref().unwrap();
        assert_eq!(tm.match_type, MatchType::EndsWith);
        assert_eq!(tm.value, "example.com");
    }

    #[test]
    fn extract_prop_filters_equals() {
        let xml = r#"<card:prop-filter name="FN">
    <card:text-match match-type="equals">John Doe</card:text-match>
  </card:prop-filter>"#;
        let filters = extract_prop_filters(xml);
        let tm = filters[0].text_match.as_ref().unwrap();
        assert_eq!(tm.match_type, MatchType::Equals);
        assert_eq!(tm.value, "John Doe");
    }

    #[test]
    fn extract_prop_filters_negate() {
        let xml = r#"<card:prop-filter name="FN">
    <card:text-match match-type="contains" negate-condition="yes">john</card:text-match>
  </card:prop-filter>"#;
        let filters = extract_prop_filters(xml);
        let tm = filters[0].text_match.as_ref().unwrap();
        assert!(tm.negate);
    }

    #[test]
    fn extract_prop_filters_multiple() {
        let xml = r#"<card:filter test="allof">
  <card:prop-filter name="FN">
    <card:text-match match-type="contains">john</card:text-match>
  </card:prop-filter>
  <card:prop-filter name="EMAIL">
    <card:text-match match-type="contains">example</card:text-match>
  </card:prop-filter>
</card:filter>"#;
        let filters = extract_prop_filters(xml);
        assert_eq!(filters.len(), 2);
        assert_eq!(filters[0].name, "FN");
        assert_eq!(filters[1].name, "EMAIL");
    }

    // ── extract_filter_test ─────────────────────────────────────────────

    #[test]
    fn filter_test_default_allof() {
        let xml = r#"<card:filter><card:prop-filter name="FN"/></card:filter>"#;
        assert_eq!(extract_filter_test(xml), FilterTest::AllOf);
    }

    #[test]
    fn filter_test_anyof() {
        let xml = r#"<card:filter test="anyof"><card:prop-filter name="FN"/></card:filter>"#;
        assert_eq!(extract_filter_test(xml), FilterTest::AnyOf);
    }

    #[test]
    fn filter_test_allof_explicit() {
        let xml = r#"<card:filter test="allof"><card:prop-filter name="FN"/></card:filter>"#;
        assert_eq!(extract_filter_test(xml), FilterTest::AllOf);
    }

    #[test]
    fn filter_test_not_confused_by_prop_filter() {
        // The word "filter" also appears in "prop-filter" -- should not pick up test attr from there
        let xml = r#"<CR:filter test="anyof"><CR:prop-filter name="FN" test="allof"/></CR:filter>"#;
        assert_eq!(extract_filter_test(xml), FilterTest::AnyOf);
    }

    // ── vcard_matches_prop_filter ───────────────────────────────────────

    #[test]
    fn match_presence_only() {
        let pf = PropFilter {
            name: "EMAIL".into(),
            text_match: None,
        };
        assert!(vcard_matches_prop_filter(VCARD_JOHN, &pf));
        assert!(!vcard_matches_prop_filter(VCARD_NO_EMAIL, &pf));
    }

    #[test]
    fn match_contains() {
        let pf = PropFilter {
            name: "FN".into(),
            text_match: Some(TextMatch {
                value: "john".into(),
                match_type: MatchType::Contains,
                negate: false,
            }),
        };
        assert!(vcard_matches_prop_filter(VCARD_JOHN, &pf));
        assert!(!vcard_matches_prop_filter(VCARD_JANE, &pf));
    }

    #[test]
    fn match_starts_with() {
        let pf = PropFilter {
            name: "FN".into(),
            text_match: Some(TextMatch {
                value: "jane".into(),
                match_type: MatchType::StartsWith,
                negate: false,
            }),
        };
        assert!(!vcard_matches_prop_filter(VCARD_JOHN, &pf));
        assert!(vcard_matches_prop_filter(VCARD_JANE, &pf));
    }

    #[test]
    fn match_ends_with() {
        let pf = PropFilter {
            name: "EMAIL".into(),
            text_match: Some(TextMatch {
                value: "example.com".into(),
                match_type: MatchType::EndsWith,
                negate: false,
            }),
        };
        assert!(vcard_matches_prop_filter(VCARD_JOHN, &pf));
        assert!(!vcard_matches_prop_filter(VCARD_JANE, &pf)); // jane@example.org
    }

    #[test]
    fn match_equals() {
        let pf = PropFilter {
            name: "FN".into(),
            text_match: Some(TextMatch {
                value: "John Doe".into(),
                match_type: MatchType::Equals,
                negate: false,
            }),
        };
        assert!(vcard_matches_prop_filter(VCARD_JOHN, &pf));
        assert!(!vcard_matches_prop_filter(VCARD_JANE, &pf));
    }

    #[test]
    fn match_negate() {
        let pf = PropFilter {
            name: "FN".into(),
            text_match: Some(TextMatch {
                value: "john".into(),
                match_type: MatchType::Contains,
                negate: true,
            }),
        };
        // Negated: John's vCard should NOT match because it contains "john"
        assert!(!vcard_matches_prop_filter(VCARD_JOHN, &pf));
        // Jane's vCard should match because it does NOT contain "john"
        assert!(vcard_matches_prop_filter(VCARD_JANE, &pf));
    }

    #[test]
    fn match_case_insensitive() {
        let pf = PropFilter {
            name: "FN".into(),
            text_match: Some(TextMatch {
                value: "JOHN DOE".into(),
                match_type: MatchType::Equals,
                negate: false,
            }),
        };
        assert!(vcard_matches_prop_filter(VCARD_JOHN, &pf));
    }

    #[test]
    fn match_missing_property_with_text_match() {
        // If property doesn't exist and we have a text-match, it shouldn't match
        let pf = PropFilter {
            name: "EMAIL".into(),
            text_match: Some(TextMatch {
                value: "anything".into(),
                match_type: MatchType::Contains,
                negate: false,
            }),
        };
        assert!(!vcard_matches_prop_filter(VCARD_NO_EMAIL, &pf));
    }

    #[test]
    fn match_missing_property_negated_text_match() {
        // If property doesn't exist and text-match is negated, the values list is empty
        // so no value matches the text => matched=false, negate => true
        let pf = PropFilter {
            name: "EMAIL".into(),
            text_match: Some(TextMatch {
                value: "anything".into(),
                match_type: MatchType::Contains,
                negate: true,
            }),
        };
        assert!(vcard_matches_prop_filter(VCARD_NO_EMAIL, &pf));
    }

    // ── Integration: anyof vs allof ─────────────────────────────────────

    #[test]
    fn allof_requires_all_filters() {
        let filters = vec![
            PropFilter {
                name: "FN".into(),
                text_match: Some(TextMatch {
                    value: "john".into(),
                    match_type: MatchType::Contains,
                    negate: false,
                }),
            },
            PropFilter {
                name: "EMAIL".into(),
                text_match: Some(TextMatch {
                    value: "example.com".into(),
                    match_type: MatchType::Contains,
                    negate: false,
                }),
            },
        ];
        // John has both FN containing "john" and EMAIL containing "example.com"
        assert!(filters
            .iter()
            .all(|pf| vcard_matches_prop_filter(VCARD_JOHN, pf)));
        // Jane has FN not containing "john" but has EMAIL containing "example" (not .com)
        assert!(!filters
            .iter()
            .all(|pf| vcard_matches_prop_filter(VCARD_JANE, pf)));
    }

    #[test]
    fn anyof_requires_any_filter() {
        let filters = vec![
            PropFilter {
                name: "FN".into(),
                text_match: Some(TextMatch {
                    value: "john".into(),
                    match_type: MatchType::Contains,
                    negate: false,
                }),
            },
            PropFilter {
                name: "FN".into(),
                text_match: Some(TextMatch {
                    value: "jane".into(),
                    match_type: MatchType::Contains,
                    negate: false,
                }),
            },
        ];
        // anyof: John matches first filter
        assert!(filters
            .iter()
            .any(|pf| vcard_matches_prop_filter(VCARD_JOHN, pf)));
        // anyof: Jane matches second filter
        assert!(filters
            .iter()
            .any(|pf| vcard_matches_prop_filter(VCARD_JANE, pf)));
        // anyof: Bob matches neither
        assert!(!filters
            .iter()
            .any(|pf| vcard_matches_prop_filter(VCARD_NO_EMAIL, pf)));
    }
}
