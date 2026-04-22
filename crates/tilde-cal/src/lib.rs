//! tilde-cal: CalDAV handler (RFC 4791)
//!
//! Implements CalDAV over HTTP with axum. Supports MKCALENDAR, PUT, GET, DELETE,
//! PROPFIND, PROPPATCH, and REPORT (calendar-query, calendar-multiget, sync-collection).

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

pub struct CalDavState {
    pub db: Arc<Mutex<Connection>>,
    pub session_ttl_hours: u32,
}

pub type SharedCalDavState = Arc<CalDavState>;

/// Build the CalDAV router, to be mounted at /caldav
pub fn build_caldav_router(state: SharedCalDavState) -> Router {
    Router::new()
        .route("/", any(caldav_root_handler))
        .route("/{*path}", any(caldav_handler))
        .with_state(state)
}

/// Ensure default calendar exists
pub fn ensure_default_calendar(db: &Connection) {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db.execute(
        "INSERT OR IGNORE INTO calendars (id, name, display_name, ctag, sync_token, created_at, updated_at)
         VALUES (?1, 'default', 'Personal', '1', 0, ?2, ?3)",
        rusqlite::params![uuid::Uuid::new_v4().to_string(), now, now],
    );
}

fn compute_etag(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    let result = hasher.finalize();
    format!("{:x}", result).chars().take(16).collect()
}

fn xml_response(status: StatusCode, body: String) -> axum::response::Response {
    (
        status,
        [(header::CONTENT_TYPE, "application/xml; charset=utf-8")],
        body,
    )
        .into_response()
}

async fn caldav_root_handler(
    method: Method,
    State(state): State<SharedCalDavState>,
    req: axum::extract::Request,
) -> axum::response::Response {
    handle_caldav_request(&state, method, "", req).await
}

async fn caldav_handler(
    method: Method,
    State(state): State<SharedCalDavState>,
    AxumPath(path): AxumPath<String>,
    req: axum::extract::Request,
) -> axum::response::Response {
    handle_caldav_request(&state, method, &path, req).await
}

fn check_auth(state: &SharedCalDavState, req: &axum::extract::Request, scope_prefix: &str) -> bool {
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

async fn handle_caldav_request(
    state: &SharedCalDavState,
    method: Method,
    path: &str,
    req: axum::extract::Request,
) -> axum::response::Response {
    // Auth check
    if !check_auth(state, &req, "/caldav/") {
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
                HeaderValue::from_static("1, 2, 3, calendar-access"),
            );
            resp.headers_mut().insert(
                header::HeaderName::from_static("allow"),
                HeaderValue::from_static("OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, REPORT, MKCALENDAR, MKCOL, MOVE, COPY"),
            );
            resp
        }
        "PROPFIND" => handle_propfind(state, path, &depth),
        "PROPPATCH" => handle_proppatch(state, path, &body),
        "MKCALENDAR" | "MKCOL" => handle_mkcalendar(state, path, &body),
        "PUT" => handle_put(state, path, &body, if_match.as_deref()),
        "GET" => handle_get(state, path),
        "DELETE" => handle_delete(state, path),
        "REPORT" => handle_report(state, path, &body),
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}

/// Parse path segments: /admin/calname/uid.ics
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

fn handle_propfind(state: &SharedCalDavState, path: &str, depth: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (principal, cal_name, obj_name) = parse_path(path);

    // Root or principal level: list calendars
    if principal.is_none() || (principal.is_some() && cal_name.is_none()) {
        let mut responses = String::new();
        let href = if let Some(p) = &principal {
            format!("/caldav/{}/", p)
        } else {
            "/caldav/".to_string()
        };

        responses.push_str(&format!(
            r#"<d:response>
  <d:href>{}</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/></d:resourcetype>
      <d:current-user-principal><d:href>/principals/admin/</d:href></d:current-user-principal>
      <d:displayname>CalDAV</d:displayname>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
            href
        ));

        if depth == "1" {
            let mut stmt = db.prepare(
                "SELECT name, display_name, ctag, description, color, sync_token FROM calendars"
            ).unwrap();
            let calendars = stmt
                .query_map([], |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, Option<String>>(3)?,
                        row.get::<_, Option<String>>(4)?,
                        row.get::<_, i64>(5)?,
                    ))
                })
                .unwrap();

            let p = principal.unwrap_or("admin");
            for cal in calendars.flatten() {
                let (name, display_name, ctag, description, color, sync_token) = cal;
                let desc_xml = description
                    .map(|d| {
                        format!(
                            "<cal:calendar-description>{}</cal:calendar-description>",
                            escape_xml(&d)
                        )
                    })
                    .unwrap_or_default();
                let color_xml = color.map(|c| format!("<x:calendar-color xmlns:x=\"http://apple.com/ns/ical/\">{}</x:calendar-color>", escape_xml(&c))).unwrap_or_default();
                responses.push_str(&format!(
                    r#"
<d:response>
  <d:href>/caldav/{}/{}/</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
      <d:displayname>{}</d:displayname>
      <cs:getctag xmlns:cs="http://calendarserver.org/ns/">{}</cs:getctag>
      <d:sync-token>http://tilde.local/sync/{}</d:sync-token>
      {}{}
      <cal:supported-calendar-component-set>
        <cal:comp name="VEVENT"/>
        <cal:comp name="VTODO"/>
      </cal:supported-calendar-component-set>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                    p,
                    name,
                    escape_xml(&display_name),
                    ctag,
                    sync_token,
                    desc_xml,
                    color_xml
                ));
            }
        }

        let xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/">
{}</d:multistatus>"#,
            responses
        );
        return xml_response(StatusCode::MULTI_STATUS, xml);
    }

    // Calendar level
    if let Some(cal_name) = cal_name {
        if let Some(obj_name) = obj_name {
            // Single object PROPFIND
            let uid = obj_name.trim_end_matches(".ics");
            match db.query_row(
                "SELECT co.uid, co.etag FROM calendar_objects co
                 JOIN calendars c ON co.calendar_id = c.id
                 WHERE c.name = ?1 AND co.uid = ?2 AND co.deleted = 0",
                rusqlite::params![cal_name, uid],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ) {
                Ok((uid, etag)) => {
                    let p = principal.unwrap_or("admin");
                    let xml = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>
      <d:resourcetype/>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>
</d:multistatus>"#,
                        p, cal_name, uid, etag
                    );
                    xml_response(StatusCode::MULTI_STATUS, xml)
                }
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        } else {
            // Calendar collection PROPFIND
            let cal_result = db.query_row(
                "SELECT id, display_name, ctag, description, color, sync_token FROM calendars WHERE name = ?1",
                [cal_name],
                |row| Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, i64>(5)?,
                )),
            );

            match cal_result {
                Ok((cal_id, display_name, ctag, description, color, sync_token)) => {
                    let p = principal.unwrap_or("admin");
                    let desc_xml = description
                        .map(|d| {
                            format!(
                                "<cal:calendar-description>{}</cal:calendar-description>",
                                escape_xml(&d)
                            )
                        })
                        .unwrap_or_default();
                    let color_xml = color.map(|c| format!("<x:calendar-color xmlns:x=\"http://apple.com/ns/ical/\">{}</x:calendar-color>", escape_xml(&c))).unwrap_or_default();
                    let mut responses = format!(
                        r#"<d:response>
  <d:href>/caldav/{}/{}/</d:href>
  <d:propstat>
    <d:prop>
      <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
      <d:displayname>{}</d:displayname>
      <cs:getctag xmlns:cs="http://calendarserver.org/ns/">{}</cs:getctag>
      <d:sync-token>http://tilde.local/sync/{}</d:sync-token>
      {}{}
      <cal:supported-calendar-component-set>
        <cal:comp name="VEVENT"/>
        <cal:comp name="VTODO"/>
      </cal:supported-calendar-component-set>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                        p,
                        cal_name,
                        escape_xml(&display_name),
                        ctag,
                        sync_token,
                        desc_xml,
                        color_xml
                    );

                    if depth == "1" {
                        let mut stmt = db.prepare(
                            "SELECT uid, etag FROM calendar_objects WHERE calendar_id = ?1 AND deleted = 0"
                        ).unwrap();
                        let objects = stmt
                            .query_map([&cal_id], |row| {
                                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
                            })
                            .unwrap();
                        for obj in objects.flatten() {
                            let (uid, etag) = obj;
                            responses.push_str(&format!(
                                r#"
<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <d:getcontenttype>text/calendar; charset=utf-8</d:getcontenttype>
      <d:resourcetype/>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                                p, cal_name, uid, etag
                            ));
                        }
                    }

                    let xml = format!(
                        r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav" xmlns:cs="http://calendarserver.org/ns/">
{}</d:multistatus>"#,
                        responses
                    );
                    xml_response(StatusCode::MULTI_STATUS, xml)
                }
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

fn handle_proppatch(state: &SharedCalDavState, path: &str, body: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_principal, cal_name, _) = parse_path(path);

    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    if let Some(display_name) = extract_xml_value(body, "displayname") {
        let updated = db.execute(
            "UPDATE calendars SET display_name = ?1, updated_at = ?2, ctag = CAST(CAST(ctag AS INTEGER) + 1 AS TEXT) WHERE name = ?3",
            rusqlite::params![display_name, now, cal_name],
        ).unwrap_or(0);
        if updated > 0 {
            let xml = format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:">
<d:response>
  <d:href>/caldav/admin/{}/</d:href>
  <d:propstat>
    <d:prop><d:displayname/></d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>
</d:multistatus>"#,
                cal_name
            );
            return xml_response(StatusCode::MULTI_STATUS, xml);
        }
    }

    StatusCode::NOT_FOUND.into_response()
}

fn handle_mkcalendar(
    state: &SharedCalDavState,
    path: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_principal, cal_name, _) = parse_path(path);

    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };

    let exists: bool = db
        .query_row(
            "SELECT COUNT(*) FROM calendars WHERE name = ?1",
            [cal_name],
            |row| row.get::<_, i64>(0),
        )
        .unwrap_or(0)
        > 0;

    if exists {
        return (StatusCode::CONFLICT, "Calendar already exists").into_response();
    }

    let display_name =
        extract_xml_value(body, "displayname").unwrap_or_else(|| cal_name.to_string());
    let description = extract_xml_value(body, "calendar-description");
    let color = extract_xml_value(body, "calendar-color");

    let id = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    match db.execute(
        "INSERT INTO calendars (id, name, display_name, color, description, ctag, sync_token, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, '1', 0, ?6, ?7)",
        rusqlite::params![id, cal_name, display_name, color, description, now, now],
    ) {
        Ok(_) => StatusCode::CREATED.into_response(),
        Err(e) => {
            tracing::error!(error = %e, "Failed to create calendar");
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

fn handle_put(
    state: &SharedCalDavState,
    path: &str,
    body: &str,
    if_match: Option<&str>,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_principal, cal_name, obj_name) = parse_path(path);

    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let obj_name = match obj_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let uid = obj_name.trim_end_matches(".ics");

    let cal_id: String = match db.query_row(
        "SELECT id FROM calendars WHERE name = ?1",
        [cal_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let existing = db.query_row(
        "SELECT etag FROM calendar_objects WHERE calendar_id = ?1 AND uid = ?2 AND deleted = 0",
        rusqlite::params![cal_id, uid],
        |row| row.get::<_, String>(0),
    );

    if let Some(expected) = if_match {
        match &existing {
            Ok(current_etag) => {
                if current_etag != expected.trim_matches('"') {
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

    let component_type = if body.contains("VTODO") {
        "VTODO"
    } else {
        "VEVENT"
    };
    let summary = extract_ics_field(body, "SUMMARY");
    let dtstart = extract_ics_field(body, "DTSTART");
    let dtend = extract_ics_field(body, "DTEND");
    let location = extract_ics_field(body, "LOCATION");
    let description = extract_ics_field(body, "DESCRIPTION");
    let priority = extract_ics_field(body, "PRIORITY").and_then(|p| p.parse::<i32>().ok());
    let ics_status = extract_ics_field(body, "STATUS");
    let is_new = existing.is_err();

    if is_new {
        db.execute(
            "INSERT INTO calendar_objects (id, calendar_id, uid, ics_data, etag, component_type, summary, dtstart, dtend, location, description, priority, status, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15)",
            rusqlite::params![
                uuid::Uuid::new_v4().to_string(), cal_id, uid, body, etag,
                component_type, summary, dtstart, dtend, location, description, priority, ics_status, now, now
            ],
        ).unwrap();
    } else {
        db.execute(
            "UPDATE calendar_objects SET ics_data = ?1, etag = ?2, summary = ?3, dtstart = ?4, dtend = ?5,
             location = ?6, description = ?7, priority = ?8, status = ?9, updated_at = ?10, component_type = ?11
             WHERE calendar_id = ?12 AND uid = ?13 AND deleted = 0",
            rusqlite::params![
                body, etag, summary, dtstart, dtend, location, description, priority, ics_status, now, component_type, cal_id, uid
            ],
        ).unwrap();
    }

    // Update ctag and sync_token
    let new_sync_token: i64 = db
        .query_row(
            "SELECT sync_token FROM calendars WHERE id = ?1",
            [&cal_id],
            |row| row.get(0),
        )
        .unwrap_or(0)
        + 1;

    db.execute(
        "UPDATE calendars SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3",
        rusqlite::params![new_sync_token, now, cal_id],
    ).unwrap();

    let change_type = if is_new { "created" } else { "modified" };
    db.execute(
        "INSERT INTO sync_changes (collection_type, collection_id, object_uri, change_type, sync_token, created_at)
         VALUES ('calendar', ?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![cal_id, format!("{}.ics", uid), change_type, new_sync_token, now],
    ).unwrap();

    let status = if is_new {
        StatusCode::CREATED
    } else {
        StatusCode::NO_CONTENT
    };
    (status, [(header::ETAG, format!("\"{}\"", etag))]).into_response()
}

fn handle_get(state: &SharedCalDavState, path: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_principal, cal_name, obj_name) = parse_path(path);

    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    match obj_name {
        Some(name) => {
            let uid = name.trim_end_matches(".ics");
            match db.query_row(
                "SELECT co.ics_data, co.etag FROM calendar_objects co
                 JOIN calendars c ON co.calendar_id = c.id
                 WHERE c.name = ?1 AND co.uid = ?2 AND co.deleted = 0",
                rusqlite::params![cal_name, uid],
                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
            ) {
                Ok((ics_data, etag)) => (
                    StatusCode::OK,
                    [
                        (
                            header::CONTENT_TYPE,
                            "text/calendar; charset=utf-8".to_string(),
                        ),
                        (header::ETAG, format!("\"{}\"", etag)),
                    ],
                    ics_data,
                )
                    .into_response(),
                Err(_) => StatusCode::NOT_FOUND.into_response(),
            }
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn handle_delete(state: &SharedCalDavState, path: &str) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let (_principal, cal_name, obj_name) = parse_path(path);
    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    match obj_name {
        Some(name) => {
            let uid = name.trim_end_matches(".ics");
            let cal_id: String = match db.query_row(
                "SELECT id FROM calendars WHERE name = ?1",
                [cal_name],
                |row| row.get(0),
            ) {
                Ok(id) => id,
                Err(_) => return StatusCode::NOT_FOUND.into_response(),
            };

            let affected = db.execute(
                "UPDATE calendar_objects SET deleted = 1, updated_at = ?1 WHERE calendar_id = ?2 AND uid = ?3 AND deleted = 0",
                rusqlite::params![now, cal_id, uid],
            ).unwrap_or(0);

            if affected == 0 {
                return StatusCode::NOT_FOUND.into_response();
            }

            let new_sync_token: i64 = db
                .query_row(
                    "SELECT sync_token FROM calendars WHERE id = ?1",
                    [&cal_id],
                    |row| row.get(0),
                )
                .unwrap_or(0)
                + 1;

            db.execute(
                "UPDATE calendars SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3",
                rusqlite::params![new_sync_token, now, cal_id],
            ).unwrap();

            db.execute(
                "INSERT INTO sync_changes (collection_type, collection_id, object_uri, change_type, sync_token, created_at)
                 VALUES ('calendar', ?1, ?2, 'deleted', ?3, ?4)",
                rusqlite::params![cal_id, format!("{}.ics", uid), new_sync_token, now],
            ).unwrap();

            StatusCode::NO_CONTENT.into_response()
        }
        None => {
            let affected = db
                .execute("DELETE FROM calendars WHERE name = ?1", [cal_name])
                .unwrap_or(0);
            if affected == 0 {
                StatusCode::NOT_FOUND.into_response()
            } else {
                StatusCode::NO_CONTENT.into_response()
            }
        }
    }
}

fn handle_report(state: &SharedCalDavState, path: &str, body: &str) -> axum::response::Response {
    let (_principal, cal_name, _) = parse_path(path);
    let cal_name = match cal_name {
        Some(n) => n,
        None => return StatusCode::BAD_REQUEST.into_response(),
    };
    let principal = "admin";

    if body.contains("calendar-multiget") {
        handle_multiget_report(state, cal_name, principal, body)
    } else if body.contains("sync-collection") {
        handle_sync_collection_report(state, cal_name, principal, body)
    } else if body.contains("free-busy-query") {
        handle_freebusy_report(state, cal_name, principal, body)
    } else {
        handle_calendar_query_report(state, cal_name, principal, body)
    }
}

fn handle_calendar_query_report(
    state: &SharedCalDavState,
    cal_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let cal_id: String = match db.query_row(
        "SELECT id FROM calendars WHERE name = ?1",
        [cal_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let start = extract_xml_attr(body, "time-range", "start");
    let end = extract_xml_attr(body, "time-range", "end");

    let mut query =
        "SELECT uid, etag, ics_data FROM calendar_objects WHERE calendar_id = ?1 AND deleted = 0"
            .to_string();
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![Box::new(cal_id)];

    if let Some(ref s) = start {
        query.push_str(" AND (dtend IS NULL OR dtend >= ?2)");
        params.push(Box::new(s.clone()));
    }
    if let Some(ref e) = end {
        let idx = params.len() + 1;
        query.push_str(&format!(" AND (dtstart IS NULL OR dtstart <= ?{})", idx));
        params.push(Box::new(e.clone()));
    }

    let mut stmt = db.prepare(&query).unwrap();
    let param_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    let objects: Vec<(String, String, String)> = stmt
        .query_map(param_refs.as_slice(), |row| {
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
    for (uid, etag, ics_data) in &objects {
        responses.push_str(&format!(
            r#"<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <cal:calendar-data>{}</cal:calendar-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
            principal,
            cal_name,
            uid,
            etag,
            escape_xml(ics_data)
        ));
    }

    xml_response(
        StatusCode::MULTI_STATUS,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
{}</d:multistatus>"#,
            responses
        ),
    )
}

fn handle_multiget_report(
    state: &SharedCalDavState,
    cal_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let hrefs = extract_hrefs(body);

    let cal_id: String = match db.query_row(
        "SELECT id FROM calendars WHERE name = ?1",
        [cal_name],
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
            .trim_end_matches(".ics");
        match db.query_row(
            "SELECT uid, etag, ics_data FROM calendar_objects WHERE calendar_id = ?1 AND uid = ?2 AND deleted = 0",
            rusqlite::params![cal_id, uid],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
        ) {
            Ok((uid, etag, ics_data)) => {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <cal:calendar-data>{}</cal:calendar-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#, principal, cal_name, uid, etag, escape_xml(&ics_data)));
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
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
{}</d:multistatus>"#,
            responses
        ),
    )
}

fn handle_sync_collection_report(
    state: &SharedCalDavState,
    cal_name: &str,
    principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let cal_id: String = match db.query_row(
        "SELECT id FROM calendars WHERE name = ?1",
        [cal_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let sync_token = extract_xml_value(body, "sync-token")
        .and_then(|t| t.rsplit('/').next().and_then(|n| n.parse::<i64>().ok()))
        .unwrap_or(0);

    let current_sync_token: i64 = db
        .query_row(
            "SELECT sync_token FROM calendars WHERE id = ?1",
            [&cal_id],
            |row| row.get(0),
        )
        .unwrap_or(0);

    let mut responses = String::new();

    if sync_token == 0 {
        let mut stmt = db.prepare(
            "SELECT uid, etag, ics_data FROM calendar_objects WHERE calendar_id = ?1 AND deleted = 0"
        ).unwrap();
        let objects: Vec<(String, String, String)> = stmt
            .query_map([&cal_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .unwrap()
            .flatten()
            .collect();

        for (uid, etag, ics_data) in &objects {
            responses.push_str(&format!(
                r#"<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:propstat>
    <d:prop>
      <d:getetag>"{}"</d:getetag>
      <cal:calendar-data>{}</cal:calendar-data>
    </d:prop>
    <d:status>HTTP/1.1 200 OK</d:status>
  </d:propstat>
</d:response>"#,
                principal,
                cal_name,
                uid,
                etag,
                escape_xml(ics_data)
            ));
        }
    } else {
        let mut stmt = db
            .prepare(
                "SELECT object_uri, change_type FROM sync_changes
             WHERE collection_type = 'calendar' AND collection_id = ?1 AND sync_token > ?2
             ORDER BY sync_token",
            )
            .unwrap();
        let changes: Vec<(String, String)> = stmt
            .query_map(rusqlite::params![cal_id, sync_token], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .unwrap()
            .flatten()
            .collect();

        for (object_uri, change_type) in &changes {
            let uid = object_uri.trim_end_matches(".ics");
            if change_type == "deleted" {
                responses.push_str(&format!(
                    r#"<d:response>
  <d:href>/caldav/{}/{}/{}.ics</d:href>
  <d:status>HTTP/1.1 404 Not Found</d:status>
</d:response>"#,
                    principal, cal_name, uid
                ));
            } else if let Ok((uid, etag, ics_data)) = db.query_row(
                                "SELECT uid, etag, ics_data FROM calendar_objects WHERE calendar_id = ?1 AND uid = ?2 AND deleted = 0",
                                rusqlite::params![cal_id, uid],
                                |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, String>(2)?)),
                            ) {
                                responses.push_str(&format!(
                                    r#"<d:response>
              <d:href>/caldav/{}/{}/{}.ics</d:href>
              <d:propstat>
                <d:prop>
                  <d:getetag>"{}"</d:getetag>
                  <cal:calendar-data>{}</cal:calendar-data>
                </d:prop>
                <d:status>HTTP/1.1 200 OK</d:status>
              </d:propstat>
            </d:response>"#, principal, cal_name, uid, etag, escape_xml(&ics_data)));
                            }
        }
    }

    xml_response(
        StatusCode::MULTI_STATUS,
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
{}
<d:sync-token>http://tilde.local/sync/{}</d:sync-token>
</d:multistatus>"#,
            responses, current_sync_token
        ),
    )
}

fn handle_freebusy_report(
    state: &SharedCalDavState,
    cal_name: &str,
    _principal: &str,
    body: &str,
) -> axum::response::Response {
    let db = state.db.lock().unwrap();
    let cal_id: String = match db.query_row(
        "SELECT id FROM calendars WHERE name = ?1",
        [cal_name],
        |row| row.get(0),
    ) {
        Ok(id) => id,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let start = extract_xml_attr(body, "time-range", "start").unwrap_or_default();
    let end = extract_xml_attr(body, "time-range", "end").unwrap_or_default();

    let mut stmt = db
        .prepare(
            "SELECT dtstart, dtend FROM calendar_objects
         WHERE calendar_id = ?1 AND deleted = 0 AND component_type = 'VEVENT'
         AND dtend >= ?2 AND dtstart <= ?3",
        )
        .unwrap();

    let busy: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![cal_id, start, end], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .unwrap()
        .flatten()
        .collect();

    let mut fb_lines = String::new();
    for (s, e) in &busy {
        fb_lines.push_str(&format!("FREEBUSY:{}/{}\r\n", s, e));
    }

    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//EN\r\n\
         BEGIN:VFREEBUSY\r\nDTSTART:{}\r\nDTEND:{}\r\n{}END:VFREEBUSY\r\n\
         END:VCALENDAR\r\n",
        start, end, fb_lines
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/calendar; charset=utf-8")],
        ics,
    )
        .into_response()
}

// ─── Helpers ────────────────────────────────────────────────────────────────

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn extract_xml_value(xml: &str, tag_name: &str) -> Option<String> {
    let patterns = [
        format!("<{}>", tag_name),
        format!("<d:{}>", tag_name),
        format!("<cal:{}>", tag_name),
        format!("<C:{}>", tag_name),
        format!("<D:{}>", tag_name),
    ];
    for pat in &patterns {
        if let Some(start_idx) = xml.find(pat.as_str()) {
            let content_start = start_idx + pat.len();
            if let Some(end_idx) = xml[content_start..].find("</") {
                return Some(
                    xml[content_start..content_start + end_idx]
                        .trim()
                        .to_string(),
                );
            }
        }
    }
    // Try any namespace prefix
    let search = format!(":{}>", tag_name);
    if let Some(pos) = xml.find(&search) {
        let content_start = pos + search.len();
        if let Some(end_idx) = xml[content_start..].find("</") {
            return Some(
                xml[content_start..content_start + end_idx]
                    .trim()
                    .to_string(),
            );
        }
    }
    None
}

fn extract_xml_attr(xml: &str, tag_name: &str, attr_name: &str) -> Option<String> {
    for prefix in &["", "cal:", "C:"] {
        let pat = format!("<{}{} ", prefix, tag_name);
        if let Some(start_idx) = xml.find(&pat) {
            let tag_content = &xml[start_idx..];
            if let Some(end) = tag_content.find('>') {
                let tag_str = &tag_content[..end];
                let attr_pat = format!("{}=\"", attr_name);
                if let Some(attr_start) = tag_str.find(&attr_pat) {
                    let val_start = attr_start + attr_pat.len();
                    if let Some(val_end) = tag_str[val_start..].find('"') {
                        return Some(tag_str[val_start..val_start + val_end].to_string());
                    }
                }
            }
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
                found = Some((search_from + pos + pat.len(), pat.len()));
                break;
            }
        }
        match found {
            Some((content_start, _)) => {
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

fn extract_ics_field(ics: &str, field: &str) -> Option<String> {
    for line in ics.lines() {
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

type EventRecord = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

pub fn list_events(
    db: &Connection,
    calendar: Option<&str>,
    from: Option<&str>,
    to: Option<&str>,
) -> Vec<EventRecord> {
    let mut query = String::from(
        "SELECT co.uid, co.component_type, co.summary, co.dtstart, co.dtend, co.location, co.status
         FROM calendar_objects co JOIN calendars c ON co.calendar_id = c.id WHERE co.deleted = 0",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
    let mut idx = 1;
    if let Some(cal) = calendar {
        query.push_str(&format!(" AND c.name = ?{}", idx));
        params.push(Box::new(cal.to_string()));
        idx += 1;
    }
    if let Some(f) = from {
        query.push_str(&format!(" AND (co.dtend IS NULL OR co.dtend >= ?{})", idx));
        params.push(Box::new(f.to_string()));
        idx += 1;
    }
    if let Some(t) = to {
        query.push_str(&format!(
            " AND (co.dtstart IS NULL OR co.dtstart <= ?{})",
            idx
        ));
        params.push(Box::new(t.to_string()));
    }
    query.push_str(" ORDER BY co.dtstart");
    let mut stmt = db.prepare(&query).unwrap();
    let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    stmt.query_map(refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, Option<String>>(6)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}

pub fn list_calendars(db: &Connection) -> Vec<(String, String, String, Option<String>)> {
    let mut stmt = db
        .prepare("SELECT name, display_name, ctag, description FROM calendars")
        .unwrap();
    stmt.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
            row.get::<_, Option<String>>(3)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}

pub fn create_event(
    db: &Connection,
    calendar_name: &str,
    summary: &str,
    start: &str,
    end: &str,
    location: Option<&str>,
    description: Option<&str>,
) -> anyhow::Result<String> {
    let cal_id: String = db
        .query_row(
            "SELECT id FROM calendars WHERE name = ?1",
            [calendar_name],
            |row| row.get(0),
        )
        .map_err(|_| anyhow::anyhow!("calendar '{}' not found", calendar_name))?;

    let uid = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let mut ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//EN\r\nBEGIN:VEVENT\r\nUID:{}\r\nSUMMARY:{}\r\nDTSTART:{}\r\nDTEND:{}\r\n",
        uid, summary, start, end
    );
    if let Some(loc) = location {
        ics.push_str(&format!("LOCATION:{}\r\n", loc));
    }
    if let Some(desc) = description {
        ics.push_str(&format!("DESCRIPTION:{}\r\n", desc));
    }
    ics.push_str("END:VEVENT\r\nEND:VCALENDAR\r\n");
    let etag = compute_etag(&ics);

    db.execute(
        "INSERT INTO calendar_objects (id, calendar_id, uid, ics_data, etag, component_type, summary, dtstart, dtend, location, description, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'VEVENT', ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
        rusqlite::params![uuid::Uuid::new_v4().to_string(), cal_id, uid, ics, etag, summary, start, end, location, description, now, now],
    )?;

    let new_st: i64 = db
        .query_row(
            "SELECT sync_token FROM calendars WHERE id = ?1",
            [&cal_id],
            |row| row.get(0),
        )
        .unwrap_or(0)
        + 1;
    db.execute("UPDATE calendars SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![new_st, now, cal_id])?;
    Ok(uid)
}

pub fn create_task(
    db: &Connection,
    calendar_name: Option<&str>,
    summary: &str,
    due: Option<&str>,
    priority: Option<i32>,
) -> anyhow::Result<String> {
    let cal_name = calendar_name.unwrap_or("default");
    ensure_default_calendar(db);
    let cal_id: String = db
        .query_row(
            "SELECT id FROM calendars WHERE name = ?1",
            [cal_name],
            |row| row.get(0),
        )
        .map_err(|_| anyhow::anyhow!("calendar '{}' not found", cal_name))?;

    let uid = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let mut ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//EN\r\nBEGIN:VTODO\r\nUID:{}\r\nSUMMARY:{}\r\nSTATUS:NEEDS-ACTION\r\n",
        uid, summary
    );
    if let Some(d) = due {
        ics.push_str(&format!("DUE:{}\r\n", d));
    }
    if let Some(p) = priority {
        ics.push_str(&format!("PRIORITY:{}\r\n", p));
    }
    ics.push_str("END:VTODO\r\nEND:VCALENDAR\r\n");
    let etag = compute_etag(&ics);

    db.execute(
        "INSERT INTO calendar_objects (id, calendar_id, uid, ics_data, etag, component_type, summary, dtstart, priority, status, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, 'VTODO', ?6, ?7, ?8, 'NEEDS-ACTION', ?9, ?10)",
        rusqlite::params![uuid::Uuid::new_v4().to_string(), cal_id, uid, ics, etag, summary, due, priority, now, now],
    )?;

    let new_st: i64 = db
        .query_row(
            "SELECT sync_token FROM calendars WHERE id = ?1",
            [&cal_id],
            |row| row.get(0),
        )
        .unwrap_or(0)
        + 1;
    db.execute("UPDATE calendars SET ctag = CAST(?1 AS TEXT), sync_token = ?1, updated_at = ?2 WHERE id = ?3", rusqlite::params![new_st, now, cal_id])?;
    Ok(uid)
}

type TaskRecord = (
    String,
    Option<String>,
    Option<String>,
    Option<i32>,
    Option<String>,
);

pub fn list_tasks(
    db: &Connection,
    calendar: Option<&str>,
    status: Option<&str>,
) -> Vec<TaskRecord> {
    let mut query = String::from(
        "SELECT co.uid, co.summary, co.dtstart, co.priority, co.status
         FROM calendar_objects co JOIN calendars c ON co.calendar_id = c.id
         WHERE co.deleted = 0 AND co.component_type = 'VTODO'",
    );
    let mut params: Vec<Box<dyn rusqlite::types::ToSql>> = vec![];
    let mut idx = 1;
    if let Some(cal) = calendar {
        query.push_str(&format!(" AND c.name = ?{}", idx));
        params.push(Box::new(cal.to_string()));
        idx += 1;
    }
    if let Some(s) = status {
        query.push_str(&format!(" AND co.status = ?{}", idx));
        params.push(Box::new(s.to_string()));
    }
    let mut stmt = db.prepare(&query).unwrap();
    let refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| p.as_ref()).collect();
    stmt.query_map(refs.as_slice(), |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, Option<String>>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<i32>>(3)?,
            row.get::<_, Option<String>>(4)?,
        ))
    })
    .unwrap()
    .flatten()
    .collect()
}
