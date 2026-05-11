//! CalDAV integration tests.
//!
//! Tests MKCALENDAR, event CRUD, REPORT (multiget, calendar-query, sync-collection),
//! If-None-Match, Content-Type validation, and wrong-principal rejection.

mod common;

use axum::http::{Method, StatusCode, header};

fn sample_event(uid: &str, summary: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
         BEGIN:VEVENT\r\nUID:{uid}\r\nSUMMARY:{summary}\r\n\
         DTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

// ─── Basic operations ─────────────────────────────────────────────────────────

#[tokio::test]
async fn propfind_admin_principal() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/caldav/admin/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn propfind_depth_1_lists_calendars() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/caldav/admin/")
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("default"));
    assert!(body.contains("Personal"));
}

#[tokio::test]
async fn mkcalendar() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(
            Method::from_bytes(b"MKCALENDAR").unwrap(),
            "/caldav/admin/work/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::CREATED);
}

#[tokio::test]
async fn put_get_delete_event() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("event1", "Test Event");

    // PUT
    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // GET
    let resp = env
        .server
        .get("/caldav/admin/default/event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(body.contains("Test Event"));
    assert!(body.contains("event1"));

    // DELETE
    let resp = env
        .server
        .delete("/caldav/admin/default/event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // GET after delete -> 404
    let resp = env
        .server
        .get("/caldav/admin/default/event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_update_event_with_if_match() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics1 = sample_event("update-ev1", "Original");

    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/update-ev1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics1.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::CREATED);
    let etag = resp
        .header("etag")
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();

    // Update with If-Match
    let ics2 = sample_event("update-ev1", "Updated");
    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/update-ev1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::IF_MATCH, format!("\"{}\"", etag))
        .bytes(axum::body::Bytes::from(ics2.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // Verify updated content
    let resp = env
        .server
        .get("/caldav/admin/default/update-ev1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    assert!(resp.text().contains("Updated"));
}

// ─── REPORT ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn report_calendar_multiget() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("mg-event1", "Multiget Event");

    env.server
        .method(Method::PUT, "/caldav/admin/default/mg-event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<cal:calendar-multiget xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
  <d:href>/caldav/admin/default/mg-event1.ics</d:href>
</cal:calendar-multiget>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/caldav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("Multiget Event"));
}

#[tokio::test]
async fn report_calendar_query_time_range() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
        BEGIN:VEVENT\r\nUID:range-ev1\r\nSUMMARY:June Event\r\n\
        DTSTART:20260615T100000Z\r\nDTEND:20260615T110000Z\r\n\
        END:VEVENT\r\nEND:VCALENDAR\r\n";

    env.server
        .method(Method::PUT, "/caldav/admin/default/range-ev1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics))
        .content_type("text/calendar; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<cal:calendar-query xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
  <cal:filter>
    <cal:comp-filter name="VCALENDAR">
      <cal:comp-filter name="VEVENT">
        <cal:time-range start="20260601T000000Z" end="20260630T235959Z"/>
      </cal:comp-filter>
    </cal:comp-filter>
  </cal:filter>
</cal:calendar-query>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/caldav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("June Event"));
}

#[tokio::test]
async fn report_sync_collection() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("sync-ev1", "Sync Test");

    env.server
        .method(Method::PUT, "/caldav/admin/default/sync-ev1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:sync-collection xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:sync-token/>
  <d:prop>
    <d:getetag/>
    <cal:calendar-data/>
  </d:prop>
</d:sync-collection>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/caldav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("Sync Test"));
    assert!(body.contains("sync-token"));
}

// ─── Preconditions ────────────────────────────────────────────────────────────

#[tokio::test]
async fn if_none_match_star_on_existing_returns_412() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("inm-event1", "First");

    env.server
        .method(Method::PUT, "/caldav/admin/default/inm-event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;

    // Second PUT with If-None-Match: * should fail
    let ics2 = sample_event("inm-event1", "Second");
    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/inm-event1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::IF_NONE_MATCH, "*")
        .bytes(axum::body::Bytes::from(ics2.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn wrong_content_type_returns_415() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/bad.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .content_type("text/plain")
        .text("not ics")
        .await;
    resp.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ─── Principal validation ─────────────────────────────────────────────────────

#[tokio::test]
async fn wrong_principal_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/caldav/bob/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── Calendar management ──────────────────────────────────────────────────────

#[tokio::test]
async fn delete_calendar() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(
            Method::from_bytes(b"MKCALENDAR").unwrap(),
            "/caldav/admin/deletable/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    let resp = env
        .server
        .delete("/caldav/admin/deletable/")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn proppatch_calendar() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:">
  <d:set>
    <d:prop>
      <d:displayname>Renamed Calendar</d:displayname>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPPATCH").unwrap(),
            "/caldav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn options_calendar() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::OPTIONS, "/caldav/admin/default/")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
}

// ─── PROPFIND on events ───────────────────────────────────────────────────────

#[tokio::test]
async fn propfind_depth_1_lists_events() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("listed-ev", "Listed Event");

    env.server
        .method(Method::PUT, "/caldav/admin/default/listed-ev.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/caldav/admin/default/",
        )
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("listed-ev.ics"));
}

#[tokio::test]
async fn propfind_single_event() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = sample_event("single-ev", "Single Event");

    env.server
        .method(Method::PUT, "/caldav/admin/default/single-ev.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics.clone()))
        .content_type("text/calendar; charset=utf-8")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/caldav/admin/default/single-ev.ics",
        )
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("single-ev"));
}

// ─── VTODO support ────────────────────────────────────────────────────────────

#[tokio::test]
async fn vtodo_put_and_get() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "cal-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//test//EN\r\n\
        BEGIN:VTODO\r\nUID:todo1\r\nSUMMARY:Test Task\r\n\
        STATUS:NEEDS-ACTION\r\nPRIORITY:1\r\n\
        END:VTODO\r\nEND:VCALENDAR\r\n";

    let resp = env
        .server
        .method(Method::PUT, "/caldav/admin/default/todo1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(ics))
        .content_type("text/calendar; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let resp = env
        .server
        .get("/caldav/admin/default/todo1.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    let body = resp.text();
    assert!(body.contains("VTODO"));
    assert!(body.contains("Test Task"));
}

/// DELETE calendar MUST cascade to calendar_objects.
#[tokio::test]
async fn delete_calendar_cascades_to_objects() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(
            Method::from_bytes(b"MKCALENDAR").unwrap(),
            "/caldav/admin/temp2/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:orphan2\r\nSUMMARY:Orphan\r\nDTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n";
    env.server
        .method(Method::PUT, "/caldav/admin/temp2/orphan2.ics")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::CONTENT_TYPE, "text/calendar")
        .text(ics)
        .await;

    env.server
        .method(Method::DELETE, "/caldav/admin/temp2/")
        .add_header(header::AUTHORIZATION, &auth)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    let conn = env.pool.get().unwrap();
    let orphans: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM calendar_objects WHERE calendar_id NOT IN (SELECT id FROM calendars)",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(
        orphans, 0,
        "DELETE calendar left {} orphaned calendar_objects",
        orphans
    );
}
