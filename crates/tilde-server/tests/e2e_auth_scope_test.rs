//! Credential scope enforcement over real HTTP.
//!
//! App passwords carry a `scope_prefix`. Scope logic lives in `tilde-core` and is
//! unit-tested there, but nothing has checked that the **real server** applies it
//! to every mount — a security boundary deserves a test at the boundary.

mod common;

use common::e2e::{Client, run_cli, start_server};

fn scoped_client(server: &common::e2e::Server, name: &str, scope: &str) -> Client {
    let config = server.data_dir.parent().unwrap().join("config.toml");
    let out = run_cli(
        &[
            "auth",
            "app-password",
            "create",
            "--name",
            name,
            "--scope",
            scope,
        ],
        config.to_str().unwrap(),
        server.data_dir.to_str().unwrap(),
    );
    let pw = out
        .split_whitespace()
        .find(|w| w.starts_with("tilde_app_"))
        .unwrap()
        .to_string();
    Client::new(server, &pw)
}

#[test]
fn e2e_caldav_scoped_password_cannot_read_notes() {
    let (server, _) = start_server(&["admin"]);
    let caldav_only = scoped_client(&server, "caldav-only", "/caldav/");

    let (status, _) = caldav_only.get("/dav/notes/secret.md");

    assert_eq!(
        status, 401,
        "a /caldav/-scoped credential must not reach the notes mount"
    );
}

#[test]
fn e2e_caldav_scoped_password_cannot_write_notes() {
    let (server, pws) = start_server(&["admin"]);
    let admin = Client::new(&server, &pws[0]);
    admin.put("/dav/notes/secret.md", "private");

    let caldav_only = scoped_client(&server, "caldav-only2", "/caldav/");
    let status = caldav_only.put("/dav/notes/secret.md", "overwritten");

    assert_eq!(status, 401, "scope must gate writes, not just reads");

    let (_, body) = admin.get("/dav/notes/secret.md");
    assert_eq!(body, "private", "content must be untouched");
}

#[test]
fn e2e_revoked_password_stops_working_immediately() {
    let (server, _) = start_server(&["admin"]);
    let doomed = scoped_client(&server, "doomed", "*");
    assert_eq!(doomed.put("/dav/notes/r.md", "hello"), 201);

    let config = server.data_dir.parent().unwrap().join("config.toml");
    run_cli(
        &["auth", "app-password", "revoke", "doomed"],
        config.to_str().unwrap(),
        server.data_dir.to_str().unwrap(),
    );

    assert_eq!(
        doomed.get("/dav/notes/r.md").0,
        401,
        "revocation must take effect without a restart"
    );
}

#[test]
fn e2e_no_credentials_is_rejected() {
    let (server, _) = start_server(&["admin"]);
    let anon = reqwest::blocking::Client::new();

    let resp = anon
        .get(format!("{}/dav/notes/anything.md", server.base_url))
        .send()
        .unwrap();

    assert_eq!(resp.status().as_u16(), 401);
}

/// The DAV-family rule, pinned deliberately.
///
/// Issue #8: "/dav/*" is intended to cover CalDAV and CardDAV too, since they are
/// DAV protocols. That intent was previously implemented by passing the constant
/// "/dav/" as the request path everywhere, which also made every narrower scope
/// useless. The rule is now explicit, so this keeps working while "/caldav/*"
/// also works on its own mount.
#[test]
fn e2e_dav_scope_covers_the_whole_dav_family() {
    let (server, _) = start_server(&["admin"]);
    let dav = scoped_client(&server, "dav-family", "/dav/*");

    for path in ["/caldav/admin/default/", "/carddav/admin/default/"] {
        let resp = dav
            .http
            .request(
                reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
                format!("{}{}", server.base_url, path),
            )
            .basic_auth("admin", Some(&dav.password))
            .header("Depth", "1")
            .send()
            .unwrap();
        assert_eq!(
            resp.status().as_u16(),
            207,
            "/dav/* is documented to cover {} (Issue #8)",
            path
        );
    }
    assert_eq!(dav.put("/dav/notes/ok.md", "fine"), 201);
}

/// A calendar-only credential must be able to exist and work — previously
/// impossible, since it was rejected on every mount including its own.
#[test]
fn e2e_caldav_scoped_password_can_use_caldav() {
    let (server, _) = start_server(&["admin"]);
    let cal_only = scoped_client(&server, "cal-only", "/caldav/*");

    let resp = cal_only
        .http
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/caldav/admin/default/", server.base_url),
        )
        .basic_auth("admin", Some(&cal_only.password))
        .header("Depth", "1")
        .send()
        .unwrap();
    assert_eq!(
        resp.status().as_u16(),
        207,
        "a /caldav/*-scoped credential must work on its own mount"
    );

    // ...and nowhere else.
    assert_eq!(cal_only.get("/dav/notes/x.md").0, 401);
}

/// A wildcard credential keeps working everywhere, which is the migration path
/// for anyone whose existing credential spanned mounts.
#[test]
fn e2e_wildcard_scope_still_reaches_every_mount() {
    let (server, _) = start_server(&["admin"]);
    let all = scoped_client(&server, "everything", "*");

    assert_eq!(all.put("/dav/notes/a.md", "x"), 201);
    let resp = all
        .http
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/caldav/admin/default/", server.base_url),
        )
        .basic_auth("admin", Some(&all.password))
        .header("Depth", "1")
        .send()
        .unwrap();
    assert_eq!(resp.status().as_u16(), 207);
}

/// Malformed input must produce an HTTP response, never a dropped connection.
///
/// Handlers parse attacker-supplied iCalendar, vCard, EXIF and XML with
/// hand-rolled byte slicing; `&str[..n]` panics on a multibyte boundary. Before
/// CatchPanicLayer a single malformed request aborted the connection with no HTTP
/// response, and the server kept serving but that client saw a network error.
#[test]
fn e2e_malformed_input_gets_a_response_and_the_server_survives() {
    let (server, _) = start_server(&["admin"]);
    let c = scoped_client(&server, "all", "*");

    // The filter is only evaluated against existing objects, so seed one.
    let ics = "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nBEGIN:VEVENT\r\nUID:panic-probe\r\n\
               DTSTART:20260101T000000Z\r\nDTEND:20260101T010000Z\r\nSUMMARY:probe\r\n\
               END:VEVENT\r\nEND:VCALENDAR\r\n";
    let put = c
        .http
        .put(format!(
            "{}/caldav/admin/default/panic-probe.ics",
            server.base_url
        ))
        .basic_auth("admin", Some(&c.password))
        .header("Content-Type", "text/calendar")
        .body(ics)
        .send()
        .unwrap();
    assert!(
        put.status().is_success(),
        "seed PUT failed: {}",
        put.status()
    );

    // A REPORT whose time-range start is non-ASCII: parse_ical_datetime slices
    // &s[0..4] on it.
    let body = r#"<?xml version="1.0"?>
<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:">
  <D:prop><D:getetag/></D:prop>
  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
    <C:time-range start="aa€€"/>
  </C:comp-filter></C:comp-filter></C:filter>
</C:calendar-query>"#;

    let resp = c
        .http
        .request(
            reqwest::Method::from_bytes(b"REPORT").unwrap(),
            format!("{}/caldav/admin/default/", server.base_url),
        )
        .basic_auth("admin", Some(&c.password))
        .header("Depth", "1")
        .body(body.to_string())
        .send();

    // The point is not *which* status: a hardened parser may legitimately ignore
    // an unparseable range and return 207. What must never happen is the
    // connection being dropped with no HTTP response at all, which is what a
    // panic in a handler produces and what a client sees as a network failure.
    match resp {
        Ok(r) => {
            let code = r.status().as_u16();
            assert!(
                (200..600).contains(&code),
                "expected an HTTP status, got {}",
                code
            );
        }
        Err(e) => panic!(
            "malformed input dropped the connection instead of returning a status: {}",
            e
        ),
    }

    // The server must still be serving afterwards.
    assert_eq!(c.put("/dav/notes/alive.md", "still here"), 201);
}
