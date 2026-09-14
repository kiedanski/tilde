//! Hostile-input regression tests for the CalDAV and CardDAV mounts.
//!
//! Every case here was a *reachable panic* or an injection reachable with an
//! ordinary `/caldav/*`-scoped credential. A panic inside an axum handler
//! unwinds the connection task, so the client sees the connection drop rather
//! than a status code — which is why each test finishes by proving the server
//! is still serving. Asserting "nothing crashed" alone would pass against a
//! server that had stopped doing anything useful, so each test also asserts the
//! operation's real effect.

mod common;

use common::e2e::{Client, Server, start_server};

const CAL: &str = "/caldav/admin/default";
const AB: &str = "/carddav/admin/default";
const ICS: &[(&str, &str)] = &[("Content-Type", "text/calendar; charset=utf-8")];
const VCF: &[(&str, &str)] = &[("Content-Type", "text/vcard; charset=utf-8")];
const REPORT_HDRS: &[(&str, &str)] = &[("Depth", "1"), ("Content-Type", "application/xml")];

/// Issue an arbitrary WebDAV method. `reqwest` surfaces a killed connection as
/// a transport error, so a handler panic shows up here as a panic with a clear
/// message rather than as a confusing status-code mismatch.
fn dav(
    c: &Client,
    method: &str,
    path: &str,
    body: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let mut rb = c
        .http
        .request(
            reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
            format!("{}{}", c.base_url, path),
        )
        .basic_auth("admin", Some(&c.password))
        .body(body.to_string());
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    let resp = rb.send().unwrap_or_else(|e| {
        panic!(
            "{} {} died at the transport level (handler panic?): {e}",
            method, path
        )
    });
    let status = resp.status().as_u16();
    (status, resp.text().unwrap_or_default())
}

fn event_ics(uid: &str, dtstart: &str, dtend: &str) -> String {
    format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//test//EN\r\nBEGIN:VEVENT\r\n\
         UID:{uid}\r\nSUMMARY:{uid}\r\nDTSTART:{dtstart}\r\nDTEND:{dtend}\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n"
    )
}

fn vcard(uid: &str, fn_name: &str, extra: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{uid}\r\nFN:{fn_name}\r\n{extra}END:VCARD\r\n")
}

/// The liveness check every panic regression ends with.
fn assert_caldav_alive(c: &Client) {
    let (status, body) = dav(c, "PROPFIND", &format!("{}/", CAL), "", REPORT_HDRS);
    assert_eq!(
        status, 207,
        "CalDAV stopped answering after the hostile request"
    );
    assert!(
        body.contains("<d:multistatus"),
        "CalDAV answered but not with a multistatus: {body}"
    );
}

fn assert_carddav_alive(c: &Client) {
    let (status, body) = dav(c, "PROPFIND", &format!("{}/", AB), "", REPORT_HDRS);
    assert_eq!(
        status, 207,
        "CardDAV stopped answering after the hostile request"
    );
    assert!(
        body.contains("<d:multistatus"),
        "CardDAV answered but not with a multistatus: {body}"
    );
}

fn admin(server: &Server, pws: &[String]) -> Client {
    Client::new(server, &pws[0])
}

// ── Re-PUT of a soft-deleted object ────────────────────────────────────────

/// DELETE is a soft delete: the row stays behind with `deleted = 1` as an
/// RFC 6578 tombstone so `sync-collection` can report the removal. That is
/// deliberate and is preserved. What was broken is that `deleted` is not part
/// of `UNIQUE(calendar_id, uid)`, so re-PUTting the same UID took the INSERT
/// branch and hit the unique constraint.
#[test]
fn e2e_caldav_reput_after_delete_recreates_the_event() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    let url = format!("{}/reput-evt.ics", CAL);

    assert_eq!(
        dav(
            &c,
            "PUT",
            &url,
            &event_ics("reput-evt", "20260601T100000Z", "20260601T110000Z"),
            ICS
        )
        .0,
        201,
        "initial PUT must create the event"
    );
    assert_eq!(c.get(&url).0, 200, "the event must be readable");
    assert_eq!(
        dav(&c, "DELETE", &url, "", &[]).0,
        204,
        "DELETE must succeed"
    );
    assert_eq!(
        c.get(&url).0,
        404,
        "a deleted event must be gone to clients"
    );

    let (status, _) = dav(
        &c,
        "PUT",
        &url,
        &event_ics("reput-evt", "20260701T100000Z", "20260701T110000Z"),
        ICS,
    );
    assert_eq!(
        status, 201,
        "re-PUT of a deleted UID must recreate the object"
    );

    let (gs, gb) = c.get(&url);
    assert_eq!(gs, 200, "the recreated event must be readable");
    assert!(
        gb.contains("20260701T100000Z"),
        "the recreated event must carry the new body, got: {gb}"
    );

    // The resurrected row must be the *same* row, not a duplicate.
    let (ps, pb) = dav(&c, "PROPFIND", &format!("{}/", CAL), "", REPORT_HDRS);
    assert_eq!(ps, 207);
    assert_eq!(
        pb.matches("reput-evt.ics").count(),
        1,
        "the calendar must list the event exactly once: {pb}"
    );

    // The tombstone machinery still works: an initial sync sees the live event.
    let sync = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:sync-collection xmlns:d="DAV:"><d:sync-token/><d:prop><d:getetag/></d:prop></d:sync-collection>"#;
    let (ss, sb) = dav(&c, "REPORT", &format!("{}/", CAL), sync, REPORT_HDRS);
    assert_eq!(ss, 207);
    assert!(
        sb.contains("reput-evt.ics"),
        "sync must report the live event: {sb}"
    );

    assert_caldav_alive(&c);
}

#[test]
fn e2e_carddav_reput_after_delete_recreates_the_contact() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    let url = format!("{}/reput-card.vcf", AB);

    assert_eq!(
        dav(
            &c,
            "PUT",
            &url,
            &vcard("reput-card", "Ada Lovelace", ""),
            VCF
        )
        .0,
        201,
        "initial PUT must create the contact"
    );
    assert_eq!(
        dav(&c, "DELETE", &url, "", &[]).0,
        204,
        "DELETE must succeed"
    );
    assert_eq!(
        c.get(&url).0,
        404,
        "a deleted contact must be gone to clients"
    );

    let (status, _) = dav(
        &c,
        "PUT",
        &url,
        &vcard("reput-card", "Grace Hopper", ""),
        VCF,
    );
    assert_eq!(
        status, 201,
        "re-PUT of a deleted UID must recreate the contact"
    );

    let (gs, gb) = c.get(&url);
    assert_eq!(gs, 200, "the recreated contact must be readable");
    assert!(
        gb.contains("Grace Hopper"),
        "the recreated contact must carry the new body, got: {gb}"
    );

    let (ps, pb) = dav(&c, "PROPFIND", &format!("{}/", AB), "", REPORT_HDRS);
    assert_eq!(ps, 207);
    assert_eq!(
        pb.matches("reput-card.vcf").count(),
        1,
        "the addressbook must list the contact exactly once: {pb}"
    );

    assert_carddav_alive(&c);
}

// ── Non-ASCII in iCalendar datetimes ───────────────────────────────────────

/// `parse_ical_datetime` sliced its input by byte offset. A `time-range` whose
/// `start` is non-ASCII split a character and panicked before any row was read.
#[test]
fn e2e_caldav_non_ascii_time_range_is_answered_not_fatal() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    let url = format!("{}/good-evt.ics", CAL);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &url,
            &event_ics("good-evt", "20260601T100000Z", "20260601T110000Z"),
            ICS
        )
        .0,
        201
    );

    let hostile = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/></D:prop>
  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
    <C:time-range start="aa€€" end="aa€€"/>
  </C:comp-filter></C:comp-filter></C:filter>
</C:calendar-query>"#;
    let (status, body) = dav(&c, "REPORT", &format!("{}/", CAL), hostile, REPORT_HDRS);
    assert_eq!(
        status, 207,
        "a malformed time-range must be answered, not crash"
    );
    assert!(
        body.contains("good-evt.ics"),
        "an unparseable range filters nothing out, so the event must still be listed: {body}"
    );

    // A well-formed range still filters, so the handler really ran.
    let narrow = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/></D:prop>
  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
    <C:time-range start="20270101T000000Z" end="20270102T000000Z"/>
  </C:comp-filter></C:comp-filter></C:filter>
</C:calendar-query>"#;
    let (ns, nb) = dav(&c, "REPORT", &format!("{}/", CAL), narrow, REPORT_HDRS);
    assert_eq!(ns, 207);
    assert!(
        !nb.contains("good-evt.ics"),
        "a range that excludes the event must actually exclude it: {nb}"
    );

    assert_caldav_alive(&c);
}

/// The worse variant: a stored `DTSTART` is re-parsed on *every* calendar-query,
/// so one bad value made the whole calendar un-syncable for every client.
///
/// Storage stays permissive on purpose — `DTSTART` is kept verbatim so an
/// unrecognised client value round-trips unchanged, and the extractor only
/// understands a handful of forms (a `DTSTART;TZID=...` value it cannot parse
/// is perfectly legal iCalendar). The fix is in the parser, not the gate.
#[test]
fn e2e_caldav_malformed_stored_dtstart_does_not_poison_the_calendar() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);

    let poison = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//tilde//test//EN\r\nBEGIN:VEVENT\r\n\
         UID:poison-evt\r\nSUMMARY:poison\r\nDTSTART:aa€€\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"
    );
    let poison_url = format!("{}/poison-evt.ics", CAL);
    assert_eq!(
        dav(&c, "PUT", &poison_url, &poison, ICS).0,
        201,
        "a client's unrecognised DTSTART is stored, not rejected"
    );
    let (gs, gb) = c.get(&poison_url);
    assert_eq!(gs, 200);
    assert!(
        gb.contains("DTSTART:aa€€"),
        "the stored value must round-trip verbatim: {gb}"
    );

    let good_url = format!("{}/sane-evt.ics", CAL);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &good_url,
            &event_ics("sane-evt", "20260601T100000Z", "20260601T110000Z"),
            ICS
        )
        .0,
        201
    );

    // An ordinary client sync over a calendar containing the bad row.
    let query = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:calendar-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop><D:getetag/></D:prop>
  <C:filter><C:comp-filter name="VCALENDAR"><C:comp-filter name="VEVENT">
    <C:time-range start="20260501T000000Z" end="20260701T000000Z"/>
  </C:comp-filter></C:comp-filter></C:filter>
</C:calendar-query>"#;
    let (status, body) = dav(&c, "REPORT", &format!("{}/", CAL), query, REPORT_HDRS);
    assert_eq!(status, 207, "one bad row must not break time-range queries");
    assert!(
        body.contains("sane-evt.ics"),
        "the well-formed event must still be returned: {body}"
    );
    assert!(
        !body.contains("poison-evt.ics"),
        "an unparseable DTSTART cannot satisfy a time-range: {body}"
    );

    assert_caldav_alive(&c);
}

// ── Non-ASCII in CardDAV filter parsing ────────────────────────────────────

/// `extract_filter_test` mixed offsets: it searched a lowercased copy of the
/// body and then indexed the original with the result. `to_lowercase()` is not
/// length-preserving, so enough non-ASCII made the offset run past the end of
/// the original string.
#[test]
fn e2e_carddav_non_ascii_filter_is_answered_not_fatal() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &format!("{}/ada.vcf", AB),
            &vcard("ada", "Ada Lovelace", ""),
            VCF
        )
        .0,
        201
    );

    // Each 'İ' is 2 bytes but lowercases to 3, so the trailing "filter" sits
    // past the end of the original body once the offsets drift.
    let drift = "İ".repeat(12);
    let hostile = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/></D:prop>
  <C:filter test="allof">
    <C:prop-filter name="{drift}">
      <C:text-match match-type="İcontains">boom</C:text-match>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>"#
    );
    let (status, _) = dav(&c, "REPORT", &format!("{}/", AB), &hostile, REPORT_HDRS);
    assert_eq!(
        status, 207,
        "a non-ASCII filter must be answered, not crash"
    );

    // And ordinary filtering still works, so the parser is not just bailing out.
    let sane = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/></D:prop>
  <C:filter test="anyof">
    <C:prop-filter name="FN">
      <C:text-match match-type="contains">Lovelace</C:text-match>
    </C:prop-filter>
  </C:filter>
</C:addressbook-query>"#;
    let (ss, sb) = dav(&c, "REPORT", &format!("{}/", AB), sane, REPORT_HDRS);
    assert_eq!(ss, 207);
    assert!(
        sb.contains("ada.vcf"),
        "a matching filter must return the contact: {sb}"
    );

    let miss = sane.replace("Lovelace", "Hopper");
    let (ms, mb) = dav(&c, "REPORT", &format!("{}/", AB), &miss, REPORT_HDRS);
    assert_eq!(ms, 207);
    assert!(
        !mb.contains("ada.vcf"),
        "a non-matching filter must exclude it: {mb}"
    );

    assert_carddav_alive(&c);
}

/// `extract_vcard_property` indexed the original line by the byte length of an
/// *uppercased* prefix. 'ﬁ' is 3 bytes and uppercases to the 2-byte "FI", so a
/// prop-filter named "ﬁ" against a line starting with 'ﬁ' sliced mid-character.
#[test]
fn e2e_carddav_non_ascii_property_name_is_answered_not_fatal() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &format!("{}/lig.vcf", AB),
            &vcard("lig", "Ada Lovelace", "ﬁx:boom\r\n"),
            VCF
        )
        .0,
        201,
        "a vCard with an odd property line is still stored"
    );

    let hostile = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/></D:prop>
  <C:filter test="anyof"><C:prop-filter name="ﬁ"/></C:filter>
</C:addressbook-query>"#;
    let (status, _) = dav(&c, "REPORT", &format!("{}/", AB), hostile, REPORT_HDRS);
    assert_eq!(
        status, 207,
        "a non-ASCII prop-filter name must be answered, not crash"
    );

    // Presence filtering still discriminates.
    let present = r#"<?xml version="1.0" encoding="UTF-8"?>
<C:addressbook-query xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/></D:prop>
  <C:filter test="anyof"><C:prop-filter name="FN"/></C:filter>
</C:addressbook-query>"#;
    let (ps, pb) = dav(&c, "REPORT", &format!("{}/", AB), present, REPORT_HDRS);
    assert_eq!(ps, 207);
    assert!(
        pb.contains("lig.vcf"),
        "FN is present, so the contact must match: {pb}"
    );

    let absent = present.replace(r#"name="FN""#, r#"name="NICKNAME""#);
    let (as_, ab_) = dav(&c, "REPORT", &format!("{}/", AB), &absent, REPORT_HDRS);
    assert_eq!(as_, 207);
    assert!(
        !ab_.contains("lig.vcf"),
        "NICKNAME is absent, so it must not match: {ab_}"
    );

    assert_carddav_alive(&c);
}

// ── XML injection through hrefs ────────────────────────────────────────────

/// `<d:href>` interpolated the UID unescaped while `calendar-data` beside it was
/// escaped. A UID carrying XML broke every response that listed it.
#[test]
fn e2e_caldav_uid_with_xml_is_escaped_in_hrefs() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);

    // "ev<il&\"" — percent-encoded so it survives the request line.
    let hostile_url = format!("{}/ev%3Cil%26%22.ics", CAL);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &hostile_url,
            &event_ics("evil", "20260601T100000Z", "20260601T110000Z"),
            ICS
        )
        .0,
        201,
        "the odd UID is accepted"
    );
    let plain_url = format!("{}/plain.ics", CAL);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &plain_url,
            &event_ics("plain", "20260601T100000Z", "20260601T110000Z"),
            ICS
        )
        .0,
        201
    );

    let (status, body) = dav(&c, "PROPFIND", &format!("{}/", CAL), "", REPORT_HDRS);
    assert_eq!(status, 207);
    assert!(
        body.contains("ev&lt;il&amp;&quot;.ics"),
        "the UID must appear escaped inside the href: {body}"
    );
    assert!(
        !body.contains("ev<il"),
        "a raw '<' from a UID would break the document: {body}"
    );
    assert!(
        body.contains("plain.ics"),
        "the rest of the multistatus must survive the odd UID: {body}"
    );

    assert_caldav_alive(&c);
}

#[test]
fn e2e_carddav_uid_with_xml_is_escaped_in_hrefs() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);

    let hostile_url = format!("{}/ev%3Cil%26%22.vcf", AB);
    assert_eq!(
        dav(
            &c,
            "PUT",
            &hostile_url,
            &vcard("evil", "Ada Lovelace", ""),
            VCF
        )
        .0,
        201
    );
    assert_eq!(
        dav(
            &c,
            "PUT",
            &format!("{}/plain.vcf", AB),
            &vcard("plain", "Grace Hopper", ""),
            VCF
        )
        .0,
        201
    );

    let (status, body) = dav(&c, "PROPFIND", &format!("{}/", AB), "", REPORT_HDRS);
    assert_eq!(status, 207);
    assert!(
        body.contains("ev&lt;il&amp;&quot;.vcf"),
        "the UID must appear escaped inside the href: {body}"
    );
    assert!(
        !body.contains("ev<il"),
        "a raw '<' from a UID would break the document: {body}"
    );
    assert!(
        body.contains("plain.vcf"),
        "the rest of the multistatus must survive: {body}"
    );

    assert_carddav_alive(&c);
}

// ── WebDAV-Push callback SSRF ──────────────────────────────────────────────

/// A `/dav/`-scoped credential could register any URL as a push callback and the
/// server would then POST to it — blind request forgery against loopback
/// services. Only http(s) to a routable host is accepted now.
#[test]
fn e2e_caldav_push_callback_rejects_internal_targets() {
    let (server, pws) = start_server(&["admin"]);
    let c = admin(&server, &pws);
    let collection = format!("{}/", CAL);

    for hostile in [
        "http://127.0.0.1:9000/hook",
        "http://localhost:9000/hook",
        "http://[::1]:9000/hook",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.0.0.5/hook",
        "http://192.168.1.1/hook",
        "file:///etc/passwd",
        "gopher://127.0.0.1:11211/_stats",
        "not a url at all",
    ] {
        let body = serde_json::json!({ "callback_url": hostile }).to_string();
        let (status, _) = dav(&c, "POST", &collection, &body, &[]);
        assert_eq!(
            status, 400,
            "push subscribe must refuse the callback {hostile}"
        );
    }

    // Non-vacuity: the allowlist is a filter, not a blanket refusal. (Nothing
    // is delivered here — no change is made after subscribing — so this stays
    // offline.)
    let ok = serde_json::json!({
        "callback_url": "https://push.example.com/hook",
        "expiry_hours": 1,
    })
    .to_string();
    let (status, body) = dav(&c, "POST", &collection, &ok, &[]);
    assert_eq!(
        status, 201,
        "an ordinary https callback must still be accepted: {body}"
    );
    assert!(
        body.contains("subscription_id"),
        "the subscription must actually be created: {body}"
    );

    assert_caldav_alive(&c);
}
