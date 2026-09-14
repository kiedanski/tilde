//! CardDAV integration tests.
//!
//! Tests addressbook CRUD, contact CRUD, REPORT (multiget, addressbook-query),
//! text-match filtering, and sync-collection.

mod common;

use axum::http::{Method, StatusCode, header};

fn sample_vcard(fn_name: &str, email: &str) -> String {
    format!("BEGIN:VCARD\r\nVERSION:3.0\r\nFN:{fn_name}\r\nEMAIL:{email}\r\nEND:VCARD\r\n")
}

// ─── Basic operations ─────────────────────────────────────────────────────────

#[tokio::test]
async fn propfind_admin_principal() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/carddav/admin/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn propfind_depth_1_lists_addressbooks() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/carddav/admin/")
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("default"));
    assert!(body.contains("Contacts"));
}

#[tokio::test]
async fn mkcol_addressbook() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(
            Method::from_bytes(b"MKCOL").unwrap(),
            "/carddav/admin/work/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::CREATED);
}

// ─── Contact CRUD ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn put_get_delete_contact() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Alice Test", "alice@example.com");

    // PUT
    let resp = env
        .server
        .method(Method::PUT, "/carddav/admin/default/alice.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // GET
    let resp = env
        .server
        .get("/carddav/admin/default/alice.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert!(resp.text().contains("Alice Test"));

    // DELETE
    let resp = env
        .server
        .delete("/carddav/admin/default/alice.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // GET after delete -> 404
    let resp = env
        .server
        .get("/carddav/admin/default/alice.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── REPORT ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn report_addressbook_multiget() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Bob Multiget", "bob@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/bob.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-multiget xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
  <d:href>/carddav/admin/default/bob.vcf</d:href>
</card:addressbook-multiget>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/carddav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("Bob Multiget"));
}

#[tokio::test]
async fn report_addressbook_query_text_match() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard1 = sample_vcard("Charlie Alpha", "charlie@example.com");
    let vcard2 = sample_vcard("Delta Beta", "delta@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/charlie.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard1.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    env.server
        .method(Method::PUT, "/carddav/admin/default/delta.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard2.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
  <card:filter>
    <card:prop-filter name="FN">
      <card:text-match collation="i;unicode-casemap" match-type="contains">charlie</card:text-match>
    </card:prop-filter>
  </card:filter>
</card:addressbook-query>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/carddav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("Charlie Alpha"));
    assert!(!body.contains("Delta Beta"));
}

#[tokio::test]
async fn report_sync_collection() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Sync Contact", "sync@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/sync-c1.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    let report_body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:sync-collection xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:sync-token/>
  <d:prop>
    <d:getetag/>
    <card:address-data/>
  </d:prop>
</d:sync-collection>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"REPORT").unwrap(),
            "/carddav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(report_body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body = resp.text();
    assert!(body.contains("Sync Contact"));
    assert!(body.contains("sync-token"));
}

// ─── Preconditions ────────────────────────────────────────────────────────────

#[tokio::test]
async fn if_none_match_star_on_existing_returns_412() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Eve Existing", "eve@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/eve.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    // Second PUT with If-None-Match: *
    let resp = env
        .server
        .method(Method::PUT, "/carddav/admin/default/eve.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::IF_NONE_MATCH, "*")
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::PRECONDITION_FAILED);
}

#[tokio::test]
async fn wrong_content_type_returns_415() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/carddav/admin/default/bad.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .content_type("text/plain")
        .text("not vcard")
        .await;
    resp.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// ─── Principal validation ─────────────────────────────────────────────────────

#[tokio::test]
async fn wrong_principal_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/carddav/bob/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── Addressbook management ──────────────────────────────────────────────────

#[tokio::test]
async fn delete_addressbook() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(
            Method::from_bytes(b"MKCOL").unwrap(),
            "/carddav/admin/deleteme/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    let resp = env
        .server
        .delete("/carddav/admin/deleteme/")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn proppatch_addressbook() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:">
  <d:set>
    <d:prop>
      <d:displayname>Renamed Book</d:displayname>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPPATCH").unwrap(),
            "/carddav/admin/default/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn options_addressbook() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::OPTIONS, "/carddav/admin/default/")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
}

// ─── PROPFIND on contacts ─────────────────────────────────────────────────────

#[tokio::test]
async fn propfind_single_contact() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Propfind Contact", "pf@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/pf-contact.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/carddav/admin/default/pf-contact.vcf",
        )
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("pf-contact"));
}

#[tokio::test]
async fn propfind_addressbook_depth1_lists_contacts() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "card-rw", "/carddav/*");
    let auth = common::basic_auth_header(&pw);

    let vcard = sample_vcard("Depth1 Contact", "d1@example.com");

    env.server
        .method(Method::PUT, "/carddav/admin/default/depth1.vcf")
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(vcard.clone()))
        .content_type("text/vcard; charset=utf-8")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/carddav/admin/default/",
        )
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("depth1.vcf"));
}
