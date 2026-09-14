//! WebDAV integration tests.
//!
//! Tests PUT, GET, DELETE, MKCOL, MOVE, COPY, PROPFIND, PROPPATCH,
//! ETag handling, path traversal protection, and depth:infinity rejection.

mod common;

use axum::http::{Method, StatusCode, header};

// ─── Basic CRUD ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn put_get_cycle() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // PUT file
    let resp = env
        .server
        .method(Method::PUT, "/dav/files/hello.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("Hello, World!")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // GET file
    let resp = env
        .server
        .get("/dav/files/hello.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "Hello, World!");
}

#[tokio::test]
async fn put_overwrite_returns_204() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // First PUT (create)
    let resp = env
        .server
        .method(Method::PUT, "/dav/files/overwrite.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // Second PUT (overwrite)
    let resp = env
        .server
        .method(Method::PUT, "/dav/files/overwrite.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 2")
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // Verify overwrite
    let resp = env
        .server
        .get("/dav/files/overwrite.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    assert_eq!(resp.text(), "version 2");
}

#[tokio::test]
async fn delete_file() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // PUT
    env.server
        .method(Method::PUT, "/dav/files/deleteme.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("to be deleted")
        .await;

    // DELETE
    let resp = env
        .server
        .delete("/dav/files/deleteme.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);

    // GET should 404
    let resp = env
        .server
        .get("/dav/files/deleteme.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn mkcol_creates_directory() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/testdir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::CREATED);

    // PROPFIND Depth:1 on root should show the directory
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("testdir"));
}

#[tokio::test]
async fn mkcol_duplicate_returns_405() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/dupdir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    let resp = env
        .server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/dupdir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::METHOD_NOT_ALLOWED);
}

// ─── MOVE ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn move_file() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/source.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("move me")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"MOVE").unwrap(),
            "/dav/files/source.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/dest.txt")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // Old path 404
    let resp = env
        .server
        .get("/dav/files/source.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);

    // New path exists
    let resp = env
        .server
        .get("/dav/files/dest.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "move me");
}

#[tokio::test]
async fn move_nonexistent_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(
            Method::from_bytes(b"MOVE").unwrap(),
            "/dav/files/does_not_exist.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/new.txt")
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn move_no_destination_header_returns_400() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/move_src.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("content")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"MOVE").unwrap(),
            "/dav/files/move_src.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn move_directory() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/movedir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    env.server
        .method(Method::PUT, "/dav/files/movedir/child.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("child")
        .await;

    let resp = env
        .server
        .method(Method::from_bytes(b"MOVE").unwrap(), "/dav/files/movedir")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/moveddir")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let resp = env
        .server
        .get("/dav/files/moveddir/child.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "child");
}

// ─── COPY ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn copy_file() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/original.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("copy me")
        .await;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"COPY").unwrap(),
            "/dav/files/original.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/copied.txt")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // Both paths exist
    let resp = env
        .server
        .get("/dav/files/original.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();

    let resp = env
        .server
        .get("/dav/files/copied.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "copy me");
}

#[tokio::test]
async fn copy_nonexistent_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(
            Method::from_bytes(b"COPY").unwrap(),
            "/dav/files/does_not_exist.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/new.txt")
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── PROPFIND ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn propfind_depth_0() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "0")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

#[tokio::test]
async fn propfind_depth_1_lists_files() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/listed.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("content")
        .await;

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("listed.txt"));
}

// ─── ETag handling ────────────────────────────────────────────────────────────

#[tokio::test]
async fn etag_returned_on_put() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/etag_test.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("etag content")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let etag = resp.header("etag");
    assert!(
        !etag.to_str().unwrap().is_empty(),
        "Expected ETag header on PUT response"
    );
}

#[tokio::test]
async fn if_match_wrong_etag_returns_412() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Put a file
    env.server
        .method(Method::PUT, "/dav/files/ifmatch.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("v1")
        .await;

    // PUT with wrong If-Match
    let resp = env
        .server
        .method(Method::PUT, "/dav/files/ifmatch.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("if-match", "\"wrongetag\"")
        .text("v2")
        .await;
    resp.assert_status(StatusCode::PRECONDITION_FAILED);
}

// ─── Security ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn path_traversal_rejected() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Use URL-encoded ".." to prevent HTTP client from normalizing the path
    let resp = env
        .server
        .get("/dav/files/%2e%2e/%2e%2e/%2e%2e/etc/passwd")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    // Server should reject traversal attempts with 400 or 404
    let status = resp.status_code();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::NOT_FOUND,
        "Expected 400 or 404 for path traversal, got {status}"
    );
}

#[tokio::test]
async fn depth_infinity_forbidden() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/")
        .add_header("depth", "infinity")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
}

// ─── Edge cases ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_nonexistent_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .get("/dav/files/no_such_file.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_nonexistent_returns_404() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .delete("/dav/files/does_not_exist.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn put_conflict_parent_not_exist() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/nonexistent_dir/file.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("content")
        .await;
    resp.assert_status(StatusCode::CONFLICT);
}

#[tokio::test]
async fn head_returns_content_length() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/headtest.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("head content")
        .await;

    let resp = env
        .server
        .method(Method::HEAD, "/dav/files/headtest.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
}

#[tokio::test]
async fn lock_method_not_allowed() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::from_bytes(b"LOCK").unwrap(), "/dav/files/any.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn put_in_subdir() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/subdir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/subdir/nested.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("nested content")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/subdir",
        )
        .add_header("depth", "1")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    assert!(resp.text().contains("nested.txt"));
}

#[tokio::test]
async fn delete_directory_with_children() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/del_dir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    env.server
        .method(Method::PUT, "/dav/files/del_dir/inner.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("inner")
        .await;

    let resp = env
        .server
        .delete("/dav/files/del_dir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn proppatch() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/proppatch.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("content")
        .await;

    let body = r#"<?xml version="1.0" encoding="UTF-8"?>
<d:propertyupdate xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
  <d:set>
    <d:prop>
      <oc:favorite>1</oc:favorite>
    </d:prop>
  </d:set>
</d:propertyupdate>"#;

    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPPATCH").unwrap(),
            "/dav/files/proppatch.txt",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .bytes(axum::body::Bytes::from(body))
        .content_type("application/xml; charset=utf-8")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
}

// ─── Chunked uploads ──────────────────────────────────────────────────────────

#[tokio::test]
async fn chunked_upload_full_flow() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // 1. MKCOL to create upload session
    let resp = env
        .server
        .method(
            Method::from_bytes(b"MKCOL").unwrap(),
            "/dav/uploads/admin/session-001/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("OC-Total-Length", "26")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // 2. PUT chunk 1
    let resp = env
        .server
        .method(Method::PUT, "/dav/uploads/admin/session-001/0000000000")
        .add_header(header::AUTHORIZATION, &auth)
        .text("Hello, ")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // 3. PUT chunk 2
    let resp = env
        .server
        .method(Method::PUT, "/dav/uploads/admin/session-001/0000000001")
        .add_header(header::AUTHORIZATION, &auth)
        .text("chunked world!")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // 4. MOVE to finalize
    let resp = env
        .server
        .method(
            Method::from_bytes(b"MOVE").unwrap(),
            "/dav/uploads/admin/session-001/",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("destination", "/dav/files/chunked_result.txt")
        .await;
    resp.assert_status(StatusCode::CREATED);

    // 5. GET the assembled file
    let resp = env
        .server
        .get("/dav/files/chunked_result.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();
    assert_eq!(resp.text(), "Hello, chunked world!");
}

// ─── OPTIONS ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn options_returns_200() {
    let env = common::create_test_server();

    let resp = env.server.method(Method::OPTIONS, "/dav/files/").await;
    resp.assert_status_ok();
}

// ─── Bug regression tests (assert CORRECT RFC behavior) ─────────────────────

/// RFC 7232: If-Match on non-existent resource → 412
#[tokio::test]
async fn if_match_on_nonexistent_returns_412() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/ghost.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::IF_MATCH, "\"nonexistent-etag\"")
        .text("should not be created")
        .await;
    resp.assert_status(StatusCode::PRECONDITION_FAILED);
}

/// PUT to trailing slash → 409 Conflict, not 500
#[tokio::test]
async fn put_trailing_slash_not_500() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/badpath/")
        .add_header(header::AUTHORIZATION, &auth)
        .text("data")
        .await;
    let status = resp.status_code();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT,
        "PUT trailing slash: got {}, expected 400/409",
        status
    );
}

/// RFC 4918 §9.8.3: COPY Depth:0 on collection → empty collection, no children
#[tokio::test]
async fn copy_dir_depth_zero_no_children() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/copysrc")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    env.server
        .method(Method::PUT, "/dav/files/copysrc/child.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("child")
        .await;

    env.server
        .method(Method::from_bytes(b"COPY").unwrap(), "/dav/files/copysrc")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(
            header::HeaderName::from_static("destination"),
            "/dav/files/copydst",
        )
        .add_header(header::HeaderName::from_static("depth"), "0")
        .await;

    // Child must NOT exist in destination
    let resp = env
        .server
        .get("/dav/files/copydst/child.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status(StatusCode::NOT_FOUND);
}

// ─── Directory ETag changes when contents change ──────────────────────────────

/// Directory ETags must change when a file is added, so sync clients
/// (e.g. webgallery) can detect new photos via PROPFIND.
#[tokio::test]
async fn directory_etag_changes_on_file_add() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Create a directory
    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/etag-dir")
        .add_header(header::AUTHORIZATION, &auth)
        .await
        .assert_status(StatusCode::CREATED);

    // PROPFIND the directory to get its initial ETag
    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/etag-dir",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body1 = resp.text();
    let etag1 = extract_etag_from_propfind(&body1);

    // Add a file to the directory
    env.server
        .method(Method::PUT, "/dav/files/etag-dir/photo.jpg")
        .add_header(header::AUTHORIZATION, &auth)
        .text("fake photo data")
        .await
        .assert_status(StatusCode::CREATED);

    // PROPFIND again — ETag must have changed
    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/etag-dir",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    let body2 = resp.text();
    let etag2 = extract_etag_from_propfind(&body2);

    assert_ne!(
        etag1, etag2,
        "Directory ETag must change after adding a file.\nBefore: {}\nAfter: {}",
        etag1, etag2,
    );

    // Delete the file
    env.server
        .method(Method::DELETE, "/dav/files/etag-dir/photo.jpg")
        .add_header(header::AUTHORIZATION, &auth)
        .await
        .assert_status(StatusCode::NO_CONTENT);

    // PROPFIND again — ETag must have changed again
    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/etag-dir",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("depth", "0")
        .await;
    let body3 = resp.text();
    let etag3 = extract_etag_from_propfind(&body3);

    assert_ne!(
        etag2, etag3,
        "Directory ETag must change after deleting a file.\nBefore: {}\nAfter: {}",
        etag2, etag3,
    );
}

/// Directory ETag must change when a child file's content is modified in place.
#[tokio::test]
async fn directory_etag_changes_on_file_modify() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Create dir + file
    env.server
        .method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/mod-dir")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    env.server
        .method(Method::PUT, "/dav/files/mod-dir/data.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await;

    // Get directory ETag
    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/mod-dir",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("depth", "0")
        .await;
    let etag1 = extract_etag_from_propfind(&resp.text());

    // Overwrite the file with different content
    env.server
        .method(Method::PUT, "/dav/files/mod-dir/data.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 2")
        .await;

    // Directory ETag must have changed
    let resp = env
        .server
        .method(
            Method::from_bytes(b"PROPFIND").unwrap(),
            "/dav/files/mod-dir",
        )
        .add_header(header::AUTHORIZATION, &auth)
        .add_header("depth", "0")
        .await;
    let etag2 = extract_etag_from_propfind(&resp.text());

    assert_ne!(
        etag1, etag2,
        "Directory ETag must change when a child file is modified.\nBefore: {}\nAfter: {}",
        etag1, etag2,
    );
}

/// Extract the first getetag value from a PROPFIND multistatus XML response.
fn extract_etag_from_propfind(xml: &str) -> String {
    // Look for <d:getetag>"value"</d:getetag>
    let marker = "<d:getetag>";
    let start = xml.find(marker).expect("No getetag in response") + marker.len();
    let end = xml[start..]
        .find("</d:getetag>")
        .expect("No closing getetag");
    xml[start..start + end].trim().trim_matches('"').to_string()
}

// ─── ETag correctness against out-of-band writes ──────────────────────────────
//
// Every other test in this file creates files through DAV PUT — the one write
// path that maintains the `files` table. These tests write directly to disk
// instead, which is what `notes.append` (tilde-mcp/src/lib.rs:626), the CLI,
// rsync, and a restic restore all do.
//
// See plan.md §1 for the defect table these correspond to.

/// PROPFIND a path and return the raw multistatus body.
async fn propfind_body(env: &common::TestEnv, auth: &str, path: &str) -> String {
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), path)
        .add_header(header::AUTHORIZATION, auth)
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);
    resp.text()
}

/// PROPFIND a path and return its getetag value.
async fn propfind_etag(env: &common::TestEnv, auth: &str, path: &str) -> String {
    extract_etag_from_propfind(&propfind_body(env, auth, path).await)
}

/// Extract the first value of an arbitrary property from a multistatus response.
/// Generalizes `extract_etag_from_propfind`, which is hardcoded to `d:getetag`.
fn extract_prop(xml: &str, tag: &str) -> String {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml
        .find(&open)
        .unwrap_or_else(|| panic!("No {} in response:\n{}", tag, xml))
        + open.len();
    let end = xml[start..]
        .find(&close)
        .unwrap_or_else(|| panic!("No closing {}", tag));
    xml[start..start + end].trim().trim_matches('"').to_string()
}

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// T1 — An ETag must reflect what is on disk, not what the last DAV write recorded.
#[tokio::test]
async fn propfind_etag_changes_after_out_of_band_write() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/oob.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let etag1 = propfind_etag(&env, &auth, "/dav/files/oob.txt").await;

    // Bypass DAV entirely.
    std::fs::write(env.files_dir().join("oob.txt"), "version 2 is longer").unwrap();

    let etag2 = propfind_etag(&env, &auth, "/dav/files/oob.txt").await;

    assert_ne!(
        etag1, etag2,
        "ETag must change after an out-of-band write.\nBefore: {}\nAfter: {}",
        etag1, etag2,
    );
}

/// T2 — `oc:id` must be stable. A fresh UUID per PROPFIND makes every poll look
/// like a different file to Nextcloud-protocol clients, breaking rename detection.
#[tokio::test]
async fn propfind_oc_id_is_stable_for_unindexed_file() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Created on disk only — never through DAV, so no `files` row exists.
    std::fs::write(env.files_dir().join("ghost.txt"), "hello").unwrap();

    let xml1 = propfind_body(&env, &auth, "/dav/files/ghost.txt").await;
    let xml2 = propfind_body(&env, &auth, "/dav/files/ghost.txt").await;

    let id1 = extract_prop(&xml1, "oc:id");
    let id2 = extract_prop(&xml2, "oc:id");

    assert_eq!(
        id1, id2,
        "oc:id must be stable across requests.\nFirst: {}\nSecond: {}",
        id1, id2,
    );
}

/// T3 — ETag must reflect content, not length.
///
/// Deliberately does NOT sleep between writes. The temptation when implementing
/// the stat cache will be to add a `sleep(1s)` to make this pass; that would hide
/// the mtime-granularity race described in plan.md §2.1, which is real in
/// production (a fast agent write followed by a client poll).
#[tokio::test]
async fn propfind_etag_changes_on_same_length_edit() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let path = env.files_dir().join("same.txt");

    std::fs::write(&path, "aaaa").unwrap();
    let etag1 = propfind_etag(&env, &auth, "/dav/files/same.txt").await;

    std::fs::write(&path, "bbbb").unwrap();
    let etag2 = propfind_etag(&env, &auth, "/dav/files/same.txt").await;

    assert_ne!(
        etag1, etag2,
        "ETag must reflect content, not length.\nBefore: {}\nAfter: {}",
        etag1, etag2,
    );
}

/// T4 — The ETag served with a GET must belong to the bytes in that same response.
///
/// Note this is NOT "GET and PROPFIND agree" — they already agree today, because
/// both read the same stale DB value. The assertion has to be against content.
#[tokio::test]
async fn get_etag_matches_content_after_out_of_band_write() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env
        .server
        .method(Method::PUT, "/dav/files/coherent.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await;
    resp.assert_status(StatusCode::CREATED);

    std::fs::write(env.files_dir().join("coherent.txt"), "version 2").unwrap();

    let resp = env
        .server
        .get("/dav/files/coherent.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    resp.assert_status_ok();

    let served_etag = resp
        .header("etag")
        .to_str()
        .unwrap()
        .trim_matches('"')
        .to_string();
    let body = resp.text();
    let expected = sha256_hex(body.as_bytes())[..16].to_string();

    assert_eq!(
        served_etag, expected,
        "GET served content whose ETag belongs to a different version.\n\
         Body: {:?}\nServed ETag: {}\nETag of body: {}",
        body, served_etag, expected,
    );
}

/// T5 — Directory ETags must account for children that have no DB row.
///
/// Covers the silent fallthrough at tilde-dav/src/lib.rs:1908, where a child
/// missing from `child_etags` contributes nothing to the directory hash.
#[tokio::test]
async fn directory_etag_changes_when_unindexed_child_modified() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let dir = env.files_dir().join("ghostdir");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("a.txt"), "one").unwrap();

    let etag1 = propfind_etag(&env, &auth, "/dav/files/ghostdir").await;

    std::fs::write(dir.join("a.txt"), "two").unwrap();

    let etag2 = propfind_etag(&env, &auth, "/dav/files/ghostdir").await;

    assert_ne!(
        etag1, etag2,
        "Directory ETag must account for unindexed children.\nBefore: {}\nAfter: {}",
        etag1, etag2,
    );
}

// ─── Merge base tracking (plan.md §5, slice 1) ────────────────────────────────
//
// Three-way merge needs the base version the writing client was working from.
// A GET is the moment a client takes possession of a version, so that is where
// the base is recorded.

#[tokio::test]
async fn get_records_base_version_for_credential() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let auth = common::basic_auth_header(&pw);
    let cred = common::app_password_id(&env.pool, "phone");

    env.server
        .method(Method::PUT, "/dav/files/base.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await
        .assert_status(StatusCode::CREATED);

    // A PUT now records a base too: after a successful write the client
    // demonstrably holds what it sent, and treating it as stale on its next
    // write is what resurrected deleted lines (see
    // e2e_consecutive_puts_do_not_resurrect_deleted_content).
    assert_eq!(
        common::base_version(&env.pool, &cred, "base.txt"),
        Some(sha256_hex(b"version 1")),
        "a PUT must record the version it stored as this client's base"
    );

    env.server
        .get("/dav/files/base.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await
        .assert_status_ok();

    let recorded = common::base_version(&env.pool, &cred, "base.txt")
        .expect("GET must record the version served");
    assert_eq!(recorded, sha256_hex(b"version 1"));
}

#[tokio::test]
async fn base_version_is_tracked_per_credential() {
    let env = common::create_test_server();
    let phone_pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let _laptop_pw = common::create_app_password(&env.pool, "laptop", "/dav/*");
    let phone = common::app_password_id(&env.pool, "phone");
    let laptop = common::app_password_id(&env.pool, "laptop");

    env.server
        .method(Method::PUT, "/dav/files/shared.txt")
        .add_header(header::AUTHORIZATION, &common::basic_auth_header(&phone_pw))
        .text("v1")
        .await;

    // Only the phone reads it.
    env.server
        .get("/dav/files/shared.txt")
        .add_header(header::AUTHORIZATION, &common::basic_auth_header(&phone_pw))
        .await;

    assert_eq!(
        common::base_version(&env.pool, &phone, "shared.txt"),
        Some(sha256_hex(b"v1"))
    );
    assert_eq!(
        common::base_version(&env.pool, &laptop, "shared.txt"),
        None,
        "a credential that never read the file has no base version"
    );
}

#[tokio::test]
async fn base_version_advances_on_later_get() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let auth = common::basic_auth_header(&pw);
    let cred = common::app_password_id(&env.pool, "phone");

    env.server
        .method(Method::PUT, "/dav/files/moving.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("first")
        .await;
    env.server
        .get("/dav/files/moving.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;
    assert_eq!(
        common::base_version(&env.pool, &cred, "moving.txt"),
        Some(sha256_hex(b"first"))
    );

    // Written out of band, then re-read: the client now holds the newer version.
    std::fs::write(env.files_dir().join("moving.txt"), "second").unwrap();
    env.server
        .get("/dav/files/moving.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .await;

    assert_eq!(
        common::base_version(&env.pool, &cred, "moving.txt"),
        Some(sha256_hex(b"second")),
        "re-reading must advance the base, or merges use a stale ancestor"
    );
}

// ─── Archive on overwrite (plan.md §5, slice 2) ───────────────────────────────

fn blob_exists(env: &common::TestEnv, content: &[u8]) -> bool {
    let sha = sha256_hex(content);
    env.data_dir()
        .join("blobs/by-id")
        .join(&sha[..2])
        .join(&sha)
        .exists()
}

#[tokio::test]
async fn put_archives_the_version_it_overwrites() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/hist.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await
        .assert_status(StatusCode::CREATED);

    env.server
        .method(Method::PUT, "/dav/files/hist.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 2")
        .await
        .assert_status(StatusCode::NO_CONTENT);

    assert!(
        blob_exists(&env, b"version 1"),
        "the overwritten version must be archived — it is the merge base a \
         stale client will need"
    );
}

/// A PUT that displaces nothing has no *prior* version to preserve — but it does
/// archive the version it stores, so that version stays retrievable as the
/// client's merge base.
#[tokio::test]
async fn put_creating_a_new_file_archives_only_what_it_stored() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/fresh.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("brand new")
        .await
        .assert_status(StatusCode::CREATED);

    assert!(
        blob_exists(&env, b"brand new"),
        "the stored version must be archived so it can serve as a merge base"
    );
}

#[tokio::test]
async fn put_archives_content_written_out_of_band() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "phone", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/oob-hist.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("from dav")
        .await;

    // An agent writes directly to disk; that version must also be preserved
    // when a client later overwrites it, or the agent's work is unrecoverable.
    std::fs::write(env.files_dir().join("oob-hist.txt"), "from the agent").unwrap();

    env.server
        .method(Method::PUT, "/dav/files/oob-hist.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("from the phone")
        .await;

    assert!(
        blob_exists(&env, b"from the agent"),
        "an out-of-band version must be archived before being overwritten"
    );
}
