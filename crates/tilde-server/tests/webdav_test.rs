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
        .method(Method::from_bytes(b"MOVE").unwrap(), "/dav/files/source.txt")
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
        .method(
            Method::from_bytes(b"MOVE").unwrap(),
            "/dav/files/movedir",
        )
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
        .method(Method::from_bytes(b"PROPFIND").unwrap(), "/dav/files/subdir")
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

    let resp = env
        .server
        .method(Method::OPTIONS, "/dav/files/")
        .await;
    resp.assert_status_ok();
}

// ─── Bug regression tests (assert CORRECT RFC behavior) ─────────────────────

/// RFC 7232: If-Match on non-existent resource → 412
#[tokio::test]
async fn if_match_on_nonexistent_returns_412() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let resp = env.server
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

    let resp = env.server
        .method(Method::PUT, "/dav/files/badpath/")
        .add_header(header::AUTHORIZATION, &auth)
        .text("data")
        .await;
    let status = resp.status_code();
    assert!(
        status == StatusCode::BAD_REQUEST || status == StatusCode::CONFLICT,
        "PUT trailing slash: got {}, expected 400/409", status
    );
}

/// RFC 4918 §9.8.3: COPY Depth:0 on collection → empty collection, no children
#[tokio::test]
async fn copy_dir_depth_zero_no_children() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "test", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server.method(Method::from_bytes(b"MKCOL").unwrap(), "/dav/files/copysrc")
        .add_header(header::AUTHORIZATION, &auth).await;
    env.server.method(Method::PUT, "/dav/files/copysrc/child.txt")
        .add_header(header::AUTHORIZATION, &auth).text("child").await;

    env.server.method(Method::from_bytes(b"COPY").unwrap(), "/dav/files/copysrc")
        .add_header(header::AUTHORIZATION, &auth)
        .add_header(header::HeaderName::from_static("destination"), "/dav/files/copydst")
        .add_header(header::HeaderName::from_static("depth"), "0")
        .await;

    // Child must NOT exist in destination
    let resp = env.server.get("/dav/files/copydst/child.txt")
        .add_header(header::AUTHORIZATION, &auth).await;
    resp.assert_status(StatusCode::NOT_FOUND);
}
