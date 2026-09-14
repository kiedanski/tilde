//! Notes sync coherence between MCP writes and WebDAV reads.
//!
//! This is the reported bug: an agent appends to a note over MCP, the change is
//! invisible to the sync client because the ETag never moves, and the next edit
//! from the phone overwrites it.
//!
//! Lives on the `common::create_test_server()` harness rather than `e2e_test.rs`
//! because that file spawns the real binary as a subprocess and has no way to
//! drive MCP. `create_test_server()` wires `mcp_state` and the DAV routers into
//! the same router.

mod common;

use axum::http::{Method, StatusCode, header};

/// PROPFIND a path and return its getetag value.
async fn propfind_etag(env: &common::TestEnv, auth: &str, path: &str) -> String {
    let resp = env
        .server
        .method(Method::from_bytes(b"PROPFIND").unwrap(), path)
        .add_header(header::AUTHORIZATION, auth)
        .add_header("depth", "0")
        .await;
    resp.assert_status(StatusCode::MULTI_STATUS);

    let xml = resp.text();
    let marker = "<d:getetag>";
    let start = xml
        .find(marker)
        .unwrap_or_else(|| panic!("No getetag in response:\n{}", xml))
        + marker.len();
    let end = xml[start..]
        .find("</d:getetag>")
        .expect("No closing getetag");
    xml[start..start + end].trim().trim_matches('"').to_string()
}

/// T6 — The reported bug, end to end.
///
/// The note is created through DAV first, so it *does* have a `files` row. That
/// is the realistic case and the one that loses data: the row exists and is
/// stale, so nothing falls back to recomputation.
#[tokio::test]
async fn mcp_notes_append_is_visible_over_dav() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);
    let token = common::create_mcp_token(&env.pool, "agent", "*");

    let resp = env
        .server
        .method(Method::PUT, "/dav/notes/journal.md")
        .add_header(header::AUTHORIZATION, &auth)
        .text("# Journal\n")
        .await;
    resp.assert_status(StatusCode::CREATED);

    let etag_before = propfind_etag(&env, &auth, "/dav/notes/journal.md").await;

    // Agent appends. `notes.append` requires the file to already exist
    // (tilde-mcp/src/lib.rs:642) and writes to data_dir/notes, which is what
    // /dav/notes serves (tilde-server/src/lib.rs:51-66).
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "notes.append",
            "arguments": {
                "path": "journal.md",
                "content": "written by agent"
            }
        }
    });

    let resp = env
        .server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .content_type("application/json")
        .bytes(serde_json::to_vec(&body).unwrap().into())
        .await;
    resp.assert_status_ok();

    // Sanity: the append actually reached disk. If this fails the test is
    // broken, not the server.
    let on_disk = std::fs::read_to_string(env.notes_dir().join("journal.md")).unwrap();
    assert!(
        on_disk.contains("written by agent"),
        "notes.append did not write to disk; test setup is wrong.\nGot: {:?}",
        on_disk,
    );

    // The actual assertion: a sync client must be able to see the change.
    let etag_after = propfind_etag(&env, &auth, "/dav/notes/journal.md").await;

    assert_ne!(
        etag_before, etag_after,
        "PROPFIND ETag must change after notes.append, otherwise Obsidian never \
         pulls the agent's write and clobbers it on the next phone edit.\n\
         Before: {}\nAfter: {}",
        etag_before, etag_after,
    );

    let served = env
        .server
        .get("/dav/notes/journal.md")
        .add_header(header::AUTHORIZATION, &auth)
        .await
        .text();
    assert!(
        served.contains("written by agent"),
        "GET over DAV must return the appended content.\nGot: {:?}",
        served,
    );
}
