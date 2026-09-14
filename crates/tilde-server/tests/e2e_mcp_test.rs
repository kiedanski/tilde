//! MCP end-to-end against the real server binary.
//!
//! Before this file, exactly one of the 26 MCP tools had ever been invoked by a
//! test (`notes.append`, on the in-process harness). Agent access is a headline
//! feature, so it deserves coverage at the protocol boundary.

mod common;

use common::e2e::{Client, Mcp, create_mcp_token, start_server};
use serde_json::json;

fn seed(c: &Client) {
    c.put("/dav/notes/journal.md", "# Journal\n\nwidget notes here\n");
    c.put("/dav/files/report.txt", "quarterly widget report\n");
}

#[test]
fn e2e_mcp_handshake_and_tool_inventory() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let init = mcp.rpc("initialize", json!({}));
    assert_eq!(init["result"]["serverInfo"]["name"], "tilde");
    assert!(init["result"]["capabilities"]["tools"].is_object());

    let names = mcp.tool_names();
    assert_eq!(names.len(), 37, "tool inventory changed: {:?}", names);

    // No domain module may register a name twice.
    let mut sorted = names.clone();
    sorted.sort();
    let before = sorted.len();
    sorted.dedup();
    assert_eq!(before, sorted.len(), "duplicate tool names registered");
    for required in [
        "notes.search",
        "notes.read",
        "notes.append",
        "notes.create",
        "notes.write",
        "notes.delete",
        "files.list",
        "files.read",
        "files.search",
        "files.write",
        "files.delete",
        "files.mkdir",
        "files.move",
        "photos.search",
        "photos.recent",
        "photos.get",
        "photos.stats",
        "contacts.create",
        "contacts.update",
        "contacts.delete",
        "tasks.add",
        "tasks.update",
        "tasks.delete",
    ] {
        assert!(
            names.contains(&required.to_string()),
            "missing {}",
            required
        );
    }
}

/// `files.search` was wired to the **notes** directory, so it searched the wrong
/// tree entirely and could never find anything under `files/`.
#[test]
fn e2e_mcp_files_search_searches_the_files_tree() {
    let (server, pws) = start_server(&["phone"]);
    seed(&Client::new(&server, &pws[0]));
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let hits = mcp.call("files.search", json!({"query": "quarterly"}));
    let hits = hits.as_array().expect("array result");

    assert!(
        !hits.is_empty(),
        "files.search must find content under files/, got {:?}",
        hits
    );
    assert!(
        format!("{:?}", hits).contains("report.txt"),
        "expected report.txt in results: {:?}",
        hits
    );
}

/// The declared `path` parameter ("Restrict to subdirectory") was ignored.
#[test]
fn e2e_mcp_files_search_honours_the_path_filter() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    c.put("/dav/files/keep.txt", "findme here\n");
    // MKCOL then a file in a subdirectory
    c.http
        .request(
            reqwest::Method::from_bytes(b"MKCOL").unwrap(),
            format!("{}/dav/files/sub", server.base_url),
        )
        .basic_auth("admin", Some(&pws[0]))
        .send()
        .unwrap();
    c.put("/dav/files/sub/other.txt", "findme there\n");

    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));
    let scoped = mcp.call("files.search", json!({"query": "findme", "path": "sub"}));
    let scoped = format!("{:?}", scoped);

    assert!(
        scoped.contains("other.txt"),
        "should find the scoped file: {}",
        scoped
    );
    assert!(
        !scoped.contains("keep.txt"),
        "path filter must exclude files outside it: {}",
        scoped
    );
}

#[test]
fn e2e_mcp_notes_search_and_read_round_trip() {
    let (server, pws) = start_server(&["phone"]);
    seed(&Client::new(&server, &pws[0]));
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let hits = mcp.call("notes.search", json!({"query": "widget"}));
    assert!(
        !hits.as_array().unwrap().is_empty(),
        "notes.search found nothing"
    );

    let note = mcp.call("notes.read", json!({"path": "journal.md"}));
    assert!(
        note["content"]
            .as_str()
            .unwrap()
            .contains("widget notes here")
    );
}

#[test]
fn e2e_mcp_task_lifecycle() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let created = mcp.call("tasks.add", json!({"summary": "buy milk"}));
    let uid = created["uid"].as_str().unwrap().to_string();

    let listed = mcp.call("tasks.list", json!({}));
    assert!(format!("{:?}", listed).contains("buy milk"));

    mcp.call(
        "tasks.update",
        json!({"uid": uid, "summary": "buy oat milk"}),
    );
    mcp.call("tasks.complete", json!({"uid": uid}));
    mcp.call("tasks.delete", json!({"uid": uid}));

    let after = mcp.call("tasks.list", json!({}));
    assert!(
        !format!("{:?}", after).contains("oat milk"),
        "deleted task still listed: {:?}",
        after
    );
}

#[test]
fn e2e_mcp_contact_lifecycle() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    // Note the schema's parameter is `fn_name` (the vCard FN field), not `name`.
    mcp.call(
        "contacts.create",
        json!({"fn_name": "Ada Lovelace", "email": "ada@example.com"}),
    );

    let found = mcp.call("contacts.search", json!({"query": "Ada"}));
    let arr = found.as_array().unwrap();
    assert!(!arr.is_empty(), "contact not found after create");
    let uid = arr[0]["uid"].as_str().unwrap().to_string();

    mcp.call("contacts.update", json!({"uid": uid, "fn_name": "Ada L."}));
    mcp.call("contacts.delete", json!({"uid": uid}));

    let gone = mcp.call("contacts.search", json!({"query": "Ada"}));
    assert!(
        gone.as_array().unwrap().is_empty(),
        "contact survived delete"
    );
}

#[test]
fn e2e_mcp_tracker_round_trip() {
    let (server, _pws) = start_server(&["phone"]);

    // trackers.log writes into an existing collection rather than conjuring one,
    // so create it the way a user would.
    let config = server.data_dir.parent().unwrap().join("config.toml");
    common::e2e::run_cli(
        &[
            "collection",
            "create",
            "weight",
            "--schema",
            r#"{"kg":"number"}"#,
        ],
        config.to_str().unwrap(),
        server.data_dir.to_str().unwrap(),
    );

    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    mcp.call(
        "trackers.log",
        json!({"collection": "weight", "data": {"kg": 81}}),
    );
    let rows = mcp.call("trackers.query", json!({"collection": "weight"}));

    assert!(
        format!("{:?}", rows).contains("81"),
        "logged value missing: {:?}",
        rows
    );
}

/// Scopes must be enforced per tool, not just at the connection.
#[test]
fn e2e_mcp_scopes_are_enforced_per_tool() {
    let (server, pws) = start_server(&["phone"]);
    seed(&Client::new(&server, &pws[0]));
    let readonly = Mcp::new(&server, &create_mcp_token(&server, "ro", "notes:read"));

    // Allowed by scope.
    readonly.call("notes.read", json!({"path": "journal.md"}));

    // Not allowed: different resource, and a write.
    let e1 = readonly.call_expecting_error("files.read", json!({"path": "report.txt"}));
    assert!(e1.contains("scope"), "expected a scope error, got: {}", e1);
    let e2 = readonly.call_expecting_error(
        "notes.append",
        json!({"path": "journal.md", "content": "x"}),
    );
    assert!(e2.contains("scope"), "expected a scope error, got: {}", e2);
}

#[test]
fn e2e_mcp_calls_are_audited() {
    let (server, pws) = start_server(&["phone"]);
    seed(&Client::new(&server, &pws[0]));
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "audited", "*"));
    mcp.call("notes.read", json!({"path": "journal.md"}));

    let conn = rusqlite::Connection::open(server.data_dir.join("tilde.db")).unwrap();
    let n: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM mcp_audit_log WHERE tool_name = 'notes.read'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert!(n >= 1, "MCP calls must be recorded in the audit log");
}

/// Email is not configured in these tests; the tools must return empty rather
/// than erroring, or an agent's first email question looks like a broken server.
#[test]
fn e2e_mcp_email_tools_degrade_gracefully_without_email() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    for (tool, args) in [
        ("email.search", json!({"query": "anything"})),
        ("email.recent", json!({})),
        ("email.thread", json!({"message_id": "<none@example.com>"})),
    ] {
        let r = mcp.call(tool, args);
        assert!(
            r.as_array().is_some(),
            "{} should return a list, got {:?}",
            tool,
            r
        );
    }
}

/// Path traversal: a scoped MCP token must not read outside its tree.
///
/// `Path::starts_with` is component-wise and does not normalise, so the original
/// check `root.join(rel).starts_with(root)` returned true for `root/../secret`
/// and the read escaped. A `notes:read` token could read any file the server
/// process could open — including `tilde.db`, which holds credential hashes.
#[test]
fn e2e_mcp_path_traversal_is_refused() {
    let (server, _pws) = start_server(&["phone"]);
    std::fs::write(server.data_dir.join("secret.txt"), "CANARY-DO-NOT-LEAK\n").unwrap();

    let mcp = Mcp::new(&server, &create_mcp_token(&server, "ro", "*"));

    for (tool, arg) in [
        ("notes.read", "../secret.txt"),
        ("notes.read", "../../../../../../etc/hostname"),
        ("notes.append", "../secret.txt"),
        ("files.read", "../secret.txt"),
        ("files.list", ".."),
        ("files.search", ".."),
    ] {
        let args = if tool == "files.search" {
            json!({"query": "CANARY", "path": arg})
        } else if tool == "notes.append" {
            json!({"path": arg, "content": "pwned"})
        } else if tool == "files.list" {
            json!({"path": arg})
        } else {
            json!({"path": arg})
        };
        let err = mcp.call_expecting_error(tool, args);
        assert!(
            err.contains("traversal"),
            "{} with {:?} must be refused, got: {}",
            tool,
            arg,
            err
        );
    }

    // And the canary must be untouched by the attempted append.
    let canary = std::fs::read_to_string(server.data_dir.join("secret.txt")).unwrap();
    assert_eq!(canary, "CANARY-DO-NOT-LEAK\n");
}

/// The new CRUD tools must actually be reachable through the dispatcher.
#[test]
fn e2e_mcp_new_crud_tools_are_wired() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let names = mcp.tool_names();
    for expected in [
        "notes.create",
        "notes.write",
        "notes.delete",
        "files.write",
        "files.delete",
        "files.mkdir",
        "files.move",
        "photos.search",
        "photos.recent",
        "photos.get",
        "photos.stats",
    ] {
        assert!(
            names.contains(&expected.to_string()),
            "{} not registered",
            expected
        );
    }

    // An agent can now start a note from nothing — previously impossible.
    mcp.call(
        "notes.create",
        json!({"path": "memory/session.md", "content": "# Session\n"}),
    );
    let read = mcp.call("notes.read", json!({"path": "memory/session.md"}));
    assert!(read["content"].as_str().unwrap().contains("# Session"));

    mcp.call(
        "notes.write",
        json!({"path": "memory/session.md", "content": "# Session 2\n"}),
    );
    let read2 = mcp.call("notes.read", json!({"path": "memory/session.md"}));
    assert!(read2["content"].as_str().unwrap().contains("Session 2"));

    mcp.call("notes.delete", json!({"path": "memory/session.md"}));
    let gone = mcp.call_expecting_error("notes.read", json!({"path": "memory/session.md"}));
    assert!(
        gone.contains("not found"),
        "expected not-found, got {}",
        gone
    );

    mcp.call("files.mkdir", json!({"path": "reports"}));
    mcp.call(
        "files.write",
        json!({"path": "reports/q3.txt", "content": "revenue up\n"}),
    );
    let f = mcp.call("files.read", json!({"path": "reports/q3.txt"}));
    assert!(f["content"].as_str().unwrap().contains("revenue up"));

    let stats = mcp.call("photos.stats", json!({}));
    assert!(
        stats.is_object() || stats.is_array(),
        "photos.stats returned {:?}",
        stats
    );
}

/// Destructive MCP writes must archive first, exactly as the DAV path does —
/// otherwise agent writes become a side door to unrecoverable data loss.
#[test]
fn e2e_mcp_destructive_writes_archive_first() {
    let (server, _pws) = start_server(&["phone"]);
    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    mcp.call(
        "notes.create",
        json!({"path": "doomed.md", "content": "ORIGINAL CONTENT\n"}),
    );
    mcp.call(
        "notes.write",
        json!({"path": "doomed.md", "content": "REPLACED\n"}),
    );

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(b"ORIGINAL CONTENT\n");
    let sha = format!("{:x}", h.finalize());
    let blob = server
        .data_dir
        .join("blobs/by-id")
        .join(&sha[..2])
        .join(&sha);

    assert!(
        blob.exists(),
        "overwritten content must be archived; looked for {}",
        blob.display()
    );
}

/// A symlink placed *at* the requested path must not escape the root.
///
/// The containment probe started at the parent (`.ancestors().skip(1)`), so a
/// symlink at the target itself resolved outside and passed. `notes.write` uses
/// `fs::write`, which follows symlinks — so this was an arbitrary-file-write
/// primitive for any notes:write token.
#[test]
fn e2e_mcp_symlink_at_target_is_refused() {
    let (server, _pws) = start_server(&["phone"]);
    std::fs::write(server.data_dir.join("outside.txt"), "ORIGINAL\n").unwrap();

    // A note that is really a symlink pointing out of the notes tree.
    #[cfg(unix)]
    std::os::unix::fs::symlink(
        server.data_dir.join("outside.txt"),
        server.data_dir.join("notes/escape.md"),
    )
    .unwrap();

    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    let err = mcp.call_expecting_error(
        "notes.write",
        json!({"path": "escape.md", "content": "PWNED"}),
    );
    assert!(err.contains("traversal"), "expected refusal, got: {}", err);

    assert_eq!(
        std::fs::read_to_string(server.data_dir.join("outside.txt")).unwrap(),
        "ORIGINAL\n",
        "file outside the notes root was modified through a symlink"
    );
}

/// The search query must never be parsed as a grep option.
///
/// Without a `--` terminator, `-f/dev/zero` exhausts memory and `-e` or
/// `--include=*` swallow the search-directory operand, making grep recurse the
/// process working directory instead of the search root.
#[test]
fn e2e_mcp_search_query_is_not_parsed_as_a_grep_option() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    c.put("/dav/notes/real.md", "genuine content\n");
    c.put("/dav/files/real.txt", "genuine content\n");

    let mcp = Mcp::new(&server, &create_mcp_token(&server, "agent", "*"));

    // Each of these is an option, not a pattern. They must be treated as a
    // literal search string: zero matches, no hang, no escape.
    for query in ["-e", "--include=*", "-r", "--help"] {
        for tool in ["notes.search", "files.search"] {
            let hits = mcp.call(tool, json!({"query": query}));
            assert!(
                hits.as_array().map(|a| a.is_empty()).unwrap_or(false),
                "{} with query {:?} should match nothing, got {:?}",
                tool,
                query,
                hits
            );
        }
    }

    // A normal query still works, so the `--` did not break searching.
    let hits = mcp.call("notes.search", json!({"query": "genuine"}));
    assert!(!hits.as_array().unwrap().is_empty(), "normal search broke");
}
