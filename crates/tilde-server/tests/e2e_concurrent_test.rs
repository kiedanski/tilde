//! End-to-end concurrent-write tests against the **real** server binary.
//!
//! Everything else in this suite drives an in-process `axum_test::TestServer`.
//! That never exercises `tilde serve`, which builds its own `DavState` — so the
//! wiring there (blob store root, migrations against a real database, real HTTP
//! semantics) is otherwise untested.
//!
//! These tests spawn the actual binary and talk to it over TCP with two separate
//! credentials, the way a phone and a laptop would.

mod common;

use common::e2e::{Client, sha256_hex, start_server};

const BASE: &str = "# Journal\n\nline A\nline B\nline C\n";
// Laptop appends at the end; phone prepends at the start. The edits do not
// overlap, so a three-way merge can keep both.
const LAPTOP: &str = "# Journal\n\nline A\nline B\nline C\nlaptop appended\n";
const PHONE: &str = "phone prepended\n# Journal\n\nline A\nline B\nline C\n";

/// Proves slice 2 is actually wired into `tilde serve` — not just into the
/// in-process test router. Should pass today.
#[test]
fn e2e_overwritten_version_is_archived_by_the_real_server() {
    let (server, pws) = start_server(&["phone"]);
    let phone = Client::new(&server, &pws[0]);

    assert_eq!(phone.put("/dav/notes/j.md", BASE), 201);
    assert_eq!(phone.put("/dav/notes/j.md", LAPTOP), 204);

    let sha = sha256_hex(BASE.as_bytes());
    let blob = server
        .data_dir
        .join("blobs/by-id")
        .join(&sha[..2])
        .join(&sha);

    assert!(
        blob.exists(),
        "the real server must archive the version it overwrote; looked for {}",
        blob.display(),
    );
}

/// The scenario that started all this: two devices edit the same note from the
/// same starting point, in different places.
///
/// Until slice 3 lands this FAILS, and the failure message shows exactly which
/// device's work was destroyed.
#[test]
fn e2e_two_clients_editing_one_note_keep_both_edits() {
    let (server, pws) = start_server(&["phone", "laptop"]);
    let phone = Client::new(&server, &pws[0]);
    let laptop = Client::new(&server, &pws[1]);

    // Seed, then both devices sync down the same version.
    assert_eq!(phone.put("/dav/notes/j.md", BASE), 201);
    assert_eq!(phone.get("/dav/notes/j.md").0, 200);
    assert_eq!(laptop.get("/dav/notes/j.md").0, 200);

    // Laptop writes first and wins the race to the server.
    assert_eq!(laptop.put("/dav/notes/j.md", LAPTOP), 204);

    // Phone writes from the version it last read, unaware of the laptop's edit.
    phone.put("/dav/notes/j.md", PHONE);

    let (_, final_content) = phone.get("/dav/notes/j.md");

    assert!(
        final_content.contains("phone prepended"),
        "phone's edit missing:\n{}",
        final_content
    );
    assert!(
        final_content.contains("laptop appended"),
        "laptop's edit was destroyed by the phone's write — the two edits do \
         not overlap and should have merged.\nFinal content:\n{}",
        final_content
    );
}

/// The agent case: an MCP write lands between a client's read and its write.
#[test]
fn e2e_agent_append_survives_a_client_write() {
    let (server, pws) = start_server(&["phone"]);
    let phone = Client::new(&server, &pws[0]);

    assert_eq!(phone.put("/dav/notes/j.md", BASE), 201);
    assert_eq!(phone.get("/dav/notes/j.md").0, 200);

    // Agent appends directly to disk, exactly as notes.append does.
    let note = server.data_dir.join("notes/j.md");
    let with_agent = format!("{}agent appended\n", BASE);
    std::fs::write(&note, &with_agent).unwrap();

    // Phone writes from the version it read, before it saw the agent's line.
    phone.put("/dav/notes/j.md", PHONE);

    let (_, final_content) = phone.get("/dav/notes/j.md");

    assert!(
        final_content.contains("agent appended"),
        "the agent's write was destroyed by the phone's write.\nFinal content:\n{}",
        final_content
    );
}

/// Overlapping edits cannot be merged automatically. Both sides must survive in
/// the file with markers — never one silently winning.
#[test]
fn e2e_overlapping_edits_leave_conflict_markers_not_data_loss() {
    let (server, pws) = start_server(&["phone", "laptop"]);
    let phone = Client::new(&server, &pws[0]);
    let laptop = Client::new(&server, &pws[1]);

    assert_eq!(phone.put("/dav/notes/c.md", BASE), 201);
    phone.get("/dav/notes/c.md");
    laptop.get("/dav/notes/c.md");

    // Both rewrite the *same* line.
    laptop.put(
        "/dav/notes/c.md",
        "# Journal\n\nline A\nlaptop rewrote B\nline C\n",
    );
    phone.put(
        "/dav/notes/c.md",
        "# Journal\n\nline A\nphone rewrote B\nline C\n",
    );

    let (_, content) = phone.get("/dav/notes/c.md");

    assert!(
        content.contains("<<<<<<<") && content.contains(">>>>>>>"),
        "overlapping edits must be marked, not silently resolved:\n{}",
        content
    );
    assert!(
        content.contains("laptop rewrote B") && content.contains("phone rewrote B"),
        "both sides must survive a conflict:\n{}",
        content
    );
}

/// RFC 9110 §9.3.4: no validator on a PUT response whose content was transformed.
///
/// If the server returned the merged ETag, the client would record it as
/// matching its *local* (unmerged) copy, never re-fetch, and re-conflict forever.
#[test]
fn e2e_merged_put_omits_etag_so_clients_resync() {
    let (server, pws) = start_server(&["phone", "laptop"]);
    let phone = Client::new(&server, &pws[0]);
    let laptop = Client::new(&server, &pws[1]);

    assert_eq!(phone.put("/dav/notes/e.md", BASE), 201);
    phone.get("/dav/notes/e.md");
    laptop.get("/dav/notes/e.md");
    laptop.put("/dav/notes/e.md", LAPTOP);

    let resp = phone
        .http
        .put(format!("{}/dav/notes/e.md", phone.base_url))
        .basic_auth("admin", Some(&phone.password))
        .body(PHONE.to_string())
        .send()
        .unwrap();

    assert!(
        resp.headers().get("etag").is_none(),
        "a merged PUT must not carry a validator (RFC 9110 §9.3.4); got {:?}",
        resp.headers().get("etag"),
    );
    assert_eq!(
        resp.headers()
            .get("x-tilde-merge")
            .map(|v| v.to_str().unwrap()),
        Some("clean"),
    );
}

/// A normal, non-stale write must still behave exactly as before.
#[test]
fn e2e_uncontended_put_still_returns_an_etag() {
    let (server, pws) = start_server(&["phone"]);
    let phone = Client::new(&server, &pws[0]);

    assert_eq!(phone.put("/dav/notes/n.md", BASE), 201);
    phone.get("/dav/notes/n.md");

    let resp = phone
        .http
        .put(format!("{}/dav/notes/n.md", phone.base_url))
        .basic_auth("admin", Some(&phone.password))
        .body(LAPTOP.to_string())
        .send()
        .unwrap();

    assert!(
        resp.headers().get("etag").is_some(),
        "an untransformed write must still return its validator"
    );
}

/// Two consecutive writes from ONE client, no concurrency, no other writer.
///
/// After a PUT succeeds the client demonstrably holds what it just sent, but the
/// recorded base was only ever advanced by GET. So the second PUT looked stale,
/// merged against the pre-first-PUT ancestor, and diff3 fast-forwarded to the
/// copy on disk — silently resurrecting content the user had just deleted.
///
/// This is the exact data-loss class the merge feature exists to prevent,
/// reintroduced by the fix itself. Every other test in this file does a GET
/// immediately before each PUT, which hides it.
#[test]
fn e2e_consecutive_puts_do_not_resurrect_deleted_content() {
    let (server, pws) = start_server(&["phone"]);
    let phone = Client::new(&server, &pws[0]);

    assert_eq!(phone.put("/dav/notes/d.md", "a\nb\nc\n"), 201);
    assert_eq!(phone.get("/dav/notes/d.md").0, 200); // client syncs down

    // First edit: append a line.
    assert_eq!(phone.put("/dav/notes/d.md", "a\nb\nc\nd\n"), 204);

    // Second edit, with NO intervening GET — a sync client trusts the ETag its
    // own PUT returned. The user deletes the line they just added.
    phone.put("/dav/notes/d.md", "a\nb\nc\n");

    let (_, final_content) = phone.get("/dav/notes/d.md");
    assert_eq!(
        final_content, "a\nb\nc\n",
        "the deletion was discarded and 'd' came back:\n{:?}",
        final_content
    );
}

/// A merged PUT must also advance the base, or the client's next write merges
/// against a two-generation-old ancestor.
#[test]
fn e2e_base_advances_after_a_merged_put() {
    let (server, pws) = start_server(&["phone", "laptop"]);
    let phone = Client::new(&server, &pws[0]);
    let laptop = Client::new(&server, &pws[1]);

    assert_eq!(phone.put("/dav/notes/m.md", BASE), 201);
    phone.get("/dav/notes/m.md");
    laptop.get("/dav/notes/m.md");

    laptop.put("/dav/notes/m.md", LAPTOP);
    phone.put("/dav/notes/m.md", PHONE); // merges

    // Phone now writes again from the merged content it would have re-fetched.
    let (_, merged) = phone.get("/dav/notes/m.md");
    let trimmed = merged.replace("laptop appended\n", "");
    phone.put("/dav/notes/m.md", &trimmed);

    let (_, after) = phone.get("/dav/notes/m.md");
    assert!(
        !after.contains("laptop appended"),
        "a deliberate removal after a merge was undone:\n{}",
        after
    );
}

// ─── Cross-mount index destruction ────────────────────────────────────────────
//
// Every DAV mount shares one `files` table, distinguished only by a path prefix,
// and the files mount's prefix is the empty string. So a directory named
// `photos` under files/ has db_path "photos" — exactly the photos mount's
// namespace. `init.sh` itself used to create `files/notes`.

fn photos_rows(server: &common::e2e::Server) -> i64 {
    let conn = rusqlite::Connection::open(server.data_dir.join("tilde.db")).unwrap();
    conn.query_row(
        "SELECT COUNT(*) FROM files WHERE path LIKE 'photos/%'",
        [],
        |r| r.get(0),
    )
    .unwrap()
}

fn mkcol(c: &Client, server: &common::e2e::Server, pw: &str, path: &str) -> u16 {
    c.http
        .request(
            reqwest::Method::from_bytes(b"MKCOL").unwrap(),
            format!("{}{}", server.base_url, path),
        )
        .basic_auth("admin", Some(pw))
        .send()
        .unwrap()
        .status()
        .as_u16()
}

/// Deleting a *files-mount* directory named `photos` must not touch the photos
/// mount's index. The cascade goes `files` -> `photos` -> `photo_tags`, so this
/// destroys every user-applied tag; EXIF is re-derivable from disk, tags are not.
#[test]
fn e2e_deleting_a_files_dir_named_photos_spares_the_photo_index() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);

    assert_eq!(c.put("/dav/photos/holiday.jpg", "pretend jpeg"), 201);
    let before = photos_rows(&server);
    assert!(before > 0, "fixture did not index a photo");

    assert_eq!(mkcol(&c, &server, &pws[0], "/dav/files/photos"), 201);
    let del = c
        .http
        .delete(format!("{}/dav/files/photos", server.base_url))
        .basic_auth("admin", Some(&pws[0]))
        .send()
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        204,
        "DELETE must succeed or this test proves nothing"
    );

    assert_eq!(
        photos_rows(&server),
        before,
        "deleting files/photos wiped the photos mount's index"
    );
}

/// The LIKE pattern is `name%`, not `name/%`, so a directory whose name is merely
/// a *prefix* of another mount also matches.
#[test]
fn e2e_deleting_a_prefix_named_files_dir_spares_other_mounts() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);

    assert_eq!(c.put("/dav/photos/holiday.jpg", "pretend jpeg"), 201);
    let before = photos_rows(&server);

    assert_eq!(mkcol(&c, &server, &pws[0], "/dav/files/photo"), 201);
    let del = c
        .http
        .delete(format!("{}/dav/files/photo", server.base_url))
        .basic_auth("admin", Some(&pws[0]))
        .send()
        .unwrap();
    assert_eq!(
        del.status().as_u16(),
        204,
        "DELETE must succeed or this test proves nothing"
    );

    assert_eq!(
        photos_rows(&server),
        before,
        "deleting files/photo (singular) matched photos/ rows"
    );
}

/// MOVE rewrites child paths by prefix and has the same collision.
#[test]
fn e2e_moving_a_files_dir_named_photos_spares_the_photo_index() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);

    assert_eq!(c.put("/dav/photos/holiday.jpg", "pretend jpeg"), 201);
    let before = photos_rows(&server);

    assert_eq!(mkcol(&c, &server, &pws[0], "/dav/files/photos"), 201);
    let mv = c
        .http
        .request(
            reqwest::Method::from_bytes(b"MOVE").unwrap(),
            format!("{}/dav/files/photos", server.base_url),
        )
        .basic_auth("admin", Some(&pws[0]))
        .header(
            "Destination",
            format!("{}/dav/files/archive", server.base_url),
        )
        .send()
        .unwrap();
    assert!(
        mv.status().is_success(),
        "MOVE must succeed or this test proves nothing: {}",
        mv.status()
    );

    assert_eq!(
        photos_rows(&server),
        before,
        "moving files/photos renamed the photos mount's index rows"
    );
}
