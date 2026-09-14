# Plan: Fix WebDAV ETag correctness and file indexing

Status: Phase 0, 1, 3.2, 3.3 complete (2026-09-13). Phase 2', 5, 6, 7, 8 complete; deploy rehearsal green; MCP covered; CI green. Phase 3.1 (watcher) and 4 outstanding.
Date: 2026-09-13

Fixes the data-loss bug where notes edited on a phone silently overwrite changes
made by agents or the CLI, and lays the groundwork for health/finance ingest.

> Repo convention note: existing plans live in `plans/<date>-<slug>.md`. This file
> is at the root as requested; move it if you want to keep the convention.

---

## 1. Verified defects

Each row was confirmed by reading the code, and checked against the existing test
suite to establish that no current test covers it.

| # | Defect | Location | Why existing tests miss it |
|---|--------|----------|----------------------------|
| 1 | `exec_notes_append` writes to disk, never updates `files` | `tilde-mcp/src/lib.rs:626-656` | No test calls an MCP write tool and then inspects DAV |
| 2 | PROPFIND fallback mints a **random UUID** as `oc:id` and uses **file size** as ETag | `tilde-dav/src/lib.rs:1879` | Every test creates files via DAV PUT, which always writes a row, so the fallback never executes |
| 3 | Directory ETag silently ignores children with no DB row | `tilde-dav/src/lib.rs:1908-1913` | Same reason — all test children are DAV-created |
| 4 | `If-Match` honored only when the client sends it; no other conflict detection | `tilde-dav/src/lib.rs:296-309` | `if_match_wrong_etag_returns_412` covers the *present* case only |
| 5 | No watcher on `notes/` or `files/`; `reindex` rebuilds only photos and links | `commands/reindex.rs`, `commands/serve.rs:147` | Not covered |

### Why the existing ETag tests pass anyway

`directory_etag_changes_on_file_modify` (`webdav_test.rs:848`) is named as though it
covers defect 3, but "modified in place" there means **a second DAV PUT** — which
updates the DB row, so the DB-backed ETag is correct and the test passes. No test in
the suite ever writes to the data directory directly. That is the entire blind spot:
**every write in the test suite goes through the one path that maintains the index.**

### The failure sequence

1. Agent calls `notes.append` → disk content changes, `files.etag` does not.
2. Obsidian issues PROPFIND → sees the **old** ETag → concludes "remote unchanged" → skips download.
3. User edits the note on the phone → PUT replaces the whole file.
4. The agent's append is gone, with no conflict recorded anywhere.

---

## 2. Design decision: disk is authoritative, DB is a stat cache

Two options were considered:

- **(A)** Keep the DB authoritative and patch every write path to update it.
- **(B)** Derive the ETag from disk, using the DB purely as a cache keyed by `(path, mtime, size)`.

**Choose (B).** Reasons:

- It matches the README's claim that files are the source of truth and SQLite is a rebuildable cache.
- It is **self-healing**. Any out-of-band write is caught on the next `stat`, so correctness does not depend on catching every write path.
- It demotes the watcher from correctness requirement to optimization. Watchers always miss events eventually — inotify queue overflow, bind mounts, writes landing while the server is down. Under (A) a missed event is silent data loss; under (B) it is one extra hash.
- It fixes defect 1 **for free**: `notes.append` needs no change, because the ETag stops depending on it reporting anything.

Keep the existing **content-hash** ETag (`sha256[..16]`, `dav/src/lib.rs:397`) rather than
switching to `mtime+size+inode`. A restic restore rewrites mtimes without changing content;
a content hash avoids a full resync storm. The stat cache means hashing happens only on
real change.

### 2.1 The mtime race — the one subtle part

A `(mtime, size)` cache key is **not** sufficient on its own. Two writes of equal length
within the same mtime tick are indistinguishable from no write at all. This is not
theoretical: it is exactly what test T3 below does, and what a fast agent write followed
by a poll will do in production.

Mitigations, both required:

1. Store mtime with **nanosecond** precision (`std::fs::Metadata::modified()` →
   `duration_since(UNIX_EPOCH).as_nanos()`), not `as_secs()` as the current PROPFIND
   code does at `dav/src/lib.rs:1862`. Note that coarse filesystems and tools like
   `tar` still hand out second-granularity timestamps, so this alone is not enough.
2. Adopt git's **racily-clean** rule: if `now - mtime < 2s`, treat the cache entry as
   stale regardless of match and re-hash. Recent files are cheap to re-hash and are
   exactly the ones at risk.

This is called out because TDD will surface it immediately — a naive implementation
passes T1 and T2 and fails T3 intermittently, which is the worst possible failure mode
to debug later.

---

## 3. Phase 0 — Failing tests first

### 3.1 Harness changes (prerequisite)

The current harness cannot express any of these tests. Two additions to
`crates/tilde-server/tests/common/mod.rs`:

```rust
impl TestEnv {
    /// Data dir root. Needed to write files out-of-band, bypassing DAV.
    pub fn data_dir(&self) -> &std::path::Path { self._dir.path() }
    pub fn files_dir(&self) -> std::path::PathBuf { self._dir.path().join("files") }
    pub fn notes_dir(&self) -> std::path::PathBuf { self._dir.path().join("notes") }
}
```

`extract_etag_from_propfind` (`webdav_test.rs:903`) returns only the *first* `getetag`
and cannot read `oc:id`. Generalize it:

```rust
/// Extract the first value of an arbitrary property from a multistatus response.
fn extract_prop(xml: &str, tag: &str) -> String;   // e.g. extract_prop(xml, "oc:id")
/// Depth:1 helper — map href -> getetag for asserting on a specific child.
fn propfind_etags_by_href(xml: &str) -> std::collections::HashMap<String, String>;
```

Plus a small async helper used by every test below:

```rust
async fn propfind_etag(env: &TestEnv, auth: &str, path: &str) -> String;
```

### 3.2 The tests

All go in `crates/tilde-server/tests/webdav_test.rs` except T6.

---

**T1 — `propfind_etag_changes_after_out_of_band_write`** (defect 1, 2)

The core assumption: an ETag must reflect disk, not the last DAV write.

```rust
#[tokio::test]
async fn propfind_etag_changes_after_out_of_band_write() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    env.server
        .method(Method::PUT, "/dav/files/oob.txt")
        .add_header(header::AUTHORIZATION, &auth)
        .text("version 1")
        .await
        .assert_status(StatusCode::CREATED);

    let etag1 = propfind_etag(&env, &auth, "/dav/files/oob.txt").await;

    // Bypass DAV entirely: this is what notes.append, the CLI, rsync,
    // and a restic restore all do.
    std::fs::write(env.files_dir().join("oob.txt"), "version 2 is longer").unwrap();

    let etag2 = propfind_etag(&env, &auth, "/dav/files/oob.txt").await;

    assert_ne!(etag1, etag2, "ETag must change after an out-of-band write");
}
```

Expected failure today: ETags are equal — the DB still holds `version 1`'s hash.

---

**T2 — `propfind_oc_id_is_stable_for_unindexed_file`** (defect 2)

Proves the random-UUID fallback. This is the one that makes Nextcloud-protocol clients
treat every poll as a brand-new file.

```rust
#[tokio::test]
async fn propfind_oc_id_is_stable_for_unindexed_file() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    // Created on disk only — never through DAV, so no `files` row exists.
    std::fs::write(env.files_dir().join("ghost.txt"), "hello").unwrap();

    let xml1 = propfind_body(&env, &auth, "/dav/files/ghost.txt").await;
    let xml2 = propfind_body(&env, &auth, "/dav/files/ghost.txt").await;

    assert_eq!(
        extract_prop(&xml1, "oc:id"),
        extract_prop(&xml2, "oc:id"),
        "oc:id must be stable across requests; a fresh UUID per PROPFIND makes \
         every poll look like a different file to Nextcloud-protocol clients",
    );
}
```

Expected failure today: two different UUIDs.

---

**T3 — `propfind_etag_changes_on_same_length_edit`** (defect 2, plus the mtime race)

The sharpest test in the set. It fails today because the fallback ETag is the file
*size*, and it will fail again against a naive second-resolution stat cache.

```rust
#[tokio::test]
async fn propfind_etag_changes_on_same_length_edit() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);

    let path = env.files_dir().join("same.txt");
    std::fs::write(&path, "aaaa").unwrap();
    let etag1 = propfind_etag(&env, &auth, "/dav/files/same.txt").await;

    std::fs::write(&path, "bbbb").unwrap();  // same length, immediate
    let etag2 = propfind_etag(&env, &auth, "/dav/files/same.txt").await;

    assert_ne!(etag1, etag2, "ETag must reflect content, not length");
}
```

Keep this test explicitly **non-sleeping**. The temptation during implementation will be
to insert a `sleep(1s)` to make it pass; that would hide exactly the production race
described in §2.1.

---

**T4 — `get_etag_matches_content_after_out_of_band_write`** (defect 1)

Note this is deliberately *not* "GET and PROPFIND agree" — they already agree today,
because both read the same stale DB value. The assertion must be against content.

```rust
#[tokio::test]
async fn get_etag_matches_content_after_out_of_band_write() {
    // ... PUT "version 1", then std::fs::write "version 2" ...
    let resp = env.server.get("/dav/files/coherent.txt")
        .add_header(header::AUTHORIZATION, &auth).await;

    let served_etag = resp.header("etag").to_str().unwrap().trim_matches('"').to_string();
    let expected = sha256_hex(resp.text().as_bytes())[..16].to_string();

    assert_eq!(served_etag, expected,
        "GET served content whose ETag belongs to a previous version");
}
```

---

**T5 — `directory_etag_changes_when_unindexed_child_modified`** (defect 3)

Covers the silent `else if let Some(child_etag)` fallthrough at `dav/src/lib.rs:1908`,
where a child with no DB row contributes nothing to the directory hash.

```rust
#[tokio::test]
async fn directory_etag_changes_when_unindexed_child_modified() {
    // MKCOL /dav/files/ghostdir via DAV, then write the child directly to disk.
    std::fs::create_dir_all(env.files_dir().join("ghostdir")).unwrap();
    std::fs::write(env.files_dir().join("ghostdir/a.txt"), "one").unwrap();
    let etag1 = propfind_etag(&env, &auth, "/dav/files/ghostdir").await;

    std::fs::write(env.files_dir().join("ghostdir/a.txt"), "two").unwrap();
    let etag2 = propfind_etag(&env, &auth, "/dav/files/ghostdir").await;

    assert_ne!(etag1, etag2,
        "Directory ETag must account for children that have no DB row");
}
```

---

**T6 — `mcp_notes_append_is_visible_over_dav`** — the actual reported bug

New file `crates/tilde-server/tests/notes_sync_test.rs`. This belongs on the
`common::create_test_server()` harness, **not** `e2e_test.rs` — that file spawns the
real binary as a subprocess and has no way to drive MCP. `create_test_server()` already
wires `mcp_state` and the DAV routers into one router, and `auth_test.rs:162` shows the
MCP JSON-RPC call shape.

```rust
#[tokio::test]
async fn mcp_notes_append_is_visible_over_dav() {
    let env = common::create_test_server();
    let pw = common::create_app_password(&env.pool, "dav-rw", "/dav/*");
    let auth = common::basic_auth_header(&pw);
    let token = common::create_mcp_token(&env.pool, "agent", "*");

    // Note created through DAV, so it *does* have a files row.
    // This is the realistic case and the one that loses data.
    env.server
        .method(Method::PUT, "/dav/notes/journal.md")
        .add_header(header::AUTHORIZATION, &auth)
        .text("# Journal\n")
        .await
        .assert_status(StatusCode::CREATED);

    let etag_before = propfind_etag(&env, &auth, "/dav/notes/journal.md").await;

    // Agent appends.  notes.append requires the file to already exist
    // (tilde-mcp/src/lib.rs:642) and writes to data_dir/notes, which is
    // what /dav/notes serves (server/src/lib.rs:51-66).
    env.server
        .post("/mcp")
        .add_header(header::AUTHORIZATION, format!("Bearer {}", token))
        .json(&serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "notes.append",
                "arguments": {"path": "journal.md", "content": "written by agent"}
            }
        }))
        .await
        .assert_status_ok();

    let etag_after = propfind_etag(&env, &auth, "/dav/notes/journal.md").await;

    assert_ne!(etag_before, etag_after,
        "PROPFIND ETag must change after notes.append — otherwise Obsidian \
         never pulls the agent's write and clobbers it on the next phone edit");

    let body = env.server.get("/dav/notes/journal.md")
        .add_header(header::AUTHORIZATION, &auth).await.text();
    assert!(body.contains("written by agent"));
}
```

### 3.3 Exit criteria for Phase 0

T1, T2, T3, T4, T5, T6 all **fail**, each for the predicted reason. If any passes,
the corresponding defect claim is wrong and this plan needs revising before code changes.

---

## 4. Phase 1 — ETag correctness

### 4.1 Migration `migrations/009_file_stat_cache.sql`

Latest existing migration is `008_untriaged_sentinel_date.sql`.

```sql
ALTER TABLE files ADD COLUMN mtime_nanos INTEGER;
ALTER TABLE files ADD COLUMN inode INTEGER;
```

`path` is already `UNIQUE` (`001_initial.sql:57`) so it has an implicit index; no new
index needed. Existing rows get `NULL` mtime, which reads as a cache miss and forces
one rehash per file on first access. That is the intended migration behavior.

### 4.2 New resolver — `crates/tilde-dav/src/lib.rs`

Replaces `get_etag_for_file` (`:1766`), which is the single chokepoint all three
call sites go through.

```rust
/// Resolve (oc_id, etag) for a path, treating disk as authoritative.
/// Returns None if the file does not exist on disk.
fn resolve_file_identity(state: &SharedDavState, rel_path: &str)
    -> Option<(String, String)>
{
    // 1. stat disk (cheap); absent -> None
    // 2. SELECT id, etag, mtime_nanos, size_bytes FROM files WHERE path = ?
    // 3. cache hit iff row exists
    //      AND row.mtime_nanos == disk mtime_nanos
    //      AND row.size_bytes  == disk size
    //      AND (now - mtime) >= 2s          <- racily-clean rule, §2.1
    //    -> return (row.id, row.etag)
    // 4. miss -> hash file, upsert row.
    //    PRESERVE row.id if the row exists; mint a uuid only on first insert.
    // 5. return fresh (id, etag)
}
```

Constraints:

- Hashing must run under `tokio::task::spawn_blocking` — precedent at `:479` and `:1042`.
- `oc_id` must be **persisted on first sight** and never regenerated. This is the defect-2 fix.
- Directories skip hashing entirely.

### 4.3 Call-site changes

| Site | Line | Change |
|------|------|--------|
| GET | `dav/src/lib.rs:253` | `get_etag_for_file` → `resolve_file_identity` |
| PUT `If-Match` | `dav/src/lib.rs:299` | same, so preconditions compare against real disk state |
| PROPFIND | `dav/src/lib.rs:1872-1880` | same; **delete** the `unwrap_or_else(\|_\| (Uuid::new_v4(), format!("{:x}", size)))` fallback |
| PROPFIND mtime | `dav/src/lib.rs:1862` | `as_secs()` → nanosecond precision for the cache key |
| Directory hash | `dav/src/lib.rs:1908-1913` | resolve each child through `resolve_file_identity` instead of reading `child_etags` from the DB, so unindexed children contribute |

Note that 4.3's last row makes the existing `child_etags` bulk query (`:1895`) redundant
for correctness, but keep a batched variant for performance — a Depth:1 PROPFIND on a
wide directory should not do N individual queries.

### 4.4 Implementation notes (as built)

Four deviations from the plan above, all discovered during implementation:

1. **`Last-Modified` stays second-granular.** §2.1 said to change `dav/src/lib.rs:1862`
   to nanoseconds, but that line builds the HTTP `Last-Modified` header, which is
   second-granular by RFC 9110 and must stay that way. The nanosecond mtime is a
   separate value read inside the resolver and only ever compared against a stored
   copy of itself.

2. **PROPFIND now builds all entries in one `spawn_blocking` hop.** `propfind_entry`
   is sync and may now hash, so the handler collects `(rel_path, href)` targets
   first and resolves them in a single blocking call rather than one per child.

3. **The existing write-path INSERTs were deliberately left alone** (PUT `:427`,
   MKCOL, COPY, chunked upload). They write rows with `mtime_nanos = NULL`, which
   the resolver reads as a cache miss and repairs on next access. This is the same
   row shape a pre-migration database has, so **the upgrade path is exercised by
   T1/T4/T6 rather than being untested** — those tests PUT a file (producing a
   legacy-shaped row) and then assert correct resolution. Cost is one extra hash
   per file, once. Wiring `mtime_nanos` into the write paths is a pure optimization
   and was judged not worth touching the critical write path for.

4. **`oc_id` fallback when a path vanishes mid-request** (listed then stat'd) is now
   derived from the path hash rather than a fresh UUID, so it stays stable.

### 4.5 Exit criteria

**Met.** All six Phase 0 tests pass; all 32 pre-existing `webdav_test.rs` tests
still pass (37 total in that file). Full workspace suite green, `cargo fmt --check`
clean, `cargo clippy --no-default-features -- -D warnings` clean.

Still outstanding: the manual check — append via MCP on the real server and confirm
Obsidian pulls it on next sync.

**Unrelated pre-existing failure:** `tilde-photos` `test_heic_blurhash` and
`test_heic_thumbnail_generation` fail under `--no-default-features` (HEIC decode
without the `heic` feature). Verified pre-existing by stashing all changes and
re-running on a clean tree. CI runs `cargo test --no-default-features`, so the test
job on `main` should currently be red — worth a separate look.

---

## 5. Phase 2′ — Git-style 3-way merge

Supersedes the original Phase 2 (below), which only *detected* conflicts and left
the user to resolve one by hand each time. Conflict copies turn silent data loss
into a daily chore, which is a bad trade for an append-heavy workload: appends to
different parts of a file do not semantically conflict and should merge silently.

### 5.1 The crux: a merge needs the base version's *content*

Last-served-ETag tracking (original 2b) yields the base version's **identity**, not
its bytes. Three-way merge needs the bytes. The cheap way to retain them is
**archive-on-overwrite**: before a PUT replaces a file, copy the outgoing content
into a content-addressed store. That captures exactly the versions a merge could
need, with no cost on reads.

    client reads v1 → agent writes v2 (server archives v1) → client PUTs v1'
    → server holds current=v2, theirs=v1', base=v1 → merge

`init.sh:85` already creates `blobs/by-id/`, which nothing in the codebase uses —
the same abandoned scaffolding pattern as `hlc`. That is the store.

### 5.2 Prerequisites (both real, both discovered while designing)

1. **`verify_app_password` returns `bool`** (`tilde-core/src/auth.rs:103`), discarding
   *which* credential authenticated. Base tracking is keyed per client, so it must
   return the app-password id. Callers: `tilde-dav:70`, `tilde-cal:100`, `tilde-card:97`.
2. **Each device needs its own app password.** If phone and laptop share one, "the
   version this client last saw" is meaningless and merges pick wrong bases. Verify
   with `tilde auth app-password list` before relying on this.

### 5.3 The response rule that makes it work

After a merge the stored file is not what the client sent. Returning the merged
ETag would make the client record "my local content = this ETag", never re-fetch,
and re-conflict on its next edit — forever.

RFC 9110 §9.3.4 mandates the fix: a server **MUST NOT** send a validator in a
successful PUT response unless the representation was saved *without transformation*.
A merge is a transformation, so the ETag is omitted and conforming clients re-fetch.

### 5.4 Design

- Base storage: `blobs/by-id/<sha256>`, populated by archive-on-overwrite
- Base selection: `client_base_versions(credential_id, path, sha256, served_at)`, recorded on GET
- Merge: `diffy::merge(base, ours, theirs)` — the diff3 family, same as `git merge-file`
- Clean merge → write silently, omit ETag per §5.3, no user action
- Conflicted → write the file **with `<<<<<<</=======/>>>>>>>` markers** so it syncs to
  the phone and is resolved in Obsidian directly. One file, not two.
- Gated to text content types under a size cap; binary falls back to a conflict copy
- GC for blobs no live client references

**History is explicitly out of scope.** Notes are already plain files, so `git init`
in `notes/` works today, and `.git` is invisible to WebDAV because PROPFIND skips
dotfiles. tilde should not reimplement that.

### 5.5 Slices (TDD, in order)

1. ~~**Credential identity + base tracking**~~ — **done.** `authenticate_app_password`
   returns the credential id (`verify_app_password` kept as a bool wrapper so
   `tilde-cal`/`tilde-card` are untouched); `check_auth` returns `Option<String>`;
   migration 010 adds `client_base_versions`; GET records the served version.
   Also: `upsert_file_row_conn` now persists the **full** sha256, not just the
   16-char ETag — slice 2 needs it as the CAS blob key.
   `HEAD` deliberately records nothing: it serves no body, so the client takes
   possession of no version. 10 new tests.
2. ~~**CAS + archive-on-overwrite**~~ — **done.** `tilde_dav::versions` stores blobs at
   `blobs/by-id/<xx>/<sha256>`, sharded by digest prefix and written temp-then-rename
   so a crash never leaves a blob whose contents disagree with its name. `handle_put`
   archives the outgoing bytes whenever it is about to displace an existing file —
   including content written **out of band**, which is otherwise unrecoverable.
   `DavState` gained `blobs_root` (one store shared by all mounts, so identical
   content dedupes across them). GC reaches from current `files.sha256` plus every
   `client_base_versions.sha256`, exposed as `tilde reindex --type versions|all`.
   10 new tests.
3. ~~**Merge on stale PUT**~~ — **done.** `versions::merge_three_way` wraps `diffy`
   (diff3, the `git merge-file` family); `merge_if_stale` fires when the client's
   recorded base differs from what is on disk. Clean merges are written silently;
   overlapping edits get `<<<<<<</=======/>>>>>>>` markers so both sides survive.
   Gated to UTF-8 under `MERGE_MAX_BYTES` (1 MiB); anything else falls back to
   overwrite, with the displaced version still archived. Response follows
   RFC 9110 §9.3.4 — no validator when the content was transformed — plus an
   `X-Tilde-Merge: clean|conflicted` header for humans.

### 5.6 Bug found only by the real-server e2e tests

`archive_version` was called **on overwrite only**, which covers just the DAV
write path. An agent, the CLI, or rsync can displace a version without ever
touching DAV — this project's central case — leaving a client with a recorded
base whose content was never archived, so the merge had no ancestor and silently
fell back to overwrite. In-process tests missed it entirely; the e2e agent test
caught it.

Fix: archive at the moment a base is **recorded** (on GET), making *every recorded
base is retrievable* an invariant. Archive-on-overwrite is retained as well, since
it preserves versions no client ever read.

**This is the argument for keeping the e2e suite.** The in-process harness drives
`build_router`; it never exercises `tilde serve`, which builds its own `DavState`.
Anything wired only in one of those two paths is invisible to the other.

---

## 6. Phase 2 (original) — Conflict detection only (superseded by Phase 2′)

Phase 1 stops changes from being *invisible*. It does not stop two genuinely concurrent
edits from clobbering each other, because most WebDAV clients never send `If-Match`.

- **2a. Require `If-Match` on PUT to existing files.** RFC-correct, returns 428 to clients that omit it. Likely breaks Obsidian sync plugins. Not recommended alone.
- **2b. Per-token last-served-ETag tracking.** Record `(token_id, path, etag_served)` on GET/PROPFIND. On an unconditional PUT, if the current ETag differs from what *this* token last received, the write is based on stale data → write a conflict copy (`note (conflict 2026-09-13 from phone).md`) and keep both. Needs no client cooperation. Costs a new table and a write on every read.
- **2c. Conflict copy on any unconditional overwrite where content differs.** Simplest; produces spurious conflict copies during normal single-device editing. Not recommended.

**Recommendation: 2b**, but decide only after Phase 1 has run in real use for a few days.
Phase 1 may remove enough pain that this is not worth its cost.

---

## 6.5 Phase 5 — Media streaming (Range requests)

**Done.** Found while investigating "videos not streaming well in webgallery".
The cause was in tilde, not the gallery app — two separate defects:

1. **No HTTP Range support at all** in the DAV layer: no `Accept-Ranges`, no
   `206 Partial Content`, no `Range` parsing. A `<video>` element cannot seek
   without it (every seek re-downloads the file), and Safari/iOS probes with
   `Range: bytes=0-1` and refuses to play when answered `200`.
2. **`mime_from_path` knew only `mp4` and `webm`**, while `tilde_photos::VIDEO_EXTENSIONS`
   ingests `mov`, `avi`, `mkv` too. An iPhone `.mov` was served as
   `application/octet-stream`, which browsers download instead of playing.

Implemented `parse_range` (RFC 9110 §14) supporting `bytes=N-M`, `bytes=N-`, and
`bytes=-N` — the suffix form matters because MP4s with a trailing `moov` atom
need the tail before playback can begin. Unsatisfiable ranges return 416 with
`Content-Range: bytes */LEN`; unparseable ones are ignored per §14.2. Multi-range
is deliberately ignored rather than answered with multipart, which no player needs.
Range responses seek and `take()` rather than buffering, so streaming a large
video still costs one 64 KiB buffer.

Mime map extended to cover every ingested video container plus common audio types.

11 parser unit tests, 9 real-server e2e tests.

### 6.5.1 The actual client: WebGallery (Android, Media3/ExoPlayer)

Confirmed against `~/workspace/webgallery`. It is an Android app, not a web app,
and its player setup (`ui/video/VideoPlayerViewModel.kt`, `OkHttpDataSource` +
`DefaultMediaSourceFactory`) is correct — the fault was entirely server-side.

Failure mechanism:

- ExoPlayer's first request for progressive media has position 0 and unknown
  length, so it sends **no** `Range` header. tilde answered 200 and initial
  playback worked — which is why this looked like a flaky streaming problem
  rather than a missing feature.
- On **seek** ExoPlayer sends `Range: bytes=N-`. tilde ignored it and returned
  200 with the whole file. `OkHttpDataSource` responds to "asked for a range, got
  200" by setting `bytesToSkip = N`, downloading and discarding every byte before
  the seek point. Seeking three minutes in re-streamed three minutes of video.

`e2e_exoplayer_seek_pattern_on_photos_mount` replicates that exact sequence
against `/dav/photos/`, the mount the app streams from.

Note the mime fix is **not** what fixed this case: Android records `.mp4`, which
was already mapped. It remains correct for `.mov`/`.mkv`/`.avi` in the library.

---

## 6.6 Phase 6 — Upgrade and security e2e

**Done.**

### Upgrade path (`e2e_upgrade_test.rs`)

Migrations 009/010 had only ever run against an empty schema created by the
current binary. Real deployments upgrade a *populated* database whose `files`
rows predate `mtime_nanos`/`inode` and may carry a **stale** `etag` — that stale
value being the exact bug this work fixes, so it is what production data looks
like.

The fixture builds a database from the historical 001–008 migration files,
including the `migrations` tracking rows with correct sha256 checksums (the
runner rejects a mismatch), then seeds legacy rows. Tests assert the new
migrations apply, `oc:id` and unrelated records survive, a stale legacy ETag is
**healed** on first read, and a file created before the upgrade still merges.

`legacy_fixture_really_is_pre_009` guards the rest: without it, a fixture that
drifted into building a current-schema database would silently reduce every other
test to a fresh-install test while still passing.

### Security bug found: revoke reported success without revoking

`tilde auth app-password revoke` matched `WHERE id = ?1` only, while
`mcp token revoke` and `webhook token revoke` both accept `id OR name`. Revoking
by name — the obvious action for a lost device — updated zero rows and **still
printed "App password X revoked"**.

Fixed to accept either, and all three revoke commands now fail loudly when
nothing matched, rather than reporting success. `e2e_revoked_password_stops_working_immediately`
covers it.

---

## 6.7 Deploy rehearsal

`scripts/rehearse-upgrade.sh` (+ `scripts/rehearse-fixture.py`) builds a realistic
4-month-old deployment — 160 indexed files (40 carrying stale ETags), 200
collection records, a real ffmpeg-generated mp4 — at the **001–008 schema**, then
upgrades it with the current release binary and exercises everything end to end.

    cargo build --release --no-default-features && ./scripts/rehearse-upgrade.sh

30 checks, all passing: migration, row preservation, stale-ETag healing, prune,
concurrent-edit merge on a *legacy* note, agent-vs-client merge, real mp4 range
streaming, revocation, and a data-integrity sweep.

### Two findings from the rehearsal

**`tilde status` does NOT run migrations.** `db::init_db` only sets PRAGMAs;
`status.rs` is not among the commands that migrate (`serve`, `init`, `usage`,
`reindex`, `backup`, and the data subcommands all do). Deploy instructions that
say "run `tilde status` to apply migrations" are wrong. The rehearsal asserts this
explicitly so the gotcha stays documented.

**`reindex` did not warm the photos mount.** `--type all` covered files and notes
but skipped photos — the largest tree, and the one serving video, so the first
PROPFIND or range request paid to hash every file. Now warmed (never pruned there:
photo rows have dependent `photos`/`photo_tags`/thumbnail records that the
dedicated pruning logic cleans up, and removing the `files` row first would orphan
them).

---

## 6.8 Phase 7 — MCP coverage, and CI unblocked

**Done.** Before this, exactly **one** of the 26 MCP tools had ever been invoked
by a test (`notes.append`, in-process). `e2e_mcp_test.rs` exercises the protocol
against the real binary: handshake, full tool inventory, notes/files/tasks/
contacts/tracker round-trips, per-tool scope enforcement, the audit log, and
graceful degradation of the email tools when no account is configured.

### Bug found: `files.search` searched the wrong tree

`exec_files_search` was handed `notes_dir` by the dispatcher (`tilde-mcp/src/lib.rs`),
so a tool documented as "Search file contents" searched **notes/** and could never
find anything under `files/`. Its declared `path` parameter ("Restrict to
subdirectory") was also accepted and ignored. Both fixed.

This is precisely the class of bug that only shows up when the tools are actually
called: the endpoint authenticated, listed 26 tools, and returned a well-formed
empty array.

### CI was red on `main`, and is now green

`test_heic_thumbnail_generation` and `test_heic_blurhash` exercise decode paths
that are themselves `#[cfg(feature = "heic")]`, but the tests carried no such
gate — so they failed under `--no-default-features`, which is exactly what the CI
`test` job runs. Gated both.

**280 passing with default features, 278 with `--no-default-features`, zero failures.**

---

## 6.9 Phase 8 — Review round: security and correctness

Three reviewers ran over the work (one security, one implementation, one
descriptions). Findings below are recorded with how each was *established*,
because two of the most confident-sounding ones did not survive checking.

### Fixed — data loss

**Base never advanced on PUT.** `record_base_version` had a single call site, in
`handle_get`. A client's second consecutive write therefore looked stale, merged
against the pre-first-write ancestor, and diff3 fast-forwarded to the copy on
disk — silently resurrecting content the user had just deleted. One credential,
no concurrency, no other writer.

Confirmed by execution twice, independently. **This was introduced by the merge
feature itself**, i.e. the fix for data loss was causing data loss. Every existing
test missed it because they all GET immediately before each PUT.
Fix: advance the base to the stored content on every successful PUT.
Tests: `e2e_consecutive_puts_do_not_resurrect_deleted_content`,
`e2e_base_advances_after_a_merged_put`.

**MOVE rewrote another mount's index.** All mounts share `files`, keyed by path
prefix, and the files mount's prefix is empty — so moving a `files/photos`
directory renamed every photos-mount row. Guarded via `sibling_mount_exclusion`.

**Directory DELETE orphaned every child row.** `disk_path.is_dir()` was evaluated
*after* the move to `.trash/`, so it was always false and the child cleanup never
ran. Also narrowed the pattern from `path%` to `path/%`, which had matched
siblings sharing a name prefix.

### Fixed — security

- **Path traversal in every MCP path tool** (`safe_join`). `Path::starts_with` is
  component-wise and does not normalise, so `root/../etc/passwd` passed. A
  `notes:read` token could read any file the process could open, including the
  database. Verified exploitable end-to-end before the fix.
- **Symlink at the target path** escaped containment: the probe used
  `.ancestors().skip(1)` and never checked the target itself, while `notes.write`
  uses `fs::write`, which follows symlinks.
- **`grep` option injection** in both search tools and the CLI — no `--`
  terminator, so `-f/dev/zero` exhausted memory and `-e` made grep recurse the
  process working directory.
- **Reachable panic in the MCP audit log** — `&params_str[..500]` panics on a
  multibyte boundary. Ordinary input (an accented character, an emoji) triggered
  it, *after* the write had landed, killing the connection with the client unable
  to tell whether its write succeeded. Two more instances of the same pattern
  found in `notifications.rs` and `usage.rs`.
- **`CatchPanicLayer`** added as the outermost layer. Handlers parse hostile
  iCalendar/vCard/EXIF/XML with hand-rolled byte slicing; unknown panics of this
  class should be 500s, not dropped connections. A global `TimeoutLayer` was
  deliberately **not** added — it would break large video streaming and chunked
  uploads.

### Two findings that did not survive verification

**"CRITICAL: no scope enforcement between mounts" — intentional, not a bug.**
The reviewer proved a `/dav/*` credential reaches CalDAV and CardDAV and rated it
a critical auth bypass. It is deliberate: `auth_test.rs` pins it with the comment
`// Issue #8: /dav/* scope should cover CalDAV since it's a DAV protocol`.

Shipping the "fix" would have broken calendar and contact sync on any device
using the credential `INSTALL.md` tells users to create.

The *implementation* was genuinely broken, though: the family rule was
implemented by passing the constant `"/dav/"` as the request path everywhere, so
authorization compared a constant against itself. The rule worked and nothing
narrower did — `/caldav/*` was rejected on its own mount and no credential could
be limited to one mount. Now the real request path is authorized and the family
rule is explicit in `scope_allows`. **Existing credentials keep working.**

Note `nest_service` strips the mount prefix, so `uri().path()` inside the CalDAV
router is `/admin/…`, not `/caldav/admin/…`; it has to be restored or every
mount-scoped credential fails.

**"DELETE /dav/files/photos wipes the photo index" — not exploitable.** Reported
CONFIRMED-BY-CODE. The dangerous `LIKE` branch is dead: the trash `rename` runs
first, so `is_dir()` is false by the time it is checked. The reviewer traced the
branch linearly and missed the earlier move. A real but lesser bug underneath
(orphaned child rows), fixed above.

### Test quality

A mutation test settled it: setting `RACY_WINDOW_NANOS = 0` — disabling the
racily-clean rule entirely — leaves all 43 + 49 tests green. The mechanism plan
§2.1 calls "the one subtle part" has **zero failing-capable coverage**;
`propfind_etag_changes_on_same_length_edit` passes on nanosecond-granularity
tmpfs because the mtime key alone catches the change. Forcing both writes into
one tick needs `filetime::set_file_mtime`.

Nine vacuous tests were named, including three in `auth.rs` that reimplement
`scope_allows` in the test body and assert on their own arithmetic. Every
security fix in this phase was verified by reverting it and watching the test go
red.

---

## 6.10 Deploy runbook

### Before upgrading

1. **Take a backup and verify it.** `restic` is an external binary
   (`tilde-backup/src/restic.rs` shells out to it, despite the README having
   claimed an embedded library). Nothing in this repo tests backup/restore — it is
   the only major path with no coverage, and the one needed if a migration goes
   wrong. Snapshot, then actually list the snapshot.
2. **Audit credentials.** `tilde auth app-password revoke <name>` previously
   matched on id only and **printed success while revoking nothing**. Anything
   believed revoked by name is still live:
   `tilde auth app-password list`
3. **Rotate MCP tokens** if any has ever left the machine. Before the `safe_join`
   fix, any MCP token could read arbitrary files the server process could open,
   including `tilde.db` and therefore every credential hash.

### Order matters

    tilde update                  # pull the new release first
    tilde reindex --type all      # migrates 009/010 AND warms the stat cache
    systemctl restart tilde

`tilde status` does **not** run migrations — `db::init_db` only sets PRAGMAs and
`status.rs` is not among the commands that migrate. Earlier guidance in this file
said otherwise and was wrong. `serve`, `init`, `usage`, `reindex` and `backup` all
migrate.

Running `reindex` before `update` only migrates against the *old* binary, which
is why `update` comes first.

### What to expect

- Migrations 009/010 are additive (`ADD COLUMN` ×2, one new table). Rollback is
  restoring the database copy.
- The first read of each file re-hashes it to populate the stat cache.
  `reindex --type all` pays that cost once, up front, including the photos mount.
- Rehearse first if you want certainty:
  `cargo build --release --no-default-features && ./scripts/rehearse-upgrade.sh`
  builds a populated pre-009 instance and exercises migration, stale-ETag healing,
  prune, merge, real mp4 range streaming, revocation and data integrity.

### Release gate

CI runs `cargo test --no-default-features` with `RUSTFLAGS: -D warnings`. A plain
`cargo test` does **not** reproduce that and will miss unused-variable errors that
fail the release build. Check with:

    RUSTFLAGS="-D warnings" cargo test --no-default-features
    cargo clippy --no-default-features -- -D warnings
    cargo fmt --check

Note CI's clippy does not pass `--all-targets`, so pre-existing lint failures in
test modules (`tilde-card`, `tilde-photos`) do not gate the release.

---

## 7. Phase 3 — Watcher and reindex

With Phase 1 landed these are optimizations and operational tools, not correctness fixes.

**3.2 and 3.3 are done; 3.1 is not.** See §6.1 below for what was built.

- **3.1 Watcher.** New `crates/tilde-dav/src/watcher.rs`, modeled on `crates/tilde-photos/src/watcher.rs` (`notify` crate, debounce map, background thread). Watches `files/` and `notes/`; refreshes the stat cache on change, removes rows on delete. Wire into `commands/serve.rs` beside the photo watcher at `:147`. Purpose: pre-warm hashes so PROPFIND never pays, and provide the event hook Phase 4 needs.
- **3.2 `tilde reindex files`.** `commands/reindex.rs` rebuilds only photos and links today. Add a mode that walks `files/` and `notes/`, upserts rows, prunes rows whose files are gone. Needed after a restic restore.
- **3.3 Cleanup.** `init.sh:82` creates `files/notes`, which nothing serves — `/dav/notes` maps to `data_dir/notes` (`server/src/lib.rs:51-66`). Remove the decoy. README fixes: it claims an embedded rustic-rs library but `tilde-backup/src/restic.rs:72` shells out to a `restic` binary; it lists `tilde-notes/` and `tilde-collections/` crates that do not exist; it references an absent `assets/` directory.

### 7.1 As built (3.2, 3.3)

`tilde_dav::reindex_tree(conn, root, db_prefix, prune) -> ReindexStats` walks a
tree and refreshes the stat cache, wired into `reindex --type files|notes|all`.
Covered by 8 unit tests in `tilde-dav`.

Two notes on the implementation:

1. **The ETag core was refactored to take `&Connection` rather than `&SharedDavState`**
   (`resolve_identity_conn`, `upsert_file_row_conn`), so the CLI and the server
   share one implementation instead of duplicating the hashing rules.

2. **Pruning needed a cross-mount guard, and it is load-bearing.** Every DAV mount
   writes into the one `files` table, distinguished only by a path prefix — and the
   files mount's prefix is the empty string. A naive "prune everything under my
   prefix" therefore treats every `photos/` and `notes/` row as an orphan and
   deletes it. `SIBLING_MOUNT_PREFIXES` skips them, and
   `reindex_tree_prune_does_not_touch_sibling_mounts` covers it — verified
   non-vacuous by removing the guard and watching the test fail. Without it,
   `reindex --type files --prune` would have wiped the photo and note indexes.

Also fixed: `init.sh` created a `files/notes` directory that nothing serves, and
the README claimed an embedded rustic-rs library, two crates that do not exist,
and an `assets/` directory that is absent.

---

## 8. Phase 4 — `sync-collection` REPORT (RFC 6578) for WebDAV

Unimplemented for WebDAV today, so clients diff the whole tree on every poll.

The `sync_changes` table already exists (`migrations/003_caldav_carddav.sql:70`) and
CalDAV already implements the pattern — use `tilde-cal/src/lib.rs:1048` as the reference.
Extend `collection_type` to cover `files`/`notes`, emit rows from the Phase 3 watcher and
from DAV writes, add the REPORT handler to the DAV router.

`LOCK`/`UNLOCK` (Class 2) stays unimplemented — 405 at `:202` is legal for Class 1. Add
only if a real client demands it.

---

## 9. What this unblocks

- **Gadgetbridge health ingest** — auto-exported SQLite lands in the synced files tree; the Phase 3 watcher triggers the parse. Needs its own narrow time-series table, **not** `records`: that table is UUID PK + `data_json` (~200 bytes of overhead per 12-byte sample) and its only index is on ingest time, not measurement time (`001_initial.sql:120-129`).
- **hledger** — journal files sync as-is. Split by period/source with `include` directives from day one so each writer owns its own file and concurrent-append conflicts become structurally impossible.
- **Outbound webhooks** — the Phase 3 event emission point plus a new sink in `tilde-notify`, which already abstracts ntfy/SMTP/Matrix/Signal.
- **Read-only dashboard** — subscribes to the same events. `rust-embed` is already a dependency (`Cargo.toml:97`).

---

## 10. Risks

- **First-run hashing cost.** Every file is hashed once after the migration. Noticeable on a large photo tree. Mitigation: let the Phase 3 watcher warm the cache in the background at startup, and keep hashing off the async runtime.
- **PROPFIND latency on wide directories.** Depth:1 stats every child. `stat` is cheap and hashing only happens on change, but measure on the real data set before shipping — especially the photos mount.
- **The racily-clean rule costs re-hashes.** Files modified in the last 2 seconds are always re-hashed. Harmless for notes; worth checking against a bulk photo import.
- **`hlc` is vestigial.** Every write sets it to a wall-clock string with no logical counter or node id (`dav/src/lib.rs:436`, `collections.rs:68`). This plan does not touch it. Either implement it properly or drop the column — HLC-shaped scaffolding with none of the semantics invites a future mistake.

---

## 11. Sequencing

Phase 0 → Phase 1 → **verify in real use for a few days** → Phase 3 → Phase 2 (if still needed) → Phase 4.

Phase 2 sits after Phase 3 deliberately: Phase 1 may resolve the practical problem, and
Phase 3 is what unblocks the features actually being asked for.
