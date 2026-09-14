//! files MCP tools. See plan.md §8.
//!
//! Each domain module owns its tool definitions and execution, so the tool
//! surface can grow without every change colliding in `lib.rs`.
//!
//! This module owns the *write* half of the files surface (`files.write`,
//! `files.delete`, `files.mkdir`, `files.move`); the read half (`files.list`,
//! `files.read`, `files.search`) still lives in `lib.rs`.
//!
//! Anything that destroys bytes archives them first. The DAV layer copies the
//! outgoing contents of a file into the content-addressed blob store before a
//! PUT replaces it (see `tilde_dav::versions`), so nothing a client overwrites
//! is unrecoverable. MCP writes go through the same store: otherwise the tools
//! here would be a side door back into silent data loss.

use crate::ToolDef;
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};

/// Largest file `files.write` will accept, matching `files.read`'s read cap so
/// a file written through MCP can always be read back through MCP.
const MAX_WRITE_BYTES: usize = 1_048_576;

/// Tool definitions contributed by this module.
pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "files.write".into(),
            description: "Write a UTF-8 text file in the files tree (`<data_dir>/files`, the tree \
                 served at /dav/files — notes live in a separate tree, use notes.write there). \
                 Creates the file or replaces it in full. \
                 Paths are relative to the files root, e.g. \"docs/notes/todo.md\"; \
                 absolute paths and any path containing \"..\" are rejected. \
                 Missing parent directories are created. If the file already exists its \
                 entire previous content is replaced (this is not an append) — the \
                 replaced content is first archived to the version store and its digest \
                 is returned as archived_sha256, so the overwrite is recoverable. \
                 Fails if the path names an existing directory, or if content exceeds \
                 1MB (the same cap files.read enforces). \
                 Returns {path, bytes_written, created, archived_sha256}, where created \
                 is true when no file existed at the path and archived_sha256 is null \
                 unless something was replaced. Requires files:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File path relative to files root, e.g. \"docs/notes/todo.md\""},
                    "content": {"type": "string", "description": "Full new file content, UTF-8 text, max 1MB. Replaces any existing content."}
                },
                "required": ["path", "content"]
            }),
        },
        ToolDef {
            name: "files.delete".into(),
            description: "Delete a single file, or one empty directory, from the files tree \
                 (`<data_dir>/files`; notes.delete covers the separate notes tree). \
                 Paths are relative to the files root, e.g. \"docs/old-draft.md\"; \
                 absolute paths and any path containing \"..\" are rejected. \
                 A file's content is archived to the version store before removal and its \
                 digest returned as archived_sha256, so a deletion is recoverable. \
                 This is never recursive: deleting a directory that still contains \
                 anything (including dotfiles) fails with an error instead of destroying \
                 the tree — delete the contents first. Also fails if the path does not \
                 exist, or is the files root itself. \
                 Returns {path, deleted: \"file\"|\"directory\", archived_sha256} \
                 (archived_sha256 is null for a directory). Requires files:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "File or empty-directory path relative to files root, e.g. \"docs/old-draft.md\""}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "files.mkdir".into(),
            description:
                "Create a directory in the files tree (`<data_dir>/files`), including any \
                 missing parent directories. \
                 Paths are relative to the files root, e.g. \"projects/2026/photos\"; \
                 absolute paths and any path containing \"..\" are rejected. \
                 Idempotent: if the directory already exists this succeeds and reports \
                 created=false, changing nothing. Fails if a *file* already exists at the \
                 path. Never touches existing files. \
                 Returns {path, created}. Requires files:write scope."
                    .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Directory path relative to files root, e.g. \"projects/2026/photos\""}
                },
                "required": ["path"]
            }),
        },
        ToolDef {
            name: "files.move".into(),
            description: "Move or rename a file or directory within the files tree \
                 (`<data_dir>/files`). Both paths are relative to \
                 the files root, e.g. from \"inbox/scan.md\" to \"docs/scan.md\"; absolute \
                 paths and any path containing \"..\" are rejected on both sides, so \
                 nothing can be moved into or out of the files tree. \
                 Missing parent directories of the destination are created. \
                 Refuses to clobber: if anything already exists at the destination the \
                 move fails and nothing is changed — delete or rename that first. \
                 Also fails if the source does not exist, or if either path is the files \
                 root itself. Moving a directory moves its whole subtree. \
                 Returns {from, to, moved: \"file\"|\"directory\"}. \
                 Requires files:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Existing file or directory path relative to files root, e.g. \"inbox/scan.md\""},
                    "to": {"type": "string", "description": "New path relative to files root, e.g. \"docs/scan.md\". Must not already exist."}
                },
                "required": ["from", "to"]
            }),
        },
    ]
}

/// Execute a tool owned by this module. Returns `None` if `tool` is not ours.
///
/// `root` is the files directory (`<data_dir>/files`).
pub fn exec(tool: &str, root: &Path, params: &Value) -> Option<Result<Value, String>> {
    match tool {
        "files.write" => Some(exec_files_write(root, params)),
        "files.delete" => Some(exec_files_delete(root, params)),
        "files.mkdir" => Some(exec_files_mkdir(root, params)),
        "files.move" => Some(exec_files_move(root, params)),
        _ => None,
    }
}

/// Required scope for a tool owned by this module, if any.
pub fn required_scope(tool: &str) -> Option<&'static str> {
    match tool {
        "files.write" | "files.delete" | "files.mkdir" | "files.move" => Some("files:write"),
        _ => None,
    }
}

// ─── Path handling ───────────────────────────────────────────────────────

/// Resolve a client-supplied relative path against the files root.
///
/// Rejects absolute paths, `..` segments, and — for paths that survive that —
/// anything whose real location (after following symlinks) lands outside the
/// root. `Path::starts_with` compares components without normalising, so the
/// prefix check alone would happily accept `../../etc/passwd`; the component
/// scan is what actually closes that hole.
fn resolve(files_dir: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.trim().is_empty() {
        return Err("path parameter required".into());
    }
    for component in Path::new(rel).components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => return Err("path traversal not allowed".into()),
        }
    }

    let target = files_dir.join(rel);
    if !target.starts_with(files_dir) {
        return Err("path traversal not allowed".into());
    }
    if target == files_dir {
        return Err("path traversal not allowed".into());
    }

    // Symlink escape: check where the path (or its nearest existing ancestor,
    // for a path we are about to create) actually resolves to.
    let canon_root = files_dir
        .canonicalize()
        .map_err(|e| format!("files root unavailable: {}", e))?;
    let mut probe = target.clone();
    while !probe.exists() {
        if !probe.pop() {
            return Err("path traversal not allowed".into());
        }
    }
    let canon_probe = probe
        .canonicalize()
        .map_err(|_| "path traversal not allowed".to_string())?;
    if !canon_probe.starts_with(&canon_root) {
        return Err("path traversal not allowed".into());
    }

    Ok(target)
}

/// Content-addressed store of overwritten versions, shared with the DAV layer:
/// `<data_dir>/blobs/by-id`, alongside `<data_dir>/files`.
fn blobs_root(files_dir: &Path) -> Result<PathBuf, String> {
    files_dir
        .parent()
        .map(|p| p.join("blobs/by-id"))
        .ok_or_else(|| "cannot locate version store for files root".to_string())
}

/// Archive a file's current bytes before they are destroyed.
///
/// A failure here aborts the caller: losing the archive means losing the only
/// copy of the content that is about to be overwritten or deleted.
fn archive(files_dir: &Path, target: &Path) -> Result<String, String> {
    let blobs = blobs_root(files_dir)?;
    tilde_dav::versions::archive_version(&blobs, target)
        .map_err(|e| format!("failed to archive existing content, aborting: {}", e))
}

// ─── Tool implementations ────────────────────────────────────────────────

fn exec_files_write(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;
    let content = params
        .get("content")
        .and_then(|v| v.as_str())
        .ok_or("content parameter required")?;

    if content.len() > MAX_WRITE_BYTES {
        return Err(format!(
            "content too large ({} bytes, max 1MB)",
            content.len()
        ));
    }

    let target = resolve(files_dir, path)?;
    if target.is_dir() {
        return Err(format!("cannot write to a directory: {}", path));
    }

    let existed = target.exists();
    // Archive the outgoing bytes before they are replaced.
    let archived = if existed {
        Some(archive(files_dir, &target)?)
    } else {
        None
    };

    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&target, content).map_err(|e| e.to_string())?;

    Ok(json!({
        "path": path,
        "bytes_written": content.len(),
        "created": !existed,
        "archived_sha256": archived,
    }))
}

fn exec_files_delete(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let target = resolve(files_dir, path)?;
    if !target.exists() {
        return Err(format!("file not found: {}", path));
    }

    if target.is_dir() {
        let empty = std::fs::read_dir(&target)
            .map_err(|e| e.to_string())?
            .next()
            .is_none();
        if !empty {
            return Err(format!(
                "directory not empty: {} (delete its contents first; \
                 files.delete is never recursive)",
                path
            ));
        }
        std::fs::remove_dir(&target).map_err(|e| e.to_string())?;
        return Ok(json!({
            "path": path,
            "deleted": "directory",
            "archived_sha256": Value::Null,
        }));
    }

    // Archive before the only copy goes away.
    let archived = archive(files_dir, &target)?;
    std::fs::remove_file(&target).map_err(|e| e.to_string())?;

    Ok(json!({
        "path": path,
        "deleted": "file",
        "archived_sha256": archived,
    }))
}

fn exec_files_mkdir(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = params
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or("path parameter required")?;

    let target = resolve(files_dir, path)?;
    if target.is_dir() {
        return Ok(json!({"path": path, "created": false}));
    }
    if target.exists() {
        return Err(format!("a file already exists at: {}", path));
    }

    std::fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    Ok(json!({"path": path, "created": true}))
}

fn exec_files_move(files_dir: &Path, params: &Value) -> Result<Value, String> {
    let from = params
        .get("from")
        .and_then(|v| v.as_str())
        .ok_or("from parameter required")?;
    let to = params
        .get("to")
        .and_then(|v| v.as_str())
        .ok_or("to parameter required")?;

    // Both ends are client-supplied, so both are validated.
    let src = resolve(files_dir, from)?;
    let dest = resolve(files_dir, to)?;

    if !src.exists() {
        return Err(format!("file not found: {}", from));
    }
    if dest.exists() {
        return Err(format!(
            "destination already exists: {} (delete or rename it first)",
            to
        ));
    }

    let kind = if src.is_dir() { "directory" } else { "file" };

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::rename(&src, &dest).map_err(|e| e.to_string())?;

    Ok(json!({"from": from, "to": to, "moved": kind}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A files root with its sibling blob store, as laid out under `data_dir`.
    fn setup() -> (tempfile::TempDir, PathBuf, PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let files = tmp.path().join("files");
        std::fs::create_dir_all(&files).unwrap();
        let blobs = tmp.path().join("blobs/by-id");
        (tmp, files, blobs)
    }

    fn ok(v: Option<Result<Value, String>>) -> Value {
        v.expect("tool not routed").expect("tool returned error")
    }

    fn err(v: Option<Result<Value, String>>) -> String {
        v.expect("tool not routed").expect_err("expected an error")
    }

    #[test]
    fn scopes_and_routing() {
        for tool in ["files.write", "files.delete", "files.mkdir", "files.move"] {
            assert_eq!(required_scope(tool), Some("files:write"), "{}", tool);
        }
        assert_eq!(required_scope("files.read"), None);
        let names: Vec<String> = defs().into_iter().map(|d| d.name).collect();
        assert_eq!(
            names,
            vec!["files.write", "files.delete", "files.mkdir", "files.move"]
        );

        let (_tmp, files, _blobs) = setup();
        assert!(exec("files.read", &files, &json!({})).is_none());
    }

    #[test]
    fn write_creates_file_and_parents() {
        let (_tmp, files, _blobs) = setup();
        let res = ok(exec(
            "files.write",
            &files,
            &json!({"path": "a/b/note.md", "content": "hello"}),
        ));
        assert_eq!(res["created"], json!(true));
        assert_eq!(res["bytes_written"], json!(5));
        assert_eq!(res["archived_sha256"], Value::Null);
        assert_eq!(
            std::fs::read_to_string(files.join("a/b/note.md")).unwrap(),
            "hello"
        );
    }

    #[test]
    fn write_replaces_and_archives_prior_content() {
        let (_tmp, files, blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "note.md", "content": "version one"}),
        ));
        let res = ok(exec(
            "files.write",
            &files,
            &json!({"path": "note.md", "content": "version two"}),
        ));

        assert_eq!(res["created"], json!(false));
        assert_eq!(
            std::fs::read_to_string(files.join("note.md")).unwrap(),
            "version two"
        );

        let sha = res["archived_sha256"].as_str().expect("archived digest");
        assert!(
            tilde_dav::versions::blob_path(&blobs, sha).exists(),
            "blob missing at {:?}",
            tilde_dav::versions::blob_path(&blobs, sha)
        );
        assert_eq!(
            tilde_dav::versions::read_version(&blobs, sha).unwrap(),
            b"version one".to_vec(),
            "archived bytes should be the replaced content"
        );
    }

    #[test]
    fn write_rejects_oversized_content() {
        let (_tmp, files, _blobs) = setup();
        let big = "x".repeat(MAX_WRITE_BYTES + 1);
        let msg = err(exec(
            "files.write",
            &files,
            &json!({"path": "big.txt", "content": big}),
        ));
        assert!(msg.contains("too large"), "{}", msg);
        assert!(msg.contains("1MB"), "{}", msg);
        assert!(!files.join("big.txt").exists());
    }

    #[test]
    fn write_rejects_directory_target() {
        let (_tmp, files, _blobs) = setup();
        std::fs::create_dir(files.join("dir")).unwrap();
        let msg = err(exec(
            "files.write",
            &files,
            &json!({"path": "dir", "content": "x"}),
        ));
        assert!(msg.contains("directory"), "{}", msg);
    }

    #[test]
    fn write_rejects_path_traversal() {
        let (_tmp, files, _blobs) = setup();
        for path in ["../etc/passwd", "a/../../etc/passwd", "/etc/passwd"] {
            let msg = err(exec(
                "files.write",
                &files,
                &json!({"path": path, "content": "pwned"}),
            ));
            assert_eq!(msg, "path traversal not allowed", "for {}", path);
        }
        assert!(!files.parent().unwrap().join("etc/passwd").exists());
    }

    #[test]
    fn delete_removes_file_and_archives_it() {
        let (_tmp, files, blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "doomed.md", "content": "keep me somewhere"}),
        ));

        let res = ok(exec("files.delete", &files, &json!({"path": "doomed.md"})));
        assert_eq!(res["deleted"], json!("file"));
        assert!(!files.join("doomed.md").exists());

        let sha = res["archived_sha256"].as_str().expect("archived digest");
        assert!(tilde_dav::versions::blob_path(&blobs, sha).exists());
        assert_eq!(
            tilde_dav::versions::read_version(&blobs, sha).unwrap(),
            b"keep me somewhere".to_vec()
        );
    }

    #[test]
    fn delete_refuses_non_empty_directory() {
        let (_tmp, files, _blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "project/file.md", "content": "data"}),
        ));

        let msg = err(exec("files.delete", &files, &json!({"path": "project"})));
        assert!(msg.contains("not empty"), "{}", msg);
        assert!(files.join("project/file.md").exists(), "tree survived");
    }

    #[test]
    fn delete_removes_empty_directory() {
        let (_tmp, files, _blobs) = setup();
        std::fs::create_dir(files.join("empty")).unwrap();
        let res = ok(exec("files.delete", &files, &json!({"path": "empty"})));
        assert_eq!(res["deleted"], json!("directory"));
        assert!(!files.join("empty").exists());
    }

    #[test]
    fn delete_missing_path_errors() {
        let (_tmp, files, _blobs) = setup();
        let msg = err(exec("files.delete", &files, &json!({"path": "nope.md"})));
        assert!(msg.contains("not found"), "{}", msg);
    }

    #[test]
    fn mkdir_creates_nested_and_is_idempotent() {
        let (_tmp, files, _blobs) = setup();
        let res = ok(exec("files.mkdir", &files, &json!({"path": "a/b/c"})));
        assert_eq!(res["created"], json!(true));
        assert!(files.join("a/b/c").is_dir());

        let again = ok(exec("files.mkdir", &files, &json!({"path": "a/b/c"})));
        assert_eq!(again["created"], json!(false));

        ok(exec(
            "files.write",
            &files,
            &json!({"path": "a/file.md", "content": "x"}),
        ));
        let msg = err(exec("files.mkdir", &files, &json!({"path": "a/file.md"})));
        assert!(msg.contains("file already exists"), "{}", msg);
    }

    #[test]
    fn move_renames_file() {
        let (_tmp, files, _blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "inbox/scan.md", "content": "scanned"}),
        ));

        let res = ok(exec(
            "files.move",
            &files,
            &json!({"from": "inbox/scan.md", "to": "docs/2026/scan.md"}),
        ));
        assert_eq!(res["moved"], json!("file"));
        assert!(!files.join("inbox/scan.md").exists());
        assert_eq!(
            std::fs::read_to_string(files.join("docs/2026/scan.md")).unwrap(),
            "scanned"
        );
    }

    #[test]
    fn move_renames_directory_and_refuses_clobber() {
        let (_tmp, files, _blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "old/file.md", "content": "a"}),
        ));
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "taken.md", "content": "precious"}),
        ));

        let res = ok(exec(
            "files.move",
            &files,
            &json!({"from": "old", "to": "new"}),
        ));
        assert_eq!(res["moved"], json!("directory"));
        assert!(files.join("new/file.md").exists());

        let msg = err(exec(
            "files.move",
            &files,
            &json!({"from": "new/file.md", "to": "taken.md"}),
        ));
        assert!(msg.contains("already exists"), "{}", msg);
        assert_eq!(
            std::fs::read_to_string(files.join("taken.md")).unwrap(),
            "precious",
            "destination untouched"
        );
        assert!(files.join("new/file.md").exists(), "source untouched");
    }

    #[test]
    fn move_rejects_traversal_on_either_side() {
        let (_tmp, files, _blobs) = setup();
        ok(exec(
            "files.write",
            &files,
            &json!({"path": "ok.md", "content": "data"}),
        ));
        let outside = files.parent().unwrap().join("etc");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("passwd"), "root:x:0:0").unwrap();

        let msg = err(exec(
            "files.move",
            &files,
            &json!({"from": "ok.md", "to": "../etc/passwd"}),
        ));
        assert_eq!(msg, "path traversal not allowed");
        assert_eq!(
            std::fs::read_to_string(outside.join("passwd")).unwrap(),
            "root:x:0:0"
        );
        assert!(files.join("ok.md").exists());

        let msg = err(exec(
            "files.move",
            &files,
            &json!({"from": "../etc/passwd", "to": "stolen.md"}),
        ));
        assert_eq!(msg, "path traversal not allowed");
        assert!(!files.join("stolen.md").exists());
    }

    #[test]
    fn root_itself_is_not_a_target() {
        let (_tmp, files, _blobs) = setup();
        for path in ["", "."] {
            assert!(
                exec("files.delete", &files, &json!({"path": path}))
                    .unwrap()
                    .is_err()
            );
        }
    }
}
