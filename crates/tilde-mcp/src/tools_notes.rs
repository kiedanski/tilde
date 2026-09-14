//! notes MCP tools. See plan.md §8.
//!
//! Each domain module owns its tool definitions and execution, so the tool
//! surface can grow without every change colliding in `lib.rs`.
//!
//! The write paths here mirror the DAV layer: before any byte of an existing
//! note is destroyed, the outgoing content is copied into the content-addressed
//! version store (`<data_dir>/blobs/by-id`) so an overwrite or delete is always
//! recoverable. MCP must not become a side door that loses data the DAV PUT
//! path would have kept.

use crate::ToolDef;
use serde_json::{Value, json};
use std::path::{Component, Path, PathBuf};

/// Tool definitions contributed by this module.
pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "notes.create".into(),
            description: "Create a NEW note in the notes tree (`<data_dir>/notes`, the tree served \
                          at /dav/notes and searched by notes.search — a different tree from \
                          the files.* one). Fails with \"note already exists\" if a file is \
                          already there — it never overwrites; use notes.write to \
                          replace an existing note, or notes.append to add to one. Missing parent \
                          directories are created. Paths are relative to the notes root (e.g. \
                          'projects/ideas.md'); paths escaping the notes root are rejected. \
                          Returns {\"success\": true, \"path\": <path>, \"bytes\": <written>}. \
                          Requires notes:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'projects/ideas.md'). Must not already exist."},
                    "content": {"type": "string", "description": "Full content of the new note"}
                },
                "required": ["path", "content"]
            }),
        },
        ToolDef {
            name: "notes.write".into(),
            description: "Replace an EXISTING note's entire content, in the notes tree \
                          (`<data_dir>/notes`; files.* tools cannot reach it). The whole file is overwritten, \
                          not merged or appended — anything not included in `content` is gone from \
                          the current version. Fails with \"note not found\" if the note does not \
                          exist; use notes.create for a new note. The previous content is archived \
                          to the version store first, so the overwrite is recoverable. Paths are \
                          relative to the notes root (e.g. 'projects/ideas.md'); paths escaping the \
                          notes root are rejected. Returns {\"success\": true, \"path\": <path>, \
                          \"bytes\": <written>, \"archived_sha256\": <digest of the replaced \
                          content>}. Requires notes:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'projects/ideas.md'). Must already exist."},
                    "content": {"type": "string", "description": "Full replacement content — replaces the entire file"}
                },
                "required": ["path", "content"]
            }),
        },
        ToolDef {
            name: "notes.delete".into(),
            description: "Delete a note from the notes tree (`<data_dir>/notes`; use files.delete for \
                          the separate files tree). Fails with \"note not found\" if it does not exist, and \
                          refuses directories — it deletes a single note file only. The content is \
                          archived to the version store before removal, so the delete is \
                          recoverable. Paths are relative to the notes root (e.g. \
                          'projects/ideas.md'); paths escaping the notes root are rejected. \
                          Returns {\"success\": true, \"path\": <path>, \"archived_sha256\": \
                          <digest of the deleted content>}. Requires notes:write scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Note path relative to notes root (e.g. 'projects/ideas.md'). Must already exist."}
                },
                "required": ["path"]
            }),
        },
    ]
}

/// Execute a tool owned by this module. Returns `None` if `tool` is not ours.
///
/// `root` is the notes directory (`<data_dir>/notes`).
pub fn exec(tool: &str, root: &Path, params: &Value) -> Option<Result<Value, String>> {
    match tool {
        "notes.create" => Some(exec_notes_create(root, params)),
        "notes.write" => Some(exec_notes_write(root, params)),
        "notes.delete" => Some(exec_notes_delete(root, params)),
        _ => None,
    }
}

/// Required scope for a tool owned by this module, if any.
pub fn required_scope(tool: &str) -> Option<&'static str> {
    match tool {
        "notes.create" | "notes.write" | "notes.delete" => Some("notes:write"),
        _ => None,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Content-addressed version store for a given notes dir: `<data_dir>/blobs/by-id`.
fn blobs_root(notes_dir: &Path) -> PathBuf {
    notes_dir
        .parent()
        .map(|d| d.join("blobs").join("by-id"))
        .unwrap_or_else(|| PathBuf::from("blobs").join("by-id"))
}

/// Resolve a caller-supplied relative note path against the notes root.
///
/// `notes_dir.join(path)` alone is not a containment check: `join("../x")`
/// yields `<notes>/../x`, which still `starts_with(notes_dir)` because
/// `Path::starts_with` compares components without resolving `..`. So the path
/// is normalized lexically first, then checked with `starts_with` the way
/// `exec_notes_read` does.
fn resolve_note_path(notes_dir: &Path, path: &str) -> Result<PathBuf, String> {
    if path.is_empty() {
        return Err("path parameter required".into());
    }

    let mut full_path = notes_dir.to_path_buf();
    for component in Path::new(path).components() {
        match component {
            Component::Normal(part) => full_path.push(part),
            Component::CurDir => {}
            // An absolute path or a `..` would take us out of the notes tree.
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("path traversal not allowed".into());
            }
        }
    }

    // Belt and braces: the same containment check the read path performs.
    if !full_path.starts_with(notes_dir) {
        return Err("path traversal not allowed".into());
    }

    // Symlinks can escape a lexically-clean path, so verify the real location
    // of whatever parent directory already exists on disk.
    // Probe from the target itself, not its parent: a symlink *at* the requested
    // path would otherwise resolve outside the root and pass, and `fs::write`
    // follows symlinks.
    let existing_ancestor = full_path
        .ancestors()
        .find(|a| a.exists())
        .map(|a| a.to_path_buf());
    if let Some(ancestor) = existing_ancestor
        && let (Ok(real_ancestor), Ok(real_root)) =
            (ancestor.canonicalize(), notes_dir.canonicalize())
        && !real_ancestor.starts_with(&real_root)
    {
        return Err("path traversal not allowed".into());
    }

    Ok(full_path)
}

fn str_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("{} parameter required", key))
}

// ─── Tool implementations ────────────────────────────────────────────────

fn exec_notes_create(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = str_param(params, "path")?;
    let content = str_param(params, "content")?;

    let full_path = resolve_note_path(notes_dir, path)?;

    // Refuse to clobber: creating over an existing note would destroy content
    // with no archive and no warning.
    if full_path.exists() {
        return Err(format!("note already exists: {}", path));
    }

    if let Some(parent) = full_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }

    std::fs::write(&full_path, content.as_bytes()).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path,
        "bytes": content.len(),
    }))
}

fn exec_notes_write(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = str_param(params, "path")?;
    let content = str_param(params, "content")?;

    let full_path = resolve_note_path(notes_dir, path)?;

    if !full_path.is_file() {
        return Err(format!("note not found: {}", path));
    }

    // Archive the outgoing bytes before they are replaced, exactly as the DAV
    // PUT path does. If the archive fails the write does not happen.
    let archived = tilde_dav::versions::archive_version(&blobs_root(notes_dir), &full_path)
        .map_err(|e| format!("failed to archive previous version: {}", e))?;

    std::fs::write(&full_path, content.as_bytes()).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path,
        "bytes": content.len(),
        "archived_sha256": archived,
    }))
}

fn exec_notes_delete(notes_dir: &Path, params: &Value) -> Result<Value, String> {
    let path = str_param(params, "path")?;

    let full_path = resolve_note_path(notes_dir, path)?;

    if !full_path.exists() {
        return Err(format!("note not found: {}", path));
    }
    if !full_path.is_file() {
        return Err(format!("not a note: {}", path));
    }

    // Archive before removing so the delete stays recoverable.
    let archived = tilde_dav::versions::archive_version(&blobs_root(notes_dir), &full_path)
        .map_err(|e| format!("failed to archive previous version: {}", e))?;

    std::fs::remove_file(&full_path).map_err(|e| e.to_string())?;

    Ok(json!({
        "success": true,
        "path": path,
        "archived_sha256": archived,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns (tempdir, notes_dir). The notes dir sits under a data dir so
    /// `<data_dir>/blobs/by-id` is derivable, as it is in production.
    fn fixture() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let notes = dir.path().join("notes");
        std::fs::create_dir_all(&notes).unwrap();
        (dir, notes)
    }

    fn blob_exists(notes_dir: &Path, sha: &str) -> bool {
        tilde_dav::versions::blob_path(&blobs_root(notes_dir), sha).exists()
    }

    #[test]
    fn create_makes_a_file() {
        let (_d, notes) = fixture();
        let res = exec(
            "notes.create",
            &notes,
            &json!({"path": "a.md", "content": "# Hi"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(res["success"], json!(true));
        assert_eq!(res["bytes"], json!(4));
        assert_eq!(std::fs::read_to_string(notes.join("a.md")).unwrap(), "# Hi");
    }

    #[test]
    fn create_makes_parent_directories() {
        let (_d, notes) = fixture();
        exec(
            "notes.create",
            &notes,
            &json!({"path": "projects/deep/ideas.md", "content": "x"}),
        )
        .unwrap()
        .unwrap();
        assert!(notes.join("projects/deep/ideas.md").is_file());
    }

    #[test]
    fn create_on_existing_path_errors_and_keeps_content() {
        let (_d, notes) = fixture();
        std::fs::write(notes.join("a.md"), "original").unwrap();

        let err = exec(
            "notes.create",
            &notes,
            &json!({"path": "a.md", "content": "new"}),
        )
        .unwrap()
        .unwrap_err();
        assert!(err.contains("already exists"), "got: {err}");
        // The silent-overwrite failure mode: content must be untouched.
        assert_eq!(
            std::fs::read_to_string(notes.join("a.md")).unwrap(),
            "original"
        );
    }

    #[test]
    fn write_replaces_content() {
        let (_d, notes) = fixture();
        std::fs::write(notes.join("a.md"), "old long content").unwrap();

        let res = exec(
            "notes.write",
            &notes,
            &json!({"path": "a.md", "content": "new"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(res["success"], json!(true));
        assert_eq!(std::fs::read_to_string(notes.join("a.md")).unwrap(), "new");
    }

    #[test]
    fn write_on_missing_note_errors() {
        let (_d, notes) = fixture();
        let err = exec(
            "notes.write",
            &notes,
            &json!({"path": "nope.md", "content": "x"}),
        )
        .unwrap()
        .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
        assert!(!notes.join("nope.md").exists());
    }

    #[test]
    fn write_archives_previous_content() {
        let (_d, notes) = fixture();
        std::fs::write(notes.join("a.md"), "original").unwrap();

        let res = exec(
            "notes.write",
            &notes,
            &json!({"path": "a.md", "content": "replaced"}),
        )
        .unwrap()
        .unwrap();
        let sha = res["archived_sha256"].as_str().unwrap();
        assert!(blob_exists(&notes, sha), "blob {sha} missing");
        assert_eq!(
            tilde_dav::versions::read_version(&blobs_root(&notes), sha).unwrap(),
            b"original"
        );
    }

    #[test]
    fn delete_removes_the_note() {
        let (_d, notes) = fixture();
        std::fs::write(notes.join("a.md"), "bye").unwrap();

        let res = exec("notes.delete", &notes, &json!({"path": "a.md"}))
            .unwrap()
            .unwrap();
        assert_eq!(res["success"], json!(true));
        assert!(!notes.join("a.md").exists());
    }

    #[test]
    fn delete_archives_content_first() {
        let (_d, notes) = fixture();
        std::fs::write(notes.join("a.md"), "precious").unwrap();

        let res = exec("notes.delete", &notes, &json!({"path": "a.md"}))
            .unwrap()
            .unwrap();
        let sha = res["archived_sha256"].as_str().unwrap();
        assert!(blob_exists(&notes, sha), "blob {sha} missing");
        assert_eq!(
            tilde_dav::versions::read_version(&blobs_root(&notes), sha).unwrap(),
            b"precious"
        );
    }

    #[test]
    fn delete_on_missing_note_errors() {
        let (_d, notes) = fixture();
        let err = exec("notes.delete", &notes, &json!({"path": "nope.md"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("not found"), "got: {err}");
    }

    #[test]
    fn delete_refuses_directories() {
        let (_d, notes) = fixture();
        std::fs::create_dir(notes.join("sub")).unwrap();
        let err = exec("notes.delete", &notes, &json!({"path": "sub"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("not a note"), "got: {err}");
        assert!(notes.join("sub").is_dir());
    }

    #[test]
    fn path_traversal_is_rejected() {
        let (dir, notes) = fixture();
        let outside = dir.path().join("etc");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(outside.join("passwd"), "root:x:0:0").unwrap();

        for tool in ["notes.create", "notes.write", "notes.delete"] {
            for path in [
                "../etc/passwd",
                "../../etc/passwd",
                "/etc/passwd",
                "a/../../etc/passwd",
            ] {
                let err = exec(tool, &notes, &json!({"path": path, "content": "pwned"}))
                    .unwrap()
                    .unwrap_err();
                assert_eq!(err, "path traversal not allowed", "{tool} {path}");
            }
        }

        // Nothing outside the notes root was touched.
        assert_eq!(
            std::fs::read_to_string(outside.join("passwd")).unwrap(),
            "root:x:0:0"
        );
    }

    #[test]
    fn scopes_are_write() {
        for tool in ["notes.create", "notes.write", "notes.delete"] {
            assert_eq!(required_scope(tool), Some("notes:write"));
        }
        assert_eq!(required_scope("notes.read"), None);
    }

    #[test]
    fn exec_ignores_foreign_tools() {
        let (_d, notes) = fixture();
        assert!(exec("notes.read", &notes, &json!({"path": "a.md"})).is_none());
    }

    #[test]
    fn defs_cover_the_three_tools() {
        let names: Vec<String> = defs().into_iter().map(|d| d.name).collect();
        assert_eq!(names, vec!["notes.create", "notes.write", "notes.delete"]);
    }

    #[test]
    fn missing_params_error() {
        let (_d, notes) = fixture();
        let err = exec("notes.create", &notes, &json!({"content": "x"}))
            .unwrap()
            .unwrap_err();
        assert_eq!(err, "path parameter required");
        let err = exec("notes.create", &notes, &json!({"path": "a.md"}))
            .unwrap()
            .unwrap_err();
        assert_eq!(err, "content parameter required");
    }
}
