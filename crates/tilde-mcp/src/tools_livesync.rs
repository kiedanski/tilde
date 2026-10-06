//! MCP notes backed by the same CouchDB vault as Obsidian LiveSync.

use crate::ToolDef;
use serde_json::{Value, json};
use std::path::Path;
use tilde_livesync::Client;

pub fn configure_definitions(tools: &mut [ToolDef]) {
    for tool in tools {
        match tool.name.as_str() {
            "notes.search" => {
                tool.description = "Keyword search over Markdown notes in the configured LiveSync CouchDB vault. Matching ignores case and accents (\"cafe\" finds \"café\"). Every word must match unless joined by OR. Syntax: \"exact phrase\", prefix* (nutri* finds nutrition), -word to exclude, a OR b. Words match whole tokens, so use prefix* for partial words. Optional `path` limits results to notes whose path starts with it (e.g. \"journal/\"). Results are ranked best first, weighting title and path matches above body text: [{path, title, modified, snippet}], where snippet shows the match between « and ». An empty array means nothing matched. Requires notes:read scope.".into();
                tool.input_schema = json!({"type":"object","properties":{
                    "query":{"type":"string"},
                    "path":{"type":"string","description":"Only notes whose path starts with this prefix"},
                    "limit":{"type":"integer","minimum":1,"maximum":100}
                },"required":["query"]});
            }
            "notes.read" => {
                tool.description = "Read a Markdown note from the configured LiveSync CouchDB vault. Returns content and metadata including the revision needed for notes.write or notes.delete. Requires notes:read scope.".into();
            }
            "notes.create" => {
                tool.description = "Create a new Markdown note in the configured LiveSync CouchDB vault. Fails if it already exists. Returns the new revision. Requires notes:write scope.".into();
            }
            "notes.write" => {
                tool.description = "Replace a Markdown note in the configured LiveSync CouchDB vault only if its revision still matches the one returned by notes.read. Archives the previous content locally first. A concurrent Obsidian edit causes a conflict error. Returns the new revision and archive digest. Requires notes:write scope.".into();
                tool.input_schema = json!({"type":"object","properties":{
                    "path":{"type":"string"},"content":{"type":"string"},"revision":{"type":"string"}
                },"required":["path","content","revision"]});
            }
            "notes.append" => {
                tool.description = "Append text to an existing Markdown note in the configured LiveSync CouchDB vault. Archives the previous content locally and rejects a concurrent change. Returns the new revision and archive digest. Requires notes:write scope.".into();
            }
            "notes.delete" => {
                tool.description = "Soft-delete a Markdown note in the configured LiveSync CouchDB vault only if its revision still matches the one returned by notes.read. Archives the content locally first. Returns the deletion revision and archive digest. Requires notes:write scope.".into();
                tool.input_schema = json!({"type":"object","properties":{
                    "path":{"type":"string"},"revision":{"type":"string"}
                },"required":["path","revision"]});
            }
            _ => {}
        }
    }
}

fn str_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    params
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{key} parameter required"))
}

pub(crate) fn title(path: &str, content: &str) -> String {
    content
        .lines()
        .find_map(|line| line.strip_prefix("# "))
        .map(str::to_owned)
        .unwrap_or_else(|| {
            let filename = path.rsplit('/').next().unwrap_or(path);
            filename.strip_suffix(".md").unwrap_or(filename).to_owned()
        })
}

pub(crate) fn modified_iso(ms: i64) -> String {
    jiff::Timestamp::from_second(ms.div_euclid(1000))
        .unwrap_or(jiff::Timestamp::UNIX_EPOCH)
        .strftime("%Y-%m-%dT%H:%M:%SZ")
        .to_string()
}

pub async fn exec(
    client: &Client,
    blobs_root: &Path,
    tool: &str,
    params: &Value,
) -> Result<Value, String> {
    match tool {
        "notes.read" => {
            let path = str_param(params, "path")?;
            let note = client
                .get_note(path)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("note not found: {path}"))?;
            let note_title = title(&note.path, &note.content);
            Ok(json!({
                "content": note.content,
                "metadata": {
                    "title": note_title,
                    "path": note.path,
                    "modified": modified_iso(note.modified_ms),
                    "revision": note.revision,
                }
            }))
        }
        "notes.create" => {
            let path = str_param(params, "path")?;
            let content = str_param(params, "content")?;
            let saved = client
                .put_note(path, content, None)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({"success":true,"path":path,"bytes":content.len(),"revision":saved.revision}))
        }
        "notes.write" => {
            let path = str_param(params, "path")?;
            let content = str_param(params, "content")?;
            let revision = str_param(params, "revision")?;
            let outgoing = client
                .get_note(path)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("note not found: {path}"))?;
            if outgoing.revision != revision {
                return Err(
                    "note changed since it was read; fetch its latest revision and retry".into(),
                );
            }
            let archived =
                tilde_dav::versions::archive_bytes(blobs_root, outgoing.content.as_bytes())
                    .map_err(|e| format!("failed to archive previous version: {e}"))?;
            let saved = client
                .put_note(path, content, Some(revision))
                .await
                .map_err(|e| e.to_string())?;
            Ok(
                json!({"success":true,"path":path,"bytes":content.len(),"revision":saved.revision,"archived_sha256":archived}),
            )
        }
        "notes.append" => {
            let path = str_param(params, "path")?;
            let content = str_param(params, "content")?;
            let note = client
                .get_note(path)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("note not found: {path}"))?;
            let archived = tilde_dav::versions::archive_bytes(blobs_root, note.content.as_bytes())
                .map_err(|e| format!("failed to archive previous version: {e}"))?;
            let mut combined = note.content;
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(content);
            let saved = client
                .put_note(path, &combined, Some(&note.revision))
                .await
                .map_err(|e| e.to_string())?;
            Ok(
                json!({"success":true,"path":path,"revision":saved.revision,"archived_sha256":archived}),
            )
        }
        "notes.delete" => {
            let path = str_param(params, "path")?;
            let revision = str_param(params, "revision")?;
            let outgoing = client
                .get_note(path)
                .await
                .map_err(|e| e.to_string())?
                .ok_or_else(|| format!("note not found: {path}"))?;
            if outgoing.revision != revision {
                return Err(
                    "note changed since it was read; fetch its latest revision and retry".into(),
                );
            }
            let archived =
                tilde_dav::versions::archive_bytes(blobs_root, outgoing.content.as_bytes())
                    .map_err(|e| format!("failed to archive previous version: {e}"))?;
            let deleted = client
                .delete_note(path, revision)
                .await
                .map_err(|e| e.to_string())?;
            Ok(json!({"success":true,"path":path,"revision":deleted,"archived_sha256":archived}))
        }
        _ => Err(format!("unknown tool: {tool}")),
    }
}
