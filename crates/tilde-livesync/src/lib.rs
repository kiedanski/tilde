//! Read and write unencrypted Self-hosted LiveSync notes in CouchDB.
//!
//! LiveSync's CouchDB is the durable store. This crate interprets its note and
//! chunk documents; it does not implement CouchDB replication or write into a
//! vault. Writes use CouchDB revisions to reject concurrent updates.

mod setup_uri;
pub use setup_uri::{SetupUri, generate_setup_uri};

use reqwest::{StatusCode, Url};
use serde::Deserialize;
use serde_json::{Value, json};
use std::time::{SystemTime, UNIX_EPOCH};
use xxhash_rust::xxh64::xxh64;

const CHUNK_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid CouchDB URL or database name")]
    InvalidUrl,
    #[error("invalid note path")]
    InvalidPath,
    #[error("note already exists")]
    AlreadyExists,
    #[error("note not found")]
    NotFound,
    #[error("note changed since it was read; fetch its latest revision and retry")]
    Conflict,
    #[error(
        "note has unresolved CouchDB revision conflicts; resolve them in Obsidian before writing"
    )]
    UnresolvedConflict,
    #[error("CouchDB request failed: {0}")]
    Http(#[from] reqwest::Error),
    #[error("LiveSync document has an unsupported or malformed format: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Note {
    pub path: String,
    pub content: String,
    pub revision: String,
    pub modified_ms: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteMeta {
    pub path: String,
    pub revision: String,
    pub modified_ms: i64,
}

#[derive(Clone)]
pub struct Client {
    http: reqwest::Client,
    database_url: Url,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct AllDocs {
    rows: Vec<AllDocsRow>,
}

#[derive(Deserialize)]
struct AllDocsRow {
    doc: Option<Value>,
}

#[derive(Deserialize)]
struct PutResponse {
    id: String,
    rev: String,
}

impl Client {
    /// `server_url` is the CouchDB origin (it may include a reverse-proxy path).
    pub fn new(
        server_url: &str,
        database: &str,
        username: &str,
        password: &str,
    ) -> Result<Self, Error> {
        if database.is_empty() || database.contains(['/', '?', '#']) {
            return Err(Error::InvalidUrl);
        }
        let mut database_url = Url::parse(server_url).map_err(|_| Error::InvalidUrl)?;
        if !matches!(database_url.scheme(), "http" | "https")
            || database_url.host_str().is_none()
            || database_url.query().is_some()
            || database_url.fragment().is_some()
        {
            return Err(Error::InvalidUrl);
        }
        database_url
            .path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?
            .pop_if_empty()
            .push(database);
        Ok(Self {
            http: reqwest::Client::new(),
            database_url,
            username: username.into(),
            password: password.into(),
        })
    }

    fn document_url(&self, id: &str) -> Result<Url, Error> {
        let mut url = self.database_url.clone();
        url.path_segments_mut()
            .map_err(|_| Error::InvalidUrl)?
            .push(id);
        Ok(url)
    }

    /// Match LiveSync's unobfuscated, case-insensitive `path2id_base` mapping.
    /// CouchDB reserves IDs beginning with `_`, so LiveSync prefixes `/`.
    fn note_id(path: &str) -> String {
        let lower = path.to_lowercase();
        if lower.starts_with('_') {
            format!("/{lower}")
        } else {
            lower
        }
    }

    /// Create the configured CouchDB database explicitly. Returns `false` if
    /// it already exists. A restricted database member may use this to check a
    /// database which an administrator has already provisioned.
    pub async fn create_database(&self) -> Result<bool, Error> {
        let existing = self
            .http
            .get(self.database_url.clone())
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        if existing.status().is_success() {
            return Ok(false);
        }
        if existing.status() != StatusCode::NOT_FOUND {
            existing.error_for_status()?;
        }
        let response = self
            .http
            .put(self.database_url.clone())
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        if response.status() == StatusCode::PRECONDITION_FAILED {
            return Ok(false);
        }
        response.error_for_status()?;
        Ok(true)
    }

    /// Seed LiveSync's version document without touching any existing notes.
    /// The supported format is pinned to the version used by LiveSync 1.0.30.
    pub async fn ensure_version_document(&self) -> Result<(), Error> {
        const ID: &str = "obsydian_livesync_version";
        if let Some(document) = self.document(ID).await? {
            if document.get("type").and_then(Value::as_str) == Some("versioninfo")
                && document.get("version").and_then(Value::as_i64) == Some(12)
            {
                return Ok(());
            }
            return Err(Error::Unsupported(
                "incompatible LiveSync database version".into(),
            ));
        }
        match self
            .put_document(
                ID,
                &json!({"_id": ID, "type": "versioninfo", "version": 12}),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(Error::Conflict) => {
                let document = self.document(ID).await?;
                if document
                    .as_ref()
                    .and_then(|doc| doc.get("version"))
                    .and_then(Value::as_i64)
                    == Some(12)
                    && document
                        .as_ref()
                        .and_then(|doc| doc.get("type"))
                        .and_then(Value::as_str)
                        == Some("versioninfo")
                {
                    Ok(())
                } else {
                    Err(Error::Unsupported(
                        "incompatible LiveSync database version".into(),
                    ))
                }
            }
            Err(error) => Err(error),
        }
    }

    async fn document(&self, id: &str) -> Result<Option<Value>, Error> {
        let url = self.document_url(id)?;
        let response = self
            .http
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(response.error_for_status()?.json().await?))
    }

    async fn document_with_conflicts(&self, id: &str) -> Result<Option<Value>, Error> {
        let mut url = self.document_url(id)?;
        url.query_pairs_mut().append_pair("conflicts", "true");
        let response = self
            .http
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        Ok(Some(response.error_for_status()?.json().await?))
    }

    async fn put_document(&self, id: &str, document: &Value) -> Result<String, Error> {
        let response = self
            .http
            .put(self.document_url(id)?)
            .basic_auth(&self.username, Some(&self.password))
            .json(document)
            .send()
            .await?;
        if response.status() == StatusCode::CONFLICT {
            return Err(Error::Conflict);
        }
        let saved: PutResponse = response.error_for_status()?.json().await?;
        if saved.id != id || saved.rev.is_empty() {
            return Err(Error::Unsupported(format!(
                "invalid CouchDB response for {id}"
            )));
        }
        Ok(saved.rev)
    }

    /// Return the current note revision without fetching chunks.
    pub async fn get_note_meta(&self, path: &str) -> Result<Option<NoteMeta>, Error> {
        validate_path(path)?;
        let Some(doc) = self.document(&Self::note_id(path)).await? else {
            return Ok(None);
        };
        let meta = note_meta(&doc)?;
        if let Some(meta) = &meta
            && meta.path != path
        {
            return Err(Error::Unsupported(format!("path mismatch for {path}")));
        }
        Ok(meta)
    }

    /// Save a Markdown note. `expected_revision = None` creates a new note only;
    /// `Some(rev)` replaces only that exact revision. A concurrent Obsidian edit
    /// returns `Conflict`, so the caller can re-read and reconcile the content.
    pub async fn put_note(
        &self,
        path: &str,
        content: &str,
        expected_revision: Option<&str>,
    ) -> Result<NoteMeta, Error> {
        validate_write_path(path)?;
        let id = Self::note_id(path);
        let existing = self.document_with_conflicts(&id).await?;
        if let Some(doc) = &existing {
            ensure_writable_doc(doc, path)?;
            if doc
                .get("_conflicts")
                .and_then(Value::as_array)
                .is_some_and(|conflicts| !conflicts.is_empty())
            {
                return Err(Error::UnresolvedConflict);
            }
        }
        let existing_revision = existing
            .as_ref()
            .and_then(|doc| doc.get("_rev"))
            .and_then(Value::as_str);
        match expected_revision {
            Some(rev) if rev.is_empty() || existing_revision != Some(rev) => {
                return Err(Error::Conflict);
            }
            None if existing.as_ref().is_some_and(|doc| !is_deleted(doc)) => {
                return Err(Error::AlreadyExists);
            }
            _ => {}
        }

        let chunks = split_chunks(content);
        let mut children = Vec::with_capacity(chunks.len());
        for piece in chunks {
            let id = chunk_id(piece);
            let chunk = json!({"_id": id, "data": piece, "type": "leaf"});
            match self.put_document(&id, &chunk).await {
                Ok(_) => {}
                Err(Error::Conflict) => {
                    let stored = self.document(&id).await?.ok_or_else(|| {
                        Error::Unsupported(format!("missing conflicted chunk {id}"))
                    })?;
                    if stored.get("type").and_then(Value::as_str) != Some("leaf")
                        || stored.get("data").and_then(Value::as_str) != Some(piece)
                    {
                        return Err(Error::Unsupported(format!("chunk hash collision: {id}")));
                    }
                }
                Err(error) => return Err(error),
            }
            children.push(id);
        }

        let now = now_ms()?;
        let ctime = existing
            .as_ref()
            .and_then(|doc| doc.get("ctime"))
            .and_then(Value::as_i64)
            .unwrap_or(now);
        let mut note = json!({
            "_id": id,
            "children": children,
            "path": path,
            "ctime": ctime,
            "mtime": now,
            "size": content.len(),
            "type": "plain",
            "eden": {},
        });
        if let Some(rev) = existing_revision {
            note["_rev"] = Value::String(rev.into());
        }
        let revision = self.put_document(&id, &note).await?;
        Ok(NoteMeta {
            path: path.into(),
            revision,
            modified_ms: now,
        })
    }

    /// Soft-delete a note at the revision last observed by the caller.
    pub async fn delete_note(&self, path: &str, expected_revision: &str) -> Result<String, Error> {
        validate_write_path(path)?;
        let id = Self::note_id(path);
        let mut doc = self
            .document_with_conflicts(&id)
            .await?
            .ok_or(Error::NotFound)?;
        if doc
            .get("_conflicts")
            .and_then(Value::as_array)
            .is_some_and(|conflicts| !conflicts.is_empty())
        {
            return Err(Error::UnresolvedConflict);
        }
        if is_deleted(&doc) {
            return Err(Error::NotFound);
        }
        if expected_revision.is_empty()
            || doc.get("_rev").and_then(Value::as_str) != Some(expected_revision)
        {
            return Err(Error::Conflict);
        }
        ensure_writable_doc(&doc, path)?;
        let meta = note_meta(&doc)?.ok_or_else(|| Error::Unsupported(path.into()))?;
        if meta.path != path {
            return Err(Error::Unsupported(format!("path mismatch for {path}")));
        }
        doc["deleted"] = Value::Bool(true);
        doc["mtime"] = json!(now_ms()?);
        self.put_document(&id, &doc).await
    }

    /// Read one note. A missing or logically deleted note returns `None`.
    pub async fn get_note(&self, path: &str) -> Result<Option<Note>, Error> {
        validate_path(path)?;
        let Some(doc) = self.document(&Self::note_id(path)).await? else {
            return Ok(None);
        };
        if doc.get("deleted").and_then(Value::as_bool) == Some(true)
            || doc.get("_deleted").and_then(Value::as_bool) == Some(true)
        {
            return Ok(None);
        }
        let meta = note_meta(&doc)?.ok_or_else(|| Error::Unsupported(path.into()))?;
        if meta.path != path {
            return Err(Error::Unsupported(format!("path mismatch for {path}")));
        }
        let children = doc
            .get("children")
            .and_then(Value::as_array)
            .ok_or_else(|| Error::Unsupported(format!("missing children for {path}")))?;
        let mut chunk_docs = Vec::new();
        let eden = doc.get("eden").and_then(Value::as_object);
        for child in children {
            let id = child
                .as_str()
                .ok_or_else(|| Error::Unsupported(format!("invalid child for {path}")))?;
            if id.starts_with("h:+") {
                return Err(Error::Unsupported("encrypted chunks".into()));
            }
            let chunk = match eden.and_then(|e| e.get(id)) {
                Some(chunk) => chunk.clone(),
                None => self
                    .document(id)
                    .await?
                    .ok_or_else(|| Error::Unsupported(format!("missing chunk {id}")))?,
            };
            chunk_docs.push(chunk);
        }
        let content = assemble_content(&doc, &chunk_docs, path)?;
        Ok(Some(Note {
            path: meta.path,
            content,
            revision: meta.revision,
            modified_ms: meta.modified_ms,
        }))
    }

    /// Enumerate note metadata. System documents and chunk documents are skipped.
    pub async fn list_notes(&self) -> Result<Vec<NoteMeta>, Error> {
        let mut url = self.document_url("_all_docs")?;
        url.query_pairs_mut().append_pair("include_docs", "true");
        let response = self
            .http
            .get(url)
            .basic_auth(&self.username, Some(&self.password))
            .send()
            .await?
            .error_for_status()?;
        let rows: AllDocs = response.json().await?;
        let mut notes = Vec::new();
        for row in rows.rows {
            if let Some(doc) = row.doc
                && let Some(meta) = note_meta(&doc)?
            {
                notes.push(meta);
            }
        }
        notes.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(notes)
    }
}

fn validate_path(path: &str) -> Result<(), Error> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains(':')
        || path
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn validate_write_path(path: &str) -> Result<(), Error> {
    validate_path(path)?;
    if !path.ends_with(".md") || path.starts_with('.') {
        return Err(Error::InvalidPath);
    }
    Ok(())
}

fn is_deleted(doc: &Value) -> bool {
    doc.get("deleted").and_then(Value::as_bool) == Some(true)
        || doc.get("_deleted").and_then(Value::as_bool) == Some(true)
}

fn ensure_writable_doc(doc: &Value, path: &str) -> Result<(), Error> {
    if doc.get("type").and_then(Value::as_str) != Some("plain")
        || doc.get("path").and_then(Value::as_str) != Some(path)
        || doc.get("e_").is_some()
        || doc
            .get("children")
            .and_then(Value::as_array)
            .is_none_or(|children| {
                children
                    .iter()
                    .any(|child| child.as_str().is_none_or(|id| id.starts_with("h:+")))
            })
    {
        return Err(Error::Unsupported(format!(
            "cannot write incompatible note {path}"
        )));
    }
    Ok(())
}

fn now_ms() -> Result<i64, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Unsupported("system clock precedes Unix epoch".into()))?;
    i64::try_from(elapsed.as_millis())
        .map_err(|_| Error::Unsupported("system clock is out of range".into()))
}

fn split_chunks(content: &str) -> Vec<&str> {
    if content.is_empty() {
        return Vec::new();
    }
    let mut chunks = Vec::new();
    let mut start = 0;
    for (index, character) in content.char_indices() {
        if index - start + character.len_utf8() > CHUNK_BYTES {
            chunks.push(&content[start..index]);
            start = index;
        }
    }
    chunks.push(&content[start..]);
    chunks
}

fn chunk_id(content: &str) -> String {
    // LiveSync's default xxhash64 input includes the JavaScript UTF-16 length.
    let length = content.encode_utf16().count();
    let hash = xxh64(format!("{content}-{length}").as_bytes(), 0);
    format!("h:{}", base36(hash))
}

fn base36(mut number: u64) -> String {
    if number == 0 {
        return "0".into();
    }
    let mut result = Vec::new();
    while number > 0 {
        let digit = (number % 36) as u8;
        result.push(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
        number /= 36;
    }
    result.reverse();
    String::from_utf8(result).expect("base36 is ASCII")
}

fn note_meta(doc: &Value) -> Result<Option<NoteMeta>, Error> {
    if doc.get("deleted").and_then(Value::as_bool) == Some(true)
        || doc.get("_deleted").and_then(Value::as_bool) == Some(true)
    {
        return Ok(None);
    }
    if !matches!(doc.get("type").and_then(Value::as_str), Some("plain")) {
        return Ok(None);
    }
    let path = doc
        .get("path")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Unsupported("missing note path".into()))?;
    if path.starts_with("/\\:") {
        return Err(Error::Unsupported("obfuscated note paths".into()));
    }
    if path.contains(':') {
        // LiveSync uses prefixed paths such as i: for synchronized settings.
        return Ok(None);
    }
    validate_path(path)?;
    let revision = doc
        .get("_rev")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Unsupported(format!("missing revision for {path}")))?;
    let modified_ms = doc.get("mtime").and_then(Value::as_i64).unwrap_or(0);
    Ok(Some(NoteMeta {
        path: path.into(),
        revision: revision.into(),
        modified_ms,
    }))
}

fn plain_data(value: &Value, id: &str) -> Result<String, Error> {
    if let Some(data) = value.as_str() {
        return Ok(data.into());
    }
    if let Some(parts) = value.as_array() {
        let mut content = String::new();
        for part in parts {
            content.push_str(
                part.as_str()
                    .ok_or_else(|| Error::Unsupported(format!("invalid data element in {id}")))?,
            );
        }
        return Ok(content);
    }
    Err(Error::Unsupported(format!("invalid data in {id}")))
}

fn assemble_content(doc: &Value, chunks: &[Value], path: &str) -> Result<String, Error> {
    if doc.get("e_").is_some() {
        return Err(Error::Unsupported("encrypted note".into()));
    }
    let children = doc
        .get("children")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Unsupported(format!("missing children for {path}")))?;
    if children.is_empty() {
        return match doc.get("data") {
            Some(data) => plain_data(data, path),
            None if doc.get("size").and_then(Value::as_u64) == Some(0) => Ok(String::new()),
            None => Err(Error::Unsupported(format!("missing content for {path}"))),
        };
    }
    if children.len() != chunks.len() {
        return Err(Error::Unsupported(format!("missing chunks for {path}")));
    }
    let mut content = String::new();
    for (child, chunk) in children.iter().zip(chunks) {
        let id = child
            .as_str()
            .ok_or_else(|| Error::Unsupported(format!("invalid child for {path}")))?;
        if id.starts_with("h:+") || chunk.get("e_").is_some() {
            return Err(Error::Unsupported("encrypted chunk".into()));
        }
        let data = if chunk.is_string() {
            chunk
        } else {
            chunk
                .get("data")
                .ok_or_else(|| Error::Unsupported(format!("missing chunk data {id}")))?
        };
        content.push_str(&plain_data(data, id)?);
    }
    Ok(content)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encodes_nested_note_as_one_couchdb_document_id() {
        let client = Client::new("https://example.com/proxy/", "vault", "u", "p").unwrap();
        assert_eq!(
            client.document_url("folder/a b.md").unwrap().as_str(),
            "https://example.com/proxy/vault/folder%2Fa%20b.md"
        );
        assert_eq!(
            Client::note_id("Folder/Mixed Case.md"),
            "folder/mixed case.md"
        );
        assert_eq!(Client::note_id("_Private.md"), "/_private.md");
        assert!(validate_path("../escape.md").is_err());
    }

    #[test]
    fn assembles_chunks_in_order_and_refuses_missing_content() {
        let doc = json!({
            "_id": "folder/a.md", "_rev": "2-abc", "path": "folder/a.md",
            "type": "plain", "mtime": 123, "size": 11,
            "children": ["h:one", "h:two"], "eden": {}
        });
        let chunks = [
            json!({"_id": "h:one", "type": "leaf", "data": "hello "}),
            json!({"_id": "h:two", "type": "leaf", "data": "world"}),
        ];
        assert_eq!(
            assemble_content(&doc, &chunks, "folder/a.md").unwrap(),
            "hello world"
        );
        assert!(assemble_content(&doc, &chunks[..1], "folder/a.md").is_err());
    }

    #[test]
    fn refuses_encrypted_and_incomplete_content() {
        assert!(
            assemble_content(
                &json!({"children": [], "data": "cipher", "e_": true}),
                &[],
                "a.md"
            )
            .is_err()
        );
        assert!(
            note_meta(&json!({
                "type": "plain", "path": "/\\:opaque", "_rev": "1-x"
            }))
            .is_err()
        );
        assert!(plain_data(&json!(["okay", 3]), "h:x").is_err());
    }
}
