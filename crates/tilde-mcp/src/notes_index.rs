//! Full-text search over the LiveSync vault.
//!
//! CouchDB holds the notes; this keeps an FTS5 copy in SQLite current by
//! following CouchDB's `_changes` feed. Search used to fetch every note and
//! then every chunk from CouchDB one request at a time, which took tens of
//! seconds and ran past nginx's 60s upstream timeout.

use std::collections::HashMap;
use std::sync::Mutex as StdMutex;
use std::time::Duration;

use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use tilde_core::db::DbPool;
use tilde_livesync::{Change, Client, Error as LiveSyncError, missing_chunk_ids, note_from_doc};
use tracing::{info, warn};

use crate::tools_livesync::{modified_iso, title};

/// Changes per `_changes` request.
const PAGE: usize = 200;
/// Passes a note may wait for a chunk that has not replicated yet. After that
/// it is left out of the index until it changes again, so one broken note
/// cannot stall indexing of everything after it.
const MAX_CHUNK_DEFERRALS: u32 = 5;
/// How long a search waits to catch up with CouchDB before answering from the
/// index as it stands.
const FRESHEN_TIMEOUT: Duration = Duration::from_secs(3);
/// Background poll interval for edits made in Obsidian.
const POLL_INTERVAL: Duration = Duration::from_secs(15);

pub struct NotesIndex {
    client: Client,
    db: DbPool,
    database: String,
    /// Serializes sync passes so two passes cannot write the checkpoint out
    /// of order.
    sync_lock: tokio::sync::Mutex<()>,
    deferrals: StdMutex<HashMap<String, u32>>,
}

impl NotesIndex {
    pub fn new(client: Client, db: DbPool, database: &str) -> Self {
        Self {
            client,
            db,
            database: database.to_owned(),
            sync_lock: tokio::sync::Mutex::new(()),
            deferrals: StdMutex::new(HashMap::new()),
        }
    }

    /// Apply every pending change from CouchDB. Returns how many documents
    /// were indexed or removed.
    pub async fn sync(&self) -> Result<usize, String> {
        let _guard = self.sync_lock.lock().await;
        let mut applied = 0;
        loop {
            let since = {
                let conn = self.db.get().map_err(|e| e.to_string())?;
                reset_if_database_changed(&conn, &self.database).map_err(|e| e.to_string())?;
                load_since(&conn, &self.database).map_err(|e| e.to_string())?
            };
            let page = self
                .client
                .changes(since.as_ref(), PAGE)
                .await
                .map_err(|e| e.to_string())?;

            // Chunks usually arrive in the same page as their note; fetch the
            // rest in bulk rather than one request per chunk.
            let mut chunks: HashMap<String, Value> = page
                .results
                .iter()
                .filter(|change| is_chunk_id(&change.id))
                .filter_map(|change| Some((change.id.clone(), change.doc.clone()?)))
                .collect();
            let mut missing: Vec<String> = page
                .results
                .iter()
                .filter(|change| !change.deleted && !is_chunk_id(&change.id))
                .filter_map(|change| change.doc.as_ref())
                .filter(|doc| doc.get("type").and_then(Value::as_str) == Some("plain"))
                .filter_map(|doc| missing_chunk_ids(doc, &chunks).ok())
                .flatten()
                .collect();
            missing.sort();
            missing.dedup();
            if !missing.is_empty() {
                chunks.extend(
                    self.client
                        .fetch_documents(&missing)
                        .await
                        .map_err(|e| e.to_string())?,
                );
            }

            let conn = self.db.get().map_err(|e| e.to_string())?;
            let mut deferrals = self.deferrals.lock().unwrap_or_else(|e| e.into_inner());
            let outcome = apply_changes(
                &conn,
                &self.database,
                since.as_ref(),
                &page.results,
                &page.last_seq,
                &chunks,
                &mut deferrals,
            )
            .map_err(|e| e.to_string())?;
            applied += outcome.applied;
            if outcome.stalled {
                break;
            }
            if page.results.len() < PAGE {
                mark_built(&conn, &self.database).map_err(|e| e.to_string())?;
                break;
            }
        }
        Ok(applied)
    }

    /// Follow CouchDB forever, picking up edits made outside tilde.
    pub async fn run(&self) {
        loop {
            match self.sync().await {
                Ok(0) => {}
                Ok(applied) => info!(applied, "LiveSync notes index updated"),
                Err(error) => warn!(%error, "LiveSync notes index sync failed"),
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    pub async fn search(&self, params: &Value) -> Result<Value, String> {
        let query = params
            .get("query")
            .and_then(Value::as_str)
            .ok_or("query parameter required")?;
        let limit = params
            .get("limit")
            .and_then(Value::as_u64)
            .unwrap_or(20)
            .clamp(1, 100);
        let path = params.get("path").and_then(Value::as_str).unwrap_or("");
        let expression = fts_query(query)?;

        // Catch up first so a note written a moment ago is findable. A slow
        // CouchDB must not stall search, so fall back to the index as it is.
        match tokio::time::timeout(FRESHEN_TIMEOUT, self.sync()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => warn!(%error, "notes.search could not refresh the index"),
            Err(_) => warn!("notes.search refresh timed out; answering from the index"),
        }

        let conn = self.db.get().map_err(|e| e.to_string())?;
        if !is_built(&conn, &self.database).map_err(|e| e.to_string())? {
            let indexed: i64 = conn
                .query_row("SELECT COUNT(*) FROM livesync_notes", [], |row| row.get(0))
                .map_err(|e| e.to_string())?;
            return Err(format!(
                "the notes search index is still being built ({indexed} notes indexed so far); retry in a moment"
            ));
        }
        search_index(&conn, &expression, path, limit as usize).map_err(|e| e.to_string())
    }
}

fn is_chunk_id(id: &str) -> bool {
    id.starts_with("h:")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Applied {
    pub applied: usize,
    /// A note's chunk had not arrived; the checkpoint stops just before it.
    pub stalled: bool,
}

/// Apply one page of changes and advance the checkpoint, atomically.
pub(crate) fn apply_changes(
    conn: &Connection,
    database: &str,
    since: Option<&Value>,
    changes: &[Change],
    last_seq: &Value,
    chunks: &HashMap<String, Value>,
    deferrals: &mut HashMap<String, u32>,
) -> rusqlite::Result<Applied> {
    let tx = conn.unchecked_transaction()?;
    let mut outcome = Applied::default();
    let mut checkpoint = Some(last_seq);
    let mut previous = since;
    for change in changes {
        if is_chunk_id(&change.id) {
            previous = Some(&change.seq);
            continue;
        }
        let doc = if change.deleted {
            None
        } else {
            change.doc.as_ref()
        };
        match doc.map(|doc| note_from_doc(doc, chunks)) {
            Some(Ok(Some(note))) => {
                deferrals.remove(&change.id);
                tx.execute(
                    "INSERT INTO livesync_notes (doc_id, path, title, content, modified_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)
                     ON CONFLICT(doc_id) DO UPDATE SET path = excluded.path,
                         title = excluded.title, content = excluded.content,
                         modified_ms = excluded.modified_ms",
                    params![
                        change.id,
                        note.path,
                        title(&note.path, &note.content),
                        note.content,
                        note.modified_ms
                    ],
                )?;
            }
            Some(Err(LiveSyncError::MissingChunk(chunk))) => {
                let waited = deferrals.entry(change.id.clone()).or_insert(0);
                *waited += 1;
                if *waited <= MAX_CHUNK_DEFERRALS {
                    checkpoint = previous;
                    outcome.stalled = true;
                    break;
                }
                warn!(doc = %change.id, %chunk, "skipping LiveSync note whose chunk never arrived");
                deferrals.remove(&change.id);
                delete_note(&tx, &change.id)?;
            }
            Some(Err(error)) => {
                warn!(doc = %change.id, %error, "skipping unreadable LiveSync document");
                delete_note(&tx, &change.id)?;
            }
            // Deleted, or not a note (binary file, settings, version doc).
            None | Some(Ok(None)) => delete_note(&tx, &change.id)?,
        }
        outcome.applied += 1;
        previous = Some(&change.seq);
    }
    tx.execute(
        "INSERT INTO livesync_index_state (database, since) VALUES (?1, ?2)
         ON CONFLICT(database) DO UPDATE SET since = excluded.since",
        params![database, checkpoint.map(Value::to_string)],
    )?;
    tx.commit()?;
    Ok(outcome)
}

fn delete_note(conn: &Connection, doc_id: &str) -> rusqlite::Result<()> {
    conn.execute("DELETE FROM livesync_notes WHERE doc_id = ?1", [doc_id])?;
    Ok(())
}

/// The index belongs to one CouchDB database; pointing tilde at another one
/// starts over rather than mixing two vaults.
fn reset_if_database_changed(conn: &Connection, database: &str) -> rusqlite::Result<()> {
    let other: i64 = conn.query_row(
        "SELECT COUNT(*) FROM livesync_index_state WHERE database != ?1",
        [database],
        |row| row.get(0),
    )?;
    if other > 0 {
        conn.execute_batch("DELETE FROM livesync_notes; DELETE FROM livesync_index_state;")?;
    }
    Ok(())
}

fn load_since(conn: &Connection, database: &str) -> rusqlite::Result<Option<Value>> {
    let stored: Option<Option<String>> = conn
        .query_row(
            "SELECT since FROM livesync_index_state WHERE database = ?1",
            [database],
            |row| row.get(0),
        )
        .optional()?;
    Ok(stored
        .flatten()
        .and_then(|since| serde_json::from_str(&since).ok()))
}

fn mark_built(conn: &Connection, database: &str) -> rusqlite::Result<()> {
    let now = jiff::Timestamp::now().to_string();
    conn.execute(
        "UPDATE livesync_index_state SET built_at = COALESCE(built_at, ?2) WHERE database = ?1",
        params![database, now],
    )?;
    Ok(())
}

fn is_built(conn: &Connection, database: &str) -> rusqlite::Result<bool> {
    Ok(conn
        .query_row(
            "SELECT built_at IS NOT NULL FROM livesync_index_state WHERE database = ?1",
            [database],
            |row| row.get(0),
        )
        .optional()?
        .unwrap_or(false))
}

pub(crate) fn search_index(
    conn: &Connection,
    expression: &str,
    path_prefix: &str,
    limit: usize,
) -> rusqlite::Result<Value> {
    let mut stmt = conn.prepare(
        "SELECT n.path, n.title, n.modified_ms,
                snippet(livesync_notes_fts, -1, '«', '»', '…', 16)
         FROM livesync_notes_fts
         JOIN livesync_notes n ON n.id = livesync_notes_fts.rowid
         WHERE livesync_notes_fts MATCH ?1 AND n.path LIKE ?2 ESCAPE '\\'
         ORDER BY bm25(livesync_notes_fts, 5.0, 10.0, 1.0)
         LIMIT ?3",
    )?;
    let pattern = format!("{}%", tilde_dav::escape_like(path_prefix));
    let rows = stmt.query_map(params![expression, pattern, limit as i64], |row| {
        Ok(json!({
            "path": row.get::<_, String>(0)?,
            "title": row.get::<_, String>(1)?,
            "modified": modified_iso(row.get(2)?),
            "snippet": row.get::<_, String>(3)?,
        }))
    })?;
    Ok(Value::Array(rows.collect::<Result<_, _>>()?))
}

/// Turn user input into an FTS5 expression. Every term is quoted, so FTS5
/// operators and punctuation inside a term are literal. The supported syntax
/// is `"exact phrase"`, `prefix*`, `-excluded`, and `OR` between two terms;
/// everything else must all match.
pub(crate) fn fts_query(input: &str) -> Result<String, String> {
    struct Term {
        text: String,
        prefix: bool,
    }
    let mut groups: Vec<Vec<Term>> = Vec::new();
    let mut excluded: Vec<Term> = Vec::new();
    let mut join_with_previous = false;

    let mut chars = input.chars().peekable();
    loop {
        while chars.next_if(|c| c.is_whitespace()).is_some() {}
        let Some(&first) = chars.peek() else { break };
        let negate = first == '-';
        if negate {
            chars.next();
        }
        let (text, quoted) = if chars.next_if_eq(&'"').is_some() {
            let phrase: String = chars.by_ref().take_while(|&c| c != '"').collect();
            (phrase, true)
        } else {
            let mut word = String::new();
            while let Some(c) = chars.next_if(|c| !c.is_whitespace()) {
                word.push(c);
            }
            (word, false)
        };
        let prefix = if quoted {
            chars.next_if_eq(&'*').is_some()
        } else {
            text.ends_with('*')
        };
        if !quoted && !negate && text == "OR" {
            join_with_previous = !groups.is_empty();
            continue;
        }
        let text = if quoted {
            text
        } else {
            text.trim_end_matches('*').to_owned()
        };
        if !text.chars().any(char::is_alphanumeric) {
            continue;
        }
        let term = Term { text, prefix };
        if negate {
            excluded.push(term);
        } else if join_with_previous {
            groups.last_mut().expect("OR follows a term").push(term);
        } else {
            groups.push(vec![term]);
        }
        join_with_previous = false;
    }

    let render = |term: &Term| {
        format!(
            "\"{}\"{}",
            term.text.replace('"', "\"\""),
            if term.prefix { "*" } else { "" }
        )
    };
    if groups.is_empty() {
        return Err(if excluded.is_empty() {
            "query must contain at least one word".into()
        } else {
            "query needs at least one term to match; -excluded terms only narrow results".into()
        });
    }
    let mut expression = groups
        .iter()
        .map(|group| match group.as_slice() {
            [term] => render(term),
            terms => format!(
                "({})",
                terms.iter().map(render).collect::<Vec<_>>().join(" OR ")
            ),
        })
        .collect::<Vec<_>>()
        .join(" AND ");
    if !excluded.is_empty() {
        expression = format!("({expression})");
        for term in &excluded {
            expression.push_str(" NOT ");
            expression.push_str(&render(term));
        }
    }
    Ok(expression)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        tilde_core::db::run_migrations(&conn, std::path::Path::new("")).unwrap();
        conn
    }

    fn note(id: &str, rev: &str, path: &str, content: &str, seq: i64) -> Change {
        Change {
            seq: json!(seq),
            id: id.into(),
            deleted: false,
            doc: Some(json!({
                "_id": id, "_rev": rev, "path": path, "type": "plain",
                "mtime": 1_759_000_000_000_i64, "size": content.len(),
                "children": [], "data": content,
            })),
        }
    }

    fn apply(conn: &Connection, changes: &[Change], chunks: &HashMap<String, Value>) -> Applied {
        let last = changes.last().map(|c| c.seq.clone()).unwrap_or(json!(0));
        let since = load_since(conn, "vault").unwrap();
        apply_changes(
            conn,
            "vault",
            since.as_ref(),
            changes,
            &last,
            chunks,
            &mut HashMap::new(),
        )
        .unwrap()
    }

    fn paths(conn: &Connection, query: &str) -> Vec<String> {
        search_index(conn, &fts_query(query).unwrap(), "", 20)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|hit| hit["path"].as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn builds_safe_expressions() {
        assert_eq!(
            fts_query("coffee sleep").unwrap(),
            r#""coffee" AND "sleep""#
        );
        assert_eq!(
            fts_query(r#""weekly review" plan* -draft"#).unwrap(),
            r#"("weekly review" AND "plan"*) NOT "draft""#
        );
        assert_eq!(
            fts_query("a b OR c d").unwrap(),
            r#""a" AND ("b" OR "c") AND "d""#
        );
        // FTS5 syntax in user input stays literal instead of erroring.
        assert_eq!(
            fts_query(r#"title:x NEAR( say"hi"#).unwrap(),
            r#""title:x" AND "NEAR(" AND "say""hi""#
        );
        assert!(fts_query("  ").is_err());
        assert!(fts_query("-only").is_err());
        assert!(fts_query("OR").is_err());
    }

    #[test]
    fn ranks_matches_ignoring_case_and_accents() {
        let conn = db();
        apply(
            &conn,
            &[
                note(
                    "diet.md",
                    "1-a",
                    "Diet.md",
                    "# Nutrición\nMucho café por la mañana",
                    1,
                ),
                note(
                    "log.md",
                    "1-b",
                    "journal/log.md",
                    "Slept badly, too much coffee",
                    2,
                ),
                note(
                    "nutricion.md",
                    "1-c",
                    "nutricion.md",
                    "Nutricion plan for the week",
                    3,
                ),
            ],
            &HashMap::new(),
        );
        assert_eq!(paths(&conn, "CAFE"), ["Diet.md"]);
        assert_eq!(paths(&conn, "cafe OR coffee").len(), 2);
        let mut both = paths(&conn, "nutricion");
        both.sort();
        assert_eq!(both, ["Diet.md", "nutricion.md"]);
        assert_eq!(paths(&conn, "nutri*").len(), 2);
        assert_eq!(paths(&conn, "coffee -slept"), Vec::<String>::new());
        assert_eq!(paths(&conn, r#""too much coffee""#), ["journal/log.md"]);
        // Escaped FTS5 syntax runs instead of erroring.
        assert!(paths(&conn, r#"title:x NEAR( say"hi"#).is_empty());

        // A title match outranks a body-only one.
        apply(
            &conn,
            &[note(
                "weekly.md",
                "1-d",
                "weekly.md",
                "# Week review\nstuff",
                4,
            )],
            &HashMap::new(),
        );
        assert_eq!(paths(&conn, "week"), ["weekly.md", "nutricion.md"]);

        let hits = search_index(&conn, &fts_query("coffee").unwrap(), "journal/", 20).unwrap();
        assert_eq!(hits[0]["snippet"], "Slept badly, too much «coffee»");
        assert!(
            search_index(&conn, &fts_query("coffee").unwrap(), "jour_al/", 20)
                .unwrap()
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn follows_edits_deletions_and_chunks() {
        let conn = db();
        apply(
            &conn,
            &[note("a.md", "1-a", "a.md", "old words", 1)],
            &HashMap::new(),
        );
        apply(
            &conn,
            &[note("a.md", "2-a", "a.md", "new words", 2)],
            &HashMap::new(),
        );
        assert!(paths(&conn, "old").is_empty());
        assert_eq!(paths(&conn, "new"), ["a.md"]);

        // LiveSync soft delete keeps the doc with deleted=true.
        let mut soft = note("a.md", "3-a", "a.md", "new words", 3);
        soft.doc.as_mut().unwrap()["deleted"] = json!(true);
        apply(&conn, &[soft], &HashMap::new());
        assert!(paths(&conn, "new").is_empty());

        // Content split across chunks fetched separately.
        let mut chunked = note("b.md", "1-b", "b.md", "", 4);
        let doc = chunked.doc.as_mut().unwrap();
        doc["children"] = json!(["h:1", "h:2"]);
        doc.as_object_mut().unwrap().remove("data");
        let chunks = HashMap::from([
            (
                "h:1".to_owned(),
                json!({"_id": "h:1", "type": "leaf", "data": "split "}),
            ),
            (
                "h:2".to_owned(),
                json!({"_id": "h:2", "type": "leaf", "data": "keyword"}),
            ),
        ]);
        apply(&conn, &[chunked.clone()], &chunks);
        assert_eq!(paths(&conn, r#""split keyword""#), ["b.md"]);

        // CouchDB tombstone.
        let tombstone = Change {
            seq: json!(5),
            id: "b.md".into(),
            deleted: true,
            doc: None,
        };
        apply(&conn, &[tombstone], &HashMap::new());
        assert!(paths(&conn, "keyword").is_empty());
    }

    #[test]
    fn waits_for_missing_chunks_then_gives_up() {
        let conn = db();
        let mut waiting = note("w.md", "1-w", "w.md", "", 2);
        let doc = waiting.doc.as_mut().unwrap();
        doc["children"] = json!(["h:late"]);
        doc.as_object_mut().unwrap().remove("data");
        let changes = [
            note("a.md", "1-a", "a.md", "first", 1),
            waiting,
            note("c.md", "1-c", "c.md", "third", 3),
        ];

        let mut deferrals = HashMap::new();
        for _ in 0..MAX_CHUNK_DEFERRALS {
            let since = load_since(&conn, "vault").unwrap();
            let outcome = apply_changes(
                &conn,
                "vault",
                since.as_ref(),
                &changes,
                &json!(3),
                &HashMap::new(),
                &mut deferrals,
            )
            .unwrap();
            assert!(outcome.stalled);
            // Checkpoint stops right before the waiting note.
            assert_eq!(load_since(&conn, "vault").unwrap(), Some(json!(1)));
        }
        assert!(paths(&conn, "third").is_empty());

        let since = load_since(&conn, "vault").unwrap();
        let outcome = apply_changes(
            &conn,
            "vault",
            since.as_ref(),
            &changes,
            &json!(3),
            &HashMap::new(),
            &mut deferrals,
        )
        .unwrap();
        assert!(!outcome.stalled);
        assert_eq!(load_since(&conn, "vault").unwrap(), Some(json!(3)));
        assert_eq!(paths(&conn, "third"), ["c.md"]);
    }

    #[test]
    fn opaque_couchdb_sequences_round_trip() {
        let conn = db();
        let seq = json!("12-g1AAAABteJzLYWBgYMpgTmHgz8tPSTV0MDQy");
        apply_changes(
            &conn,
            "vault",
            None,
            &[],
            &seq,
            &HashMap::new(),
            &mut HashMap::new(),
        )
        .unwrap();
        assert_eq!(load_since(&conn, "vault").unwrap(), Some(seq));
        mark_built(&conn, "vault").unwrap();
        assert!(is_built(&conn, "vault").unwrap());

        reset_if_database_changed(&conn, "other").unwrap();
        assert!(!is_built(&conn, "vault").unwrap());
    }
}
