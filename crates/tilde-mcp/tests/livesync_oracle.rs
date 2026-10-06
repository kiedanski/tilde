//! Run only from tests/livesync-oracle/run.sh against its disposable CouchDB.

use serde_json::json;
use tilde_mcp::tools_livesync::exec;

#[tokio::test]
#[ignore = "requires the disposable CouchDB started by tests/livesync-oracle/run.sh"]
async fn mcp_notes_share_the_livesync_vault() {
    let server = std::env::var("ORACLE_HOST_URL").unwrap();
    let database = std::env::var("ORACLE_DATABASE").unwrap();
    let client = tilde_livesync::Client::new(&server, &database, "admin", "testpassword").unwrap();
    let temp = tempfile::tempdir().unwrap();
    let blobs = temp.path().join("blobs");
    let path = "mcp/shared.md";

    let created = exec(
        &client,
        &blobs,
        "notes.create",
        &json!({"path":path,"content":"# MCP\n"}),
    )
    .await
    .unwrap();
    let first_revision = created["revision"].as_str().unwrap();
    let read = exec(&client, &blobs, "notes.read", &json!({"path":path}))
        .await
        .unwrap();
    assert_eq!(read["content"], "# MCP\n");
    assert_eq!(read["metadata"]["revision"], first_revision);

    let written = exec(
        &client,
        &blobs,
        "notes.write",
        &json!({
            "path":path,"content":"# MCP\n\nFrom Tilde","revision":first_revision
        }),
    )
    .await
    .unwrap();
    assert_ne!(written["revision"], first_revision);
    let archived = written["archived_sha256"].as_str().unwrap();
    assert_eq!(
        tilde_dav::versions::read_version(&blobs, archived).unwrap(),
        b"# MCP\n"
    );
    let stale = exec(
        &client,
        &blobs,
        "notes.write",
        &json!({
            "path":path,"content":"stale","revision":first_revision
        }),
    )
    .await
    .unwrap_err();
    assert!(stale.contains("changed since it was read"), "{stale}");

    let appended = exec(
        &client,
        &blobs,
        "notes.append",
        &json!({"path":path,"content":"from agent"}),
    )
    .await
    .unwrap();
    assert_ne!(appended["revision"], written["revision"]);
    let archived = appended["archived_sha256"].as_str().unwrap();
    assert_eq!(
        tilde_dav::versions::read_version(&blobs, archived).unwrap(),
        b"# MCP\n\nFrom Tilde"
    );
    let read = exec(&client, &blobs, "notes.read", &json!({"path":path}))
        .await
        .unwrap();
    assert_eq!(read["content"], "# MCP\n\nFrom Tilde\nfrom agent");
    let db_path = temp.path().join("tilde.db");
    let pool = tilde_core::db::init_pool(db_path.to_str().unwrap()).unwrap();
    tilde_core::db::run_migrations(&pool.get().unwrap(), temp.path()).unwrap();
    let index = tilde_mcp::notes_index::NotesIndex::new(client.clone(), pool, &database);
    let matches = index
        .search(&json!({"query":"\"from agent\"", "path": "mcp/"}))
        .await
        .unwrap();
    assert_eq!(matches[0]["path"], path);
    assert_eq!(matches[0]["snippet"], "# MCP\n\nFrom Tilde\n«from agent»");

    let disposable = exec(
        &client,
        &blobs,
        "notes.create",
        &json!({"path":"mcp/remove.md","content":"keep this version"}),
    )
    .await
    .unwrap();
    let deleted = exec(
        &client,
        &blobs,
        "notes.delete",
        &json!({"path":"mcp/remove.md","revision":disposable["revision"]}),
    )
    .await
    .unwrap();
    let archived = deleted["archived_sha256"].as_str().unwrap();
    assert_eq!(
        tilde_dav::versions::read_version(&blobs, archived).unwrap(),
        b"keep this version"
    );
    let gone = index
        .search(&json!({"query":"\"keep this version\""}))
        .await
        .unwrap();
    assert_eq!(gone, json!([]));
}
