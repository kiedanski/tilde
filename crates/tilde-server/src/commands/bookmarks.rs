use tilde_cli::BookmarksCommands;
use tilde_core::{config::Config, db};

pub async fn run_bookmarks(
    config_path: Option<&str>,
    command: BookmarksCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    // Ensure "bookmarks" collection exists
    ensure_bookmarks_collection(&conn)?;

    match command {
        BookmarksCommands::Add {
            url,
            title,
            tags,
            description,
        } => {
            let mut data = serde_json::json!({
                "url": url,
            });
            if let Some(t) = title {
                data["title"] = serde_json::json!(t);
            }
            if let Some(t) = tags {
                let tag_list: Vec<&str> = t.split(',').map(|s| s.trim()).collect();
                data["tags"] = serde_json::json!(tag_list);
            }
            if let Some(d) = description {
                data["description"] = serde_json::json!(d);
            }
            data["created_at"] = serde_json::json!(
                jiff::Zoned::now()
                    .strftime("%Y-%m-%dT%H:%M:%S%:z")
                    .to_string()
            );

            let collection_id: String = conn.query_row(
                "SELECT id FROM collections WHERE name = 'bookmarks'",
                [],
                |row| row.get(0),
            )?;

            let id = uuid::Uuid::new_v4().to_string();
            let data_str = serde_json::to_string(&data)?;
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data_str, now, now, now],
            )?;
            println!("{}", id);
        }
        BookmarksCommands::List { tag, limit } => {
            let collection_id: String = conn.query_row(
                "SELECT id FROM collections WHERE name = 'bookmarks'",
                [],
                |row| row.get(0),
            )?;

            let limit = limit.unwrap_or(50);
            let mut stmt = conn.prepare(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
            )?;
            let rows: Vec<(String, String, String)> = stmt
                .query_map(rusqlite::params![collection_id, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect();

            println!("{:<36} {:<50} {:<30} Tags", "ID", "URL", "Title");
            println!("{}", "-".repeat(130));
            for (id, data_str, _created) in &rows {
                let data: serde_json::Value = serde_json::from_str(data_str).unwrap_or_default();
                let url = data.get("url").and_then(|v| v.as_str()).unwrap_or("-");
                let title = data.get("title").and_then(|v| v.as_str()).unwrap_or("-");
                let tags = data
                    .get("tags")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default();

                // Filter by tag if specified
                if let Some(ref filter_tag) = tag
                    && !tags.contains(filter_tag)
                {
                    continue;
                }

                println!("{:<36} {:<50} {:<30} {}", id, url, title, tags);
            }
        }
    }
    Ok(())
}

fn ensure_bookmarks_collection(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) FROM collections WHERE name = 'bookmarks'",
            [],
            |row| row.get::<_, i64>(0),
        )
        .map(|c| c > 0)?;

    if !exists {
        let id = uuid::Uuid::new_v4().to_string();
        let schema = serde_json::json!({
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string"},
                "title": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "description": {"type": "string"},
                "created_at": {"type": "string"}
            }
        });
        let now = jiff::Zoned::now()
            .strftime("%Y-%m-%dT%H:%M:%S%:z")
            .to_string();
        conn.execute(
            "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, 'bookmarks', ?2, ?3, ?4)",
            rusqlite::params![id, serde_json::to_string(&schema)?, now, now],
        )?;
    }
    Ok(())
}
