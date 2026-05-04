use tilde_cli::{CollectionCommands, TrackersCommands};
use tilde_core::{config::Config, db};

use super::{confirm_prompt, validate_json_schema};

pub async fn run_collection(
    config_path: Option<&str>,
    command: CollectionCommands,
    skip_confirm: bool,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        CollectionCommands::Create { name, schema } => {
            let schema_json = std::fs::read_to_string(&schema).unwrap_or_else(|_| schema.clone()); // Allow inline JSON or file path
            // Validate it's valid JSON
            let _: serde_json::Value = serde_json::from_str(&schema_json)
                .map_err(|e| anyhow::anyhow!("Invalid JSON schema: {}", e))?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO collections (id, name, schema_json, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![id, name, schema_json, now, now],
            )?;
            println!("Collection '{}' created", name);
        }
        CollectionCommands::List => {
            let mut stmt =
                conn.prepare("SELECT name, created_at FROM collections ORDER BY name")?;
            let rows = stmt.query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            println!("{:<30} Created", "Name");
            println!("{}", "-".repeat(60));
            for row in rows {
                let (name, created) = row?;
                println!("{:<30} {}", name, created);
            }
        }
        CollectionCommands::Add { name, data } => {
            let data_val: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Invalid JSON data: {}", e))?;

            // Get collection and validate schema
            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            // Basic schema validation
            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        CollectionCommands::Get { name, id } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let (data, created, updated): (String, String, String) = conn.query_row(
                "SELECT data_json, created_at, updated_at FROM records WHERE id = ?1 AND collection_id = ?2",
                rusqlite::params![id, collection_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            ).map_err(|_| anyhow::anyhow!("Record '{}' not found", id))?;

            println!("ID:       {}", id);
            println!("Data:     {}", data);
            println!("Created:  {}", created);
            println!("Updated:  {}", updated);
        }
        CollectionCommands::Update { name, id, data } => {
            let data_val: serde_json::Value = serde_json::from_str(&data)
                .map_err(|e| anyhow::anyhow!("Invalid JSON data: {}", e))?;

            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            let updated = conn.execute(
                "UPDATE records SET data_json = ?1, updated_at = ?2, hlc = ?3 WHERE id = ?4 AND collection_id = ?5",
                rusqlite::params![data, now, now, id, collection_id],
            )?;
            if updated == 0 {
                println!("Record '{}' not found", id);
            } else {
                println!("Record updated");
            }
        }
        CollectionCommands::Delete { name, id } => {
            if !skip_confirm {
                eprint!("Delete record '{}' from collection '{}'? [y/N] ", id, name);
                if !confirm_prompt() {
                    println!("Cancelled.");
                    return Ok(());
                }
            }

            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let deleted = conn.execute(
                "DELETE FROM records WHERE id = ?1 AND collection_id = ?2",
                rusqlite::params![id, collection_id],
            )?;
            if deleted == 0 {
                println!("Record '{}' not found", id);
            } else {
                println!("Record deleted");
            }
        }
        CollectionCommands::ListRecords {
            name,
            filter: _,
            sort,
            limit,
        } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            // Validate sort field: only allow alphanumeric + underscores to prevent injection
            if let Some(ref s) = sort {
                if !s.chars().all(|c| c.is_alphanumeric() || c == '_') {
                    anyhow::bail!("Invalid sort field: must be alphanumeric");
                }
            }

            let mut sql = String::from(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1",
            );
            if let Some(ref s) = sort {
                // Sort field is validated above — safe to interpolate into json_extract path
                sql.push_str(&format!(" ORDER BY json_extract(data_json, '$.{}') ASC", s));
            } else {
                sql.push_str(" ORDER BY created_at DESC");
            }
            if let Some(l) = limit {
                sql.push_str(&format!(" LIMIT {}", l));
            }

            let mut stmt = conn.prepare(&sql)?;
            let rows = stmt.query_map([&collection_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })?;

            println!("{:<36} {:<40} Created", "ID", "Data");
            println!("{}", "-".repeat(90));
            for row in rows {
                let (id, data, created) = row?;
                println!("{:<36} {:<40} {}", id, data, created);
            }
        }
        CollectionCommands::Export { name, format } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&name],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", name))?;

            let mut stmt = conn.prepare(
                "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at"
            )?;
            let rows: Vec<(String, String, String)> = stmt
                .query_map([&collection_id], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect();

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|(id, data, created)| {
                            let mut record: serde_json::Value =
                                serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                            if let Some(obj) = record.as_object_mut() {
                                obj.insert("_id".to_string(), serde_json::json!(id));
                                obj.insert("_created_at".to_string(), serde_json::json!(created));
                            }
                            record
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                "csv" => {
                    // Extract keys from first record
                    if let Some((_, first_data, _)) = rows.first() {
                        let first: serde_json::Value = serde_json::from_str(first_data)?;
                        if let Some(obj) = first.as_object() {
                            let keys: Vec<&String> = obj.keys().collect();
                            println!(
                                "id,{},created_at",
                                keys.iter()
                                    .map(|k| k.as_str())
                                    .collect::<Vec<_>>()
                                    .join(",")
                            );
                            for (id, data, created) in &rows {
                                let record: serde_json::Value = serde_json::from_str(data)?;
                                let values: Vec<String> = keys
                                    .iter()
                                    .map(|k| {
                                        record
                                            .get(k.as_str())
                                            .map(|v| v.to_string().trim_matches('"').to_string())
                                            .unwrap_or_default()
                                    })
                                    .collect();
                                println!("{},{},{}", id, values.join(","), created);
                            }
                        }
                    }
                }
                _ => println!("Unknown format: {}. Use 'json' or 'csv'", format),
            }
        }
    }

    Ok(())
}

pub async fn run_trackers(
    config_path: Option<&str>,
    command: TrackersCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        TrackersCommands::Log { collection, data } => {
            let data_val: serde_json::Value =
                serde_json::from_str(&data).map_err(|e| anyhow::anyhow!("Invalid JSON: {}", e))?;

            let (collection_id, schema_json): (String, String) = conn
                .query_row(
                    "SELECT id, schema_json FROM collections WHERE name = ?1",
                    [&collection],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let schema: serde_json::Value = serde_json::from_str(&schema_json)?;
            validate_json_schema(&data_val, &schema)?;

            let id = uuid::Uuid::new_v4().to_string();
            let now = jiff::Zoned::now()
                .strftime("%Y-%m-%dT%H:%M:%S%:z")
                .to_string();
            conn.execute(
                "INSERT INTO records (id, collection_id, data_json, created_at, updated_at, hlc) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![id, collection_id, data, now, now, now],
            )?;
            println!("{}", id);
        }
        TrackersCommands::Query {
            collection,
            since,
            format,
            limit,
        } => {
            let (collection_id,): (String,) = conn
                .query_row(
                    "SELECT id FROM collections WHERE name = ?1",
                    [&collection],
                    |row| Ok((row.get(0)?,)),
                )
                .map_err(|_| anyhow::anyhow!("Collection '{}' not found", collection))?;

            let limit = limit.unwrap_or(50);

            let rows: Vec<(String, String, String)> = if let Some(ref since_val) = since {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 AND created_at >= ?2 ORDER BY created_at DESC LIMIT ?3"
                )?;
                stmt.query_map(rusqlite::params![collection_id, since_val, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect()
            } else {
                let mut stmt = conn.prepare(
                    "SELECT id, data_json, created_at FROM records WHERE collection_id = ?1 ORDER BY created_at DESC LIMIT ?2"
                )?;
                stmt.query_map(rusqlite::params![collection_id, limit], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })?
                .filter_map(|r| r.ok())
                .collect()
            };

            match format.as_str() {
                "json" => {
                    let records: Vec<serde_json::Value> = rows
                        .iter()
                        .map(|(id, data, created)| {
                            let mut record: serde_json::Value =
                                serde_json::from_str(data).unwrap_or(serde_json::json!({}));
                            if let Some(obj) = record.as_object_mut() {
                                obj.insert("_id".to_string(), serde_json::json!(id));
                                obj.insert("_created_at".to_string(), serde_json::json!(created));
                            }
                            record
                        })
                        .collect();
                    println!("{}", serde_json::to_string_pretty(&records)?);
                }
                _ => {
                    // Table format
                    println!("{:<36} {:<40} Created", "ID", "Data");
                    println!("{}", "-".repeat(90));
                    for (id, data, created) in &rows {
                        println!("{:<36} {:<40} {}", id, data, created);
                    }
                }
            }
        }
    }
    Ok(())
}
