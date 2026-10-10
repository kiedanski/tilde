use std::path::Path;

use tilde_cli::GadgetbridgeCommands;
use tilde_core::{config::Config, db};

pub async fn run_gadgetbridge(
    config_path: Option<&str>,
    command: GadgetbridgeCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        GadgetbridgeCommands::Import { db } => {
            let files_root = config.data_dir().join("files");
            let health_dir = files_root.join("health");
            let tz = tilde_health::resolve_timezone(&config.gadgetbridge.timezone)?;

            let mut weight = None;
            let export = match db {
                Some(db_path) => Some(tilde_health::export_gadgetbridge(
                    Path::new(&db_path),
                    &health_dir,
                    &tz,
                )?),
                None => {
                    let stats =
                        tilde_health::process_inbox(&health_dir.join("_inbox"), &health_dir, &tz)?;
                    if stats.workouts_copied > 0 {
                        println!("{} workout file(s) copied", stats.workouts_copied);
                    }
                    weight = stats.weight;
                    stats.export
                }
            };

            if let Some(stats) = &export {
                println!(
                    "Exported {} activity rows, {} sleep sessions, {} days, {} file(s) updated",
                    stats.activity_rows, stats.sleep_sessions, stats.days, stats.files_written
                );
            }
            if let Some(stats) = &weight {
                println!(
                    "Exported {} body-weight reading(s), {} file(s) updated",
                    stats.rows, stats.files_written
                );
            }
            if export.is_none() && weight.is_none() {
                println!("No database found to import");
            }

            // Server-side writes bypass DAV — refresh the stat cache for the subtree.
            let reindex = tilde_dav::reindex_tree(&conn, &health_dir, "health/", true)?;
            println!(
                "Reindexed health tree: {} indexed, {} pruned",
                reindex.indexed, reindex.pruned
            );

            // Optional Markdown mirror for Obsidian: into the LiveSync vault
            // when one is configured, else into the on-disk notes tree.
            let notes_dir = config.gadgetbridge.notes_dir.trim_matches('/').to_string();
            if !notes_dir.is_empty()
                && let Some(remote) = &config.notes.livesync
            {
                let client = tilde_livesync::Client::new(
                    &remote.server_url,
                    &remote.database,
                    &remote.username,
                    &remote.password,
                )?;
                let notes = tilde_health::render_notes(&health_dir);
                let written =
                    super::health_notes::mirror_to_livesync(&client, &notes_dir, &notes).await?;
                println!("Health notes: {written} note(s) updated in LiveSync");
            } else if !notes_dir.is_empty() {
                let target = config.data_dir().join("notes").join(&notes_dir);
                let notes = tilde_health::export_notes(&health_dir, &target)?;
                println!("Health notes: {} file(s) updated", notes.files_written);
                if notes.files_written > 0 {
                    tilde_dav::reindex_tree(&conn, &target, &format!("{notes_dir}/"), true)?;
                }
            }
            Ok(())
        }
    }
}
