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
                    stats.export
                }
            };

            match export {
                Some(stats) => {
                    println!(
                        "Exported {} activity rows, {} sleep sessions, {} days, {} file(s) updated",
                        stats.activity_rows, stats.sleep_sessions, stats.days, stats.files_written
                    );
                }
                None => println!("No Gadgetbridge database found to import"),
            }

            // Server-side writes bypass DAV — refresh the stat cache for the subtree.
            let reindex = tilde_dav::reindex_tree(&conn, &health_dir, "health/", true)?;
            println!(
                "Reindexed health tree: {} indexed, {} pruned",
                reindex.indexed, reindex.pruned
            );
            Ok(())
        }
    }
}
