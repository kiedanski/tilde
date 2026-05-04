use tilde_cli::NotificationCommands;
use tilde_core::{config::Config, db};

pub async fn run_notifications(
    config_path: Option<&str>,
    command: NotificationCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        NotificationCommands::Test { sink } => {
            let data_dir = config.data_dir();
            match sink.as_str() {
                "file" => {
                    let file_sink = tilde_notify::create_file_sink(&data_dir);
                    let event = tilde_notify::NotificationEvent {
                        event_type: "test".to_string(),
                        priority: tilde_notify::Priority::Low,
                        message: "Test notification from tilde".to_string(),
                    };
                    tilde_notify::NotificationSink::send(&file_sink, &event)?;
                    println!(
                        "Test notification sent to file sink: {}",
                        data_dir.join("notifications.log").display()
                    );
                }
                _ => {
                    println!("Unknown sink: {}. Available: file", sink);
                }
            }
        }
        NotificationCommands::List => {
            let mut stmt = conn.prepare(
                "SELECT event_type, priority, message, sinks_notified, created_at FROM notification_log ORDER BY created_at DESC LIMIT 50"
            )?;
            let rows = stmt.query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, String>(4)?,
                ))
            })?;
            println!(
                "{:<20} {:<10} {:<40} {:<15} Time",
                "Type", "Priority", "Message", "Sinks"
            );
            println!("{}", "-".repeat(100));
            for row in rows {
                let (event_type, priority, message, sinks, time) = row?;
                let msg = if message.len() > 38 {
                    format!("{}...", &message[..35])
                } else {
                    message
                };
                println!(
                    "{:<20} {:<10} {:<40} {:<15} {}",
                    event_type, priority, msg, sinks, time
                );
            }
        }
        NotificationCommands::Config => {
            println!("Notification Sinks:");
            println!("  file: enabled (logs all events to notifications.log)");
            println!("  ntfy: not configured");
            println!("  smtp: not configured");
            println!("  matrix: not configured");
            println!("  signal: not configured");
            println!();
            println!("Rate limiting: max 10 per event type per hour");
        }
    }
    Ok(())
}
