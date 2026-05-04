use tilde_cli::CalendarCommands;
use tilde_core::{config::Config, db};

pub async fn run_calendar(
    config_path: Option<&str>,
    command: CalendarCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        CalendarCommands::List => {
            let calendars = tilde_cal::list_calendars(&conn);
            if calendars.is_empty() {
                println!("No calendars found.");
            } else {
                println!(
                    "{:<20} {:<30} {:<10} DESCRIPTION",
                    "NAME", "DISPLAY NAME", "CTAG"
                );
                println!("{}", "-".repeat(80));
                for (name, display_name, ctag, desc) in &calendars {
                    println!(
                        "{:<20} {:<30} {:<10} {}",
                        name,
                        display_name,
                        ctag,
                        desc.as_deref().unwrap_or("")
                    );
                }
            }
        }
        CalendarCommands::Events { from, to, calendar } => {
            let events =
                tilde_cal::list_events(&conn, calendar.as_deref(), from.as_deref(), to.as_deref());
            if events.is_empty() {
                println!("No events found.");
            } else {
                println!(
                    "{:<38} {:<8} {:<30} {:<22} {:<22} LOCATION",
                    "UID", "TYPE", "SUMMARY", "START", "END"
                );
                println!("{}", "-".repeat(140));
                for (uid, comp_type, summary, dtstart, dtend, location, _status) in &events {
                    println!(
                        "{:<38} {:<8} {:<30} {:<22} {:<22} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        comp_type,
                        summary.as_deref().unwrap_or("(untitled)"),
                        dtstart.as_deref().unwrap_or("-"),
                        dtend.as_deref().unwrap_or("-"),
                        location.as_deref().unwrap_or(""),
                    );
                }
            }
        }
    }
    Ok(())
}
