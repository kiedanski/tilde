use tilde_cli::ContactsCommands;
use tilde_core::{config::Config, db};

pub async fn run_contacts(
    config_path: Option<&str>,
    command: ContactsCommands,
) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;

    match command {
        ContactsCommands::List => {
            let contacts = tilde_card::list_contacts(&conn);
            if contacts.is_empty() {
                println!("No contacts found.");
            } else {
                println!(
                    "{:<38} {:<30} {:<30} {:<20} ORG",
                    "UID", "NAME", "EMAIL", "PHONE"
                );
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!(
                        "{:<38} {:<30} {:<30} {:<20} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        name.as_deref().unwrap_or("-"),
                        email.as_deref().unwrap_or("-"),
                        phone.as_deref().unwrap_or("-"),
                        org.as_deref().unwrap_or(""),
                    );
                }
            }
        }
        ContactsCommands::Search { query } => {
            let contacts = tilde_card::search_contacts(&conn, &query);
            if contacts.is_empty() {
                println!("No contacts matching '{}'.", query);
            } else {
                println!(
                    "{:<38} {:<30} {:<30} {:<20} ORG",
                    "UID", "NAME", "EMAIL", "PHONE"
                );
                println!("{}", "-".repeat(140));
                for (uid, name, email, phone, org) in &contacts {
                    println!(
                        "{:<38} {:<30} {:<30} {:<20} {}",
                        &uid[..std::cmp::min(36, uid.len())],
                        name.as_deref().unwrap_or("-"),
                        email.as_deref().unwrap_or("-"),
                        phone.as_deref().unwrap_or("-"),
                        org.as_deref().unwrap_or(""),
                    );
                }
            }
        }
    }
    Ok(())
}
