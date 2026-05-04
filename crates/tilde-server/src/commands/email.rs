use tilde_cli::EmailCommands;
use tilde_core::{config::Config, db};

use super::count_files_recursive;

pub async fn run_email(config_path: Option<&str>, command: EmailCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let conn = db::init_db(config.db_path().to_str().unwrap())?;
    let migrations_dir = tilde_cli::find_migrations_dir();
    db::run_migrations(&conn, &migrations_dir)?;
    let mail_dir = config.data_dir().join("mail");

    match command {
        EmailCommands::Status => {
            println!("Email Archive Status");
            println!("====================");

            // Show sync status from kv_meta
            for account_cfg in &config.email.accounts {
                let status = tilde_email::imap::get_sync_status(&conn, &account_cfg.name);
                println!("Account: {}", status.account);
                println!(
                    "  Last sync: {}",
                    status.last_sync.as_deref().unwrap_or("never")
                );
                println!("  Folders: {}", status.folders.join(", "));

                // Count Maildir files on disk
                let maildir_account = mail_dir.join(&account_cfg.name);
                if maildir_account.exists() {
                    let file_count: usize = count_files_recursive(&maildir_account);
                    println!("  Maildir files: {}", file_count);
                }
            }
        }
    }
    Ok(())
}
