use clap::Parser;
use tilde_cli::{Cli, Commands};

mod commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config_path = cli.config.clone();
    let skip_confirm = cli.yes;

    match cli.command {
        Some(Commands::Init) => commands::run_init(config_path.as_deref()).await,
        Some(Commands::Serve) => commands::run_serve(config_path.as_deref()).await,
        Some(Commands::Status) => commands::run_status(config_path.as_deref(), cli.json).await,
        Some(Commands::Diagnose) => commands::run_diagnose(config_path.as_deref()).await,
        Some(Commands::Auth { command }) => {
            commands::run_auth(config_path.as_deref(), command).await
        }
        Some(Commands::Mcp { command }) => commands::run_mcp(config_path.as_deref(), command).await,
        Some(Commands::Completions { shell }) => {
            Cli::print_completions(shell);
            Ok(())
        }
        Some(Commands::Notes { command }) => {
            commands::run_notes(config_path.as_deref(), command).await
        }
        Some(Commands::Collection { command }) => {
            commands::run_collection(config_path.as_deref(), command, skip_confirm).await
        }
        Some(Commands::Bookmarks { command }) => {
            commands::run_bookmarks(config_path.as_deref(), command).await
        }
        Some(Commands::Trackers { command }) => {
            commands::run_trackers(config_path.as_deref(), command).await
        }
        Some(Commands::Webhook { command }) => {
            commands::run_webhook(config_path.as_deref(), command).await
        }
        Some(Commands::Notifications { command }) => {
            commands::run_notifications(config_path.as_deref(), command).await
        }
        Some(Commands::Reindex { r#type }) => {
            commands::run_reindex(config_path.as_deref(), &r#type).await
        }
        Some(Commands::Photos { command }) => {
            commands::run_photos(config_path.as_deref(), command).await
        }
        Some(Commands::Email { command }) => {
            commands::run_email(config_path.as_deref(), command).await
        }
        Some(Commands::Calendar { command }) => {
            commands::run_calendar(config_path.as_deref(), command).await
        }
        Some(Commands::Contacts { command }) => {
            commands::run_contacts(config_path.as_deref(), command).await
        }
        Some(Commands::Export { command }) => {
            commands::run_export(config_path.as_deref(), command).await
        }
        Some(Commands::Import {
            path,
            verify_first,
            dry_run,
        }) => commands::run_import(config_path.as_deref(), &path, verify_first, dry_run).await,
        Some(Commands::Backup { command }) => {
            commands::run_backup(config_path.as_deref(), command).await
        }
        Some(Commands::Install) => commands::run_install().await,
        Some(Commands::Update { command }) => {
            commands::run_update(config_path.as_deref(), command).await
        }
        None => {
            println!("tilde — Personal Cloud Server");
            println!("Run `tilde --help` for usage information.");
            Ok(())
        }
    }
}
