use clap::Parser;
use tilde_cli::{Cli, Commands};

mod commands;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let config_path = cli.config.clone();

    match cli.command {
        Some(Commands::Init) => commands::run_init(config_path.as_deref()).await,
        Some(Commands::Serve) => commands::run_serve(config_path.as_deref()).await,
        Some(Commands::Status) => commands::run_status(config_path.as_deref()).await,
        Some(Commands::Diagnose) => commands::run_diagnose(config_path.as_deref()).await,
        Some(Commands::Auth { command }) => commands::run_auth(config_path.as_deref(), command).await,
        Some(Commands::Mcp { command }) => commands::run_mcp(config_path.as_deref(), command).await,
        Some(Commands::Completions { shell }) => {
            Cli::print_completions(shell);
            Ok(())
        }
        Some(Commands::Notes { command }) => commands::run_notes(config_path.as_deref(), command).await,
        Some(Commands::Collection { command }) => commands::run_collection(config_path.as_deref(), command).await,
        Some(Commands::Bookmarks { command }) => commands::run_bookmarks(config_path.as_deref(), command).await,
        Some(Commands::Trackers { command }) => commands::run_trackers(config_path.as_deref(), command).await,
        Some(Commands::Webhook { command }) => commands::run_webhook(config_path.as_deref(), command).await,
        Some(Commands::Notifications { command }) => commands::run_notifications(config_path.as_deref(), command).await,
        None => {
            println!("tilde — Personal Cloud Server");
            println!("Run `tilde --help` for usage information.");
            Ok(())
        }
        _ => {
            println!("Command not yet implemented");
            Ok(())
        }
    }
}
