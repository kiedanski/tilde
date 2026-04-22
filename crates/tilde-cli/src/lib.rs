//! tilde-cli: clap CLI with all subcommands

use clap::Parser;
use tracing::info;

#[derive(Parser)]
#[command(name = "tilde", about = "tilde — Personal Cloud Server", version)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Override config file path
    #[arg(long, global = true)]
    config: Option<String>,

    /// JSON output for scripting
    #[arg(long, global = true)]
    json: bool,

    /// Show what would happen (on mutating commands)
    #[arg(long, global = true)]
    dry_run: bool,

    /// Increase log verbosity
    #[arg(short, long, global = true)]
    verbose: bool,
}

#[derive(clap::Subcommand)]
enum Commands {
    /// Interactive setup wizard
    Init,
    /// Start server (foreground, for systemd)
    Serve,
    /// Show server state, disk usage, backup status
    Status,
    /// Self-check: config, connectivity, cert, disk, dependencies
    Diagnose,
    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    /// MCP token management
    Mcp {
        #[command(subcommand)]
        command: McpCommands,
    },
    /// Notes management
    Notes {
        #[command(subcommand)]
        command: NotesCommands,
    },
    /// Photo management
    Photos {
        #[command(subcommand)]
        command: PhotosCommands,
    },
    /// Calendar operations
    Calendar {
        #[command(subcommand)]
        command: CalendarCommands,
    },
    /// Contacts operations
    Contacts {
        #[command(subcommand)]
        command: ContactsCommands,
    },
    /// Collection management
    Collection {
        #[command(subcommand)]
        command: CollectionCommands,
    },
    /// Email archive operations
    Email {
        #[command(subcommand)]
        command: EmailCommands,
    },
    /// Backup operations
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },
    /// Export data
    Export {
        path: String,
    },
    /// Import data
    Import {
        path: String,
    },
    /// Notification management
    Notifications {
        #[command(subcommand)]
        command: NotificationCommands,
    },
    /// Rebuild indexes
    Reindex {
        #[arg(long, default_value = "all")]
        r#type: String,
    },
    /// Update management
    Update {
        #[command(subcommand)]
        command: UpdateCommands,
    },
}

#[derive(clap::Subcommand)]
enum AuthCommands {
    ResetPassword,
    AppPassword {
        #[command(subcommand)]
        command: AppPasswordCommands,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
}

#[derive(clap::Subcommand)]
enum AppPasswordCommands {
    Create { #[arg(long)] name: String, #[arg(long)] scope: String },
    List,
    Revoke { id: String },
}

#[derive(clap::Subcommand)]
enum SessionCommands {
    List,
    Revoke { id: String },
}

#[derive(clap::Subcommand)]
enum McpCommands {
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },
    Audit {
        #[arg(long)] since: Option<String>,
        #[arg(long)] tool: Option<String>,
        #[arg(long)] token: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum TokenCommands {
    Create { #[arg(long)] name: String, #[arg(long)] scopes: String },
    List,
    Revoke { id: String },
    Rotate { id: String },
}

#[derive(clap::Subcommand)]
enum NotesCommands {
    Search { query: String },
    List { #[arg(long)] path: Option<String> },
}

#[derive(clap::Subcommand)]
enum PhotosCommands {
    List {
        #[arg(long)] tag: Option<String>,
        #[arg(long)] since: Option<String>,
        #[arg(long)] until: Option<String>,
    },
    Tag { uuid: String, #[command(subcommand)] command: TagCommands },
    Reindex,
    Thumbnail {
        #[command(subcommand)]
        command: ThumbnailCommands,
    },
}

#[derive(clap::Subcommand)]
enum TagCommands {
    Add { tag: String },
    Remove { tag: String },
}

#[derive(clap::Subcommand)]
enum ThumbnailCommands {
    Regenerate {
        #[arg(long)] all: bool,
        #[arg(long)] missing: bool,
    },
}

#[derive(clap::Subcommand)]
enum CalendarCommands {
    List,
    Events {
        #[arg(long)] from: Option<String>,
        #[arg(long)] to: Option<String>,
        #[arg(long)] calendar: Option<String>,
    },
}

#[derive(clap::Subcommand)]
enum ContactsCommands {
    List,
    Search { query: String },
}

#[derive(clap::Subcommand)]
enum CollectionCommands {
    Create { name: String, #[arg(long)] schema: String },
    List,
}

#[derive(clap::Subcommand)]
enum EmailCommands {
    Search { query: String },
    Thread { message_id: String },
    Show { message_id: String },
    Reindex,
    Status,
}

#[derive(clap::Subcommand)]
enum BackupCommands {
    Status,
    Now { #[arg(long)] offsite: Option<String> },
    List { #[arg(long)] offsite: Option<String> },
    Verify { #[arg(long)] offsite: Option<String> },
    Pin { snapshot_id: String, #[arg(long)] reason: String },
}

#[derive(clap::Subcommand)]
enum NotificationCommands {
    Test { sink: String },
    List,
    Config,
}

#[derive(clap::Subcommand)]
enum UpdateCommands {
    Check,
    Download,
}

impl Cli {
    pub async fn run(self) -> anyhow::Result<()> {
        match self.command {
            Some(Commands::Serve) => {
                info!("Starting tilde server...");
                // TODO: Build and run axum server
                println!("tilde server starting... (not yet implemented)");
                Ok(())
            }
            Some(Commands::Init) => {
                info!("Running init wizard...");
                println!("tilde init wizard (not yet implemented)");
                Ok(())
            }
            Some(Commands::Status) => {
                println!("tilde status (not yet implemented)");
                Ok(())
            }
            Some(Commands::Diagnose) => {
                println!("tilde diagnose (not yet implemented)");
                Ok(())
            }
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
}
