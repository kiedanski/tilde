//! tilde-cli: clap CLI with all subcommands

use clap::{CommandFactory, Parser};
use clap_complete::{Shell, generate};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "tilde", about = "tilde — Personal Cloud Server", version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,

    /// Override config file path
    #[arg(long, global = true)]
    pub config: Option<String>,

    /// JSON output for scripting
    #[arg(long, global = true)]
    pub json: bool,

    /// Show what would happen (on mutating commands)
    #[arg(long, global = true)]
    pub dry_run: bool,

    /// Increase log verbosity
    #[arg(short, long, global = true)]
    pub verbose: bool,

    /// Skip confirmation prompts (for scripting)
    #[arg(long, short = 'y', global = true)]
    pub yes: bool,
}

#[derive(clap::Subcommand)]
pub enum Commands {
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
    /// Bookmarks shorthand: add, list bookmarks
    Bookmarks {
        #[command(subcommand)]
        command: BookmarksCommands,
    },
    /// Trackers shorthand: log and query collection data
    Trackers {
        #[command(subcommand)]
        command: TrackersCommands,
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
    /// Restore from backup snapshot
    Restore {
        /// Backup source (e.g., "local")
        #[arg(long)]
        from: String,
        /// Snapshot ID to restore
        #[arg(long)]
        at: String,
        /// Target directory to restore into
        #[arg(long)]
        to: String,
    },
    /// Export data
    Export {
        #[command(subcommand)]
        command: ExportCommands,
    },
    /// Import data
    Import {
        /// Path to import from
        path: String,
        /// Verify export before importing
        #[arg(long)]
        verify_first: bool,
        /// Show what would be imported without doing it
        #[arg(long)]
        dry_run: bool,
    },
    /// Notification management
    Notifications {
        #[command(subcommand)]
        command: NotificationCommands,
    },
    /// Webhook token management
    Webhook {
        #[command(subcommand)]
        command: WebhookCommands,
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
    /// Install systemd unit file and configure system service
    Install,
    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: Shell,
    },
}

impl Cli {
    /// Generate shell completions and write to stdout
    pub fn print_completions(shell: Shell) {
        let mut cmd = Cli::command();
        generate(shell, &mut cmd, "tilde", &mut std::io::stdout());
    }
}

#[derive(clap::Subcommand)]
pub enum AuthCommands {
    ResetPassword,
    AppPassword {
        #[command(subcommand)]
        command: AppPasswordCommands,
    },
    Session {
        #[command(subcommand)]
        command: SessionCommands,
    },
    /// WebAuthn credential management
    Webauthn {
        #[command(subcommand)]
        command: WebauthnCommands,
    },
}

#[derive(clap::Subcommand)]
pub enum WebauthnCommands {
    /// List registered WebAuthn credentials
    List,
    /// Remove a WebAuthn credential by ID
    Remove {
        /// Credential ID to remove
        id: String,
    },
}

#[derive(clap::Subcommand)]
pub enum AppPasswordCommands {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        scope: String,
    },
    List,
    Revoke {
        id: String,
    },
}

#[derive(clap::Subcommand)]
pub enum SessionCommands {
    List,
    Revoke { id: String },
}

#[derive(clap::Subcommand)]
pub enum McpCommands {
    Token {
        #[command(subcommand)]
        command: TokenCommands,
    },
    Audit {
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        token: Option<String>,
    },
}

#[derive(clap::Subcommand)]
pub enum TokenCommands {
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        scopes: String,
    },
    List,
    Revoke {
        id: String,
    },
    Rotate {
        id: String,
    },
}

#[derive(clap::Subcommand)]
pub enum NotesCommands {
    Search {
        query: String,
    },
    List {
        #[arg(long)]
        path: Option<String>,
    },
}

#[derive(clap::Subcommand)]
pub enum PhotosCommands {
    List {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        since: Option<String>,
        #[arg(long)]
        until: Option<String>,
    },
    Tag {
        uuid: String,
        #[command(subcommand)]
        command: TagCommands,
    },
    Reindex,
    Thumbnail {
        #[command(subcommand)]
        command: ThumbnailCommands,
    },
}

#[derive(clap::Subcommand)]
pub enum TagCommands {
    Add { tag: String },
    Remove { tag: String },
}

#[derive(clap::Subcommand)]
pub enum ThumbnailCommands {
    Regenerate {
        #[arg(long)]
        all: bool,
        #[arg(long)]
        missing: bool,
    },
}

#[derive(clap::Subcommand)]
pub enum CalendarCommands {
    List,
    Events {
        #[arg(long)]
        from: Option<String>,
        #[arg(long)]
        to: Option<String>,
        #[arg(long)]
        calendar: Option<String>,
    },
}

#[derive(clap::Subcommand)]
pub enum ContactsCommands {
    List,
    Search { query: String },
}

#[derive(clap::Subcommand)]
pub enum CollectionCommands {
    Create {
        name: String,
        #[arg(long)]
        schema: String,
    },
    List,
    Add {
        name: String,
        #[arg(long)]
        data: String,
    },
    Get {
        name: String,
        id: String,
    },
    Update {
        name: String,
        id: String,
        #[arg(long)]
        data: String,
    },
    Delete {
        name: String,
        id: String,
    },
    ListRecords {
        name: String,
        #[arg(long)]
        filter: Option<String>,
        #[arg(long)]
        sort: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
    Export {
        name: String,
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(clap::Subcommand)]
pub enum BookmarksCommands {
    /// Add a bookmark
    Add {
        #[arg(long)]
        url: String,
        #[arg(long)]
        title: Option<String>,
        #[arg(long)]
        tags: Option<String>,
        #[arg(long)]
        description: Option<String>,
    },
    /// List bookmarks
    List {
        #[arg(long)]
        tag: Option<String>,
        #[arg(long)]
        limit: Option<u32>,
    },
}

#[derive(clap::Subcommand)]
pub enum TrackersCommands {
    /// Log a data entry to a collection
    Log {
        /// Collection name
        collection: String,
        /// JSON data to log
        data: String,
    },
    /// Query collection data
    Query {
        /// Collection name
        collection: String,
        #[arg(long)]
        since: Option<String>,
        #[arg(long, default_value = "table")]
        format: String,
        #[arg(long)]
        limit: Option<u32>,
    },
}

#[derive(clap::Subcommand)]
pub enum ExportCommands {
    /// Export data to directory
    Run {
        /// Output directory path
        path: String,
        /// Selective export: comma-separated types (photos, notes, calendars, contacts, collections, email)
        #[arg(long)]
        only: Option<String>,
        /// Output format: "dir" (default directory), "tar.zst" (compressed archive)
        #[arg(long)]
        format: Option<String>,
        /// Encrypt the export with age (requires `age` CLI installed)
        #[arg(long)]
        encrypt: bool,
        /// age public key recipient for encryption
        #[arg(long)]
        recipient: Option<String>,
    },
    /// Verify an existing export
    Verify {
        /// Path to export directory to verify
        path: String,
    },
}

#[derive(clap::Subcommand)]
pub enum EmailCommands {
    Search {
        query: String,
    },
    Thread {
        message_id: String,
    },
    Show {
        message_id: String,
    },
    /// Extract attachments from a message
    Attachments {
        #[command(subcommand)]
        command: AttachmentsCommands,
    },
    /// Manage local tags on messages
    Tag {
        /// Message ID
        message_id: String,
        /// Operation: add or remove
        operation: String,
        /// Tag name
        tag: String,
    },
    Reindex,
    Status,
}

#[derive(clap::Subcommand)]
pub enum AttachmentsCommands {
    Extract {
        /// Message ID
        message_id: String,
        /// Output directory
        #[arg(long)]
        to: String,
    },
}

#[derive(clap::Subcommand)]
pub enum BackupCommands {
    Status,
    Now {
        #[arg(long)]
        offsite: Option<String>,
    },
    List {
        #[arg(long)]
        offsite: Option<String>,
    },
    Verify {
        #[arg(long)]
        offsite: Option<String>,
    },
    Pin {
        snapshot_id: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(clap::Subcommand)]
pub enum NotificationCommands {
    Test { sink: String },
    List,
    Config,
}

#[derive(clap::Subcommand)]
pub enum WebhookCommands {
    /// Webhook token management
    Token {
        #[command(subcommand)]
        command: WebhookTokenCommands,
    },
}

#[derive(clap::Subcommand)]
pub enum WebhookTokenCommands {
    /// Create a webhook token
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        scopes: String,
    },
    /// List webhook tokens
    List,
    /// Revoke a webhook token
    Revoke { id: String },
}

#[derive(clap::Subcommand)]
pub enum UpdateCommands {
    Check,
    Download,
}

/// Find the migrations directory
pub fn find_migrations_dir() -> PathBuf {
    let cwd = PathBuf::from("migrations");
    if cwd.exists() {
        return cwd;
    }
    if let Ok(manifest_dir) = std::env::var("CARGO_MANIFEST_DIR") {
        let dev_path = PathBuf::from(manifest_dir).join("../../migrations");
        if dev_path.exists() {
            return dev_path;
        }
    }
    cwd
}
