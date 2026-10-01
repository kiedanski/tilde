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
    /// Gadgetbridge health-data import
    Gadgetbridge {
        #[command(subcommand)]
        command: GadgetbridgeCommands,
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
        /// Remove DB entries for files that no longer exist on disk
        #[arg(long)]
        prune: bool,
    },
    /// Update management
    Update {
        #[command(subcommand)]
        command: UpdateCommands,
    },
    /// Show file counts, storage breakdown, and recent activity
    Usage,
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
    AppPassword {
        #[command(subcommand)]
        command: AppPasswordCommands,
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
    /// Read and write an unencrypted Obsidian LiveSync vault in CouchDB
    LiveSync {
        #[command(subcommand)]
        command: LiveSyncNotesCommands,
    },
}

#[derive(clap::Subcommand)]
pub enum LiveSyncNotesCommands {
    /// Verify an existing database or create one with admin rights; seed its version document
    InitDb,
    /// Generate an Obsidian Setup URI for a pre-provisioned vault
    SetupUri {
        /// Public CouchDB URL, including any reverse-proxy path
        #[arg(long)]
        public_url: String,
    },
    /// List note paths in CouchDB
    List,
    /// Read a note from CouchDB
    Read {
        path: String,
        /// Include the note revision and metadata in a JSON object
        #[arg(long)]
        json: bool,
    },
    /// Print a note's current CouchDB revision
    Stat { path: String },
    /// Create a note, or replace the exact revision given by --if-rev
    Write {
        path: String,
        /// Read UTF-8 content from this file; stdin is used if omitted
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        /// Revision returned by stat or a previous write
        #[arg(long)]
        if_rev: Option<String>,
    },
    /// Soft-delete the exact revision given by --if-rev
    Delete {
        path: String,
        #[arg(long)]
        if_rev: String,
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
pub enum GadgetbridgeCommands {
    /// Process the health inbox (or a specific database export) into CSVs
    Import {
        /// Path to a Gadgetbridge.db export; default: everything in files/health/_inbox/
        #[arg(long)]
        db: Option<String>,
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
    /// Show email sync status
    Status,
}

#[derive(clap::Subcommand)]
pub enum BackupCommands {
    /// Show backup status, repository info, and last run time
    Status,
    /// Run a backup now (incremental, encrypted, uploaded to B2)
    Now,
    /// List snapshots in the backup repository
    List,
    /// Verify repository integrity
    Verify,
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
    /// Check if a newer version is available
    Check,
    /// Download the latest version to a staging path
    Download,
    /// Download, replace binary, and signal the running server to re-exec
    Apply,
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
