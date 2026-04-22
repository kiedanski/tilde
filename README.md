# tilde — Personal Cloud Server

A monolithic Rust binary serving open protocols (WebDAV, CalDAV, CardDAV, MCP, IMAP-as-client) that reuse existing mature client ecosystems rather than inventing new ones.

## What it does

- **File sync** via WebDAV (Nextcloud-compatible: desktop sync clients, mobile apps, rclone)
- **Calendar & contacts** via CalDAV/CardDAV (iOS, DAVx5, Thunderbird, Evolution)
- **Photo management** with auto-organization, EXIF metadata, and thumbnail generation
- **Notes** as plain markdown files over WebDAV (Joplin, Obsidian, iA Writer)
- **Email archive** via IMAP client with full-text search (read-only mirror)
- **Structured data** via generic collections (trackers, bookmarks, habits)
- **AI integration** via MCP (Model Context Protocol) with scoped access
- **Backup** via embedded restic-compatible library with offsite support

## Target

Single-user. CLI-first. Files are the source of truth. SQLite is a rebuildable cache. Export-first architecture — you can leave at any time.

**Footprint:** 1 vCPU, 256–512MB RAM, 15–30MB static musl binary.

## Quick start

```bash
# Clone and set up environment
cp .env.example .env
# Edit .env with your values (at minimum: TILDE_ADMIN_PASSWORD, TILDE_HOSTNAME)

# Initialize development environment
chmod +x init.sh
./init.sh

# Run the server
cargo run -- serve
```

## Project structure

```
tilde/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── tilde-core/         # Config, auth, database, migrations, error types
│   ├── tilde-server/       # axum app assembly, main binary entry point
│   ├── tilde-cli/          # clap CLI, all subcommands
│   ├── tilde-dav/          # WebDAV Class 1, chunked upload, file sync
│   ├── tilde-cal/          # CalDAV via RustiCal
│   ├── tilde-card/         # CardDAV via RustiCal
│   ├── tilde-photos/       # Photo ingestion, metadata, thumbnails
│   ├── tilde-notes/        # Markdown notes over WebDAV
│   ├── tilde-collections/  # Generic trackers, bookmarks, structured data
│   ├── tilde-email/        # IMAP fetcher, Maildir storage, FTS index
│   ├── tilde-mcp/          # MCP tools, bearer token auth, audit log
│   ├── tilde-backup/       # rustic-rs integration, scheduling
│   └── tilde-notify/       # Notification sinks: ntfy, SMTP, Matrix, Signal
├── migrations/             # SQL migration files
├── locales/                # Fluent .ftl files
└── assets/                 # Login page HTML (embedded via rust-embed)
```

## Technology stack

- **Language:** Rust (stable, 2024 edition)
- **HTTP:** axum 0.8+ with tower middleware
- **Database:** rusqlite (SQLite WAL, FTS5, JSON1)
- **TLS:** rustls + rustls-acme (auto-provisioning)
- **CalDAV/CardDAV:** RustiCal
- **MCP:** rmcp 1.5.x (Streamable HTTP)
- **CLI:** clap 4

## License

AGPL-3.0
