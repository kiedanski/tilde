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
- **Backup** via the `restic` binary with offsite support

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

## Experimental LiveSync notes

Tilde can read and write Markdown notes in an **unencrypted, unobfuscated**
Obsidian Self-hosted LiveSync vault through a separate CouchDB service. Start
with a new database; existing Tilde notes stay where they are until you choose
to migrate them. Add this to Tilde's `config.toml`:

```toml
[notes.livesync]
server_url = "http://127.0.0.1:5984"
public_url = "https://notes.example.com/couchdb/"
database = "tilde_notes"
username = "tilde_sync"
```

Provide the CouchDB password through `TILDE_NOTES__LIVESYNC__PASSWORD` in the
service environment. Provision the database and its restricted member account
with `scripts/configure-couchdb-livesync.py`, or by equivalent CouchDB admin
steps. Run `tilde notes live-sync init-db` to verify the connection and create
the LiveSync version document if needed. This command leaves existing notes
untouched.

Create a Tilde app password with
`tilde auth app-password create --name obsidian-setup --scope /notes/live-sync/setup`
(or use an existing wildcard app password), then open
`https://YOUR-TILDE-HOST/notes/live-sync/setup`
in a browser. Sign in with any username and that app password. The private page
generates a Setup URI and a separate passphrase and walks through connecting
Obsidian. An administrator can also generate those with
`tilde notes live-sync setup-uri --public-url https://notes.example.com/couchdb/`.
The URI carries CouchDB credentials, so keep it private and store its passphrase
separately. The page and CLI use Rust; no TypeScript service is needed.

In LiveSync onboarding, choose **I am adding a device to an existing
synchronisation setup** even for the first device. Its fetch path works with the
restricted CouchDB member and preserves local-only files when **Keep local
files even if not on remote** is chosen. Do not choose **Restart and Initialise
Server**: that action deletes and recreates the database, requires CouchDB
server-admin rights, and can erase MCP notes. After the fetch, select **Use this
device's settings** if the new remote has no saved synchronisation settings,
complete any compatibility review, and run **Self-hosted LiveSync: Sync now**.
Check a note in both directions before enabling the LiveSync preset for ongoing
sync. The Setup URI sets end-to-end encryption and path obfuscation off because
Tilde's Rust reader and MCP tools cannot read encrypted or obfuscated vaults.

Once the same vault is connected in Obsidian, you can run `tilde notes live-sync list` or
`tilde notes live-sync read path/to/note.md`. Use `read path/to/note.md --json`
to get the content and its CouchDB revision together. To create a note, pipe
UTF-8 content to `tilde notes live-sync write path/to/note.md`, or pass
`--file local.md`. To update it, pass `--if-rev REV` using the revision returned
by `read --json` or a previous write. Deletion also requires `--if-rev REV`.
If Obsidian updates a note first, Tilde reports a revision conflict and leaves
the CouchDB note unchanged so you can reconcile the edits. If CouchDB has
unresolved branches for a note, Tilde refuses further writes to that note until
you resolve them in Obsidian; the winning branch may not contain the latest
text. These commands access
LiveSync note and chunk documents directly; production use needs no TypeScript service.
Set up CouchDB and the existing Obsidian plug-in using the
[LiveSync setup guide](https://github.com/vrtmrz/obsidian-livesync/blob/main/docs/setup_own_server.md).
On Ubuntu 24.04, `scripts/install-couchdb-native.sh` installs Apache's native
CouchDB package as a localhost-only service. With that package, add
`additional_paths = ["/var/lib/couchdb", "/opt/couchdb/etc"]` under `[backup]`
so Tilde's scheduled restic snapshot includes the CouchDB database and
configuration. The Tilde service user must have read access to those paths.

When this config is present, MCP `notes.read`, `notes.search`, `notes.create`,
`notes.write`, `notes.append`, and `notes.delete` use the same CouchDB vault.
`notes.read` returns the revision in `metadata.revision`; `notes.write` and
`notes.delete` require that revision. MCP overwrites and deletes archive the
outgoing content in Tilde's local blob store first. The `/dav/notes` mount and the top-level
`tilde notes list/search` commands still use local files. Encrypted vaults and
path obfuscation are not supported by the Rust client.

To check the Rust reader against the upstream TypeScript bridge, run
`bash tests/livesync-oracle/run.sh`. The test clones the bridge at commit
`c3760beaa0851214da4860903445d7f6420ca025`, builds its Docker image,
starts a disposable CouchDB 3.5.0 database, and runs the bridge's CouchDB peer
as a TypeScript oracle. It compares Tilde's note list and each note's UTF-8 size
and SHA-256 hash with the oracle. It also checks that the bridge reads Rust
created chunks and content, that a stale Rust update fails after a bridge edit,
that Rust can update and delete the shared note, and that MCP notes are visible
to the bridge. The script removes its
containers, network, and temporary data when it finishes. Docker and Python 3
are required.

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
│   ├── tilde-email/        # IMAP fetcher, Maildir storage, FTS index
│   ├── tilde-mcp/          # MCP tools, bearer token auth, audit log
│   ├── tilde-backup/       # restic integration (external binary), scheduling
│   └── tilde-notify/       # Notification sinks: ntfy, SMTP, Matrix, Signal
├── migrations/             # SQL migration files
├── locales/                # Fluent .ftl files
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
