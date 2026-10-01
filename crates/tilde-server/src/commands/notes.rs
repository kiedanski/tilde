use tilde_cli::{LiveSyncNotesCommands, NotesCommands};
use tilde_core::config::Config;

use super::list_notes_recursive;

pub async fn run_notes(config_path: Option<&str>, command: NotesCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let notes_dir = config.data_dir().join("notes");

    match command {
        NotesCommands::LiveSync { command } => {
            let remote = config.notes.livesync.as_ref().ok_or_else(|| {
                anyhow::anyhow!("configure [notes.livesync] before using this command")
            })?;
            let client = tilde_livesync::Client::new(
                &remote.server_url,
                &remote.database,
                &remote.username,
                &remote.password,
            )?;
            match command {
                LiveSyncNotesCommands::InitDb => {
                    let created = client.create_database().await?;
                    client.ensure_version_document().await?;
                    println!("{}", if created { "created" } else { "exists" });
                }
                LiveSyncNotesCommands::SetupUri { public_url } => {
                    let setup = tilde_livesync::generate_setup_uri(
                        &public_url,
                        &remote.database,
                        &remote.username,
                        &remote.password,
                    )?;
                    println!("{}", serde_json::to_string(&setup)?);
                }
                LiveSyncNotesCommands::List => {
                    for note in client.list_notes().await? {
                        println!("{}", note.path);
                    }
                }
                LiveSyncNotesCommands::Read { path, json } => {
                    let note = client
                        .get_note(&path)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("note not found: {path}"))?;
                    if json {
                        println!(
                            "{}",
                            serde_json::json!({
                                "path": note.path,
                                "content": note.content,
                                "revision": note.revision,
                                "modified_ms": note.modified_ms,
                            })
                        );
                    } else {
                        print!("{}", note.content);
                    }
                }
                LiveSyncNotesCommands::Stat { path } => {
                    let note = client
                        .get_note_meta(&path)
                        .await?
                        .ok_or_else(|| anyhow::anyhow!("note not found: {path}"))?;
                    println!("{}", note.revision);
                }
                LiveSyncNotesCommands::Write { path, file, if_rev } => {
                    let content = match file {
                        Some(file) => std::fs::read_to_string(file)?,
                        None => {
                            use std::io::Read;
                            let mut content = String::new();
                            std::io::stdin().read_to_string(&mut content)?;
                            content
                        }
                    };
                    let saved = client.put_note(&path, &content, if_rev.as_deref()).await?;
                    println!("{}", saved.revision);
                }
                LiveSyncNotesCommands::Delete { path, if_rev } => {
                    let revision = client.delete_note(&path, &if_rev).await?;
                    println!("{revision}");
                }
            }
        }
        NotesCommands::Search { query } => {
            if !notes_dir.exists() {
                println!("Notes directory not found: {}", notes_dir.display());
                return Ok(());
            }

            // Use grep for search — notes are plain files on disk
            let output = std::process::Command::new("grep")
                .args([
                    "-rn",
                    "--include=*.md",
                    "--include=*.txt",
                    "--color=never",
                    // `--` terminates option parsing. Without it the query is
                    // itself parsed as an option: "-f/dev/zero" exhausts memory,
                    // and "-e" or "--include=*" swallow the search-directory
                    // operand so grep recurses the process working directory.
                    "--",
                    &query,
                ])
                .arg(&notes_dir)
                .output()?;

            let stdout = String::from_utf8_lossy(&output.stdout);
            if stdout.is_empty() {
                println!("No notes found matching '{}'", query);
            } else {
                let mut count = 0;
                for line in stdout.lines() {
                    // Strip the notes_dir prefix for cleaner output
                    let display = line
                        .strip_prefix(notes_dir.to_str().unwrap_or(""))
                        .map(|s| s.trim_start_matches('/'))
                        .unwrap_or(line);
                    println!("{}", display);
                    count += 1;
                }
                println!("\n{} match(es) found", count);
            }
        }
        NotesCommands::List { path } => {
            let target = match &path {
                Some(p) => notes_dir.join(p),
                None => notes_dir.clone(),
            };

            if !target.exists() {
                println!("Notes directory not found: {}", target.display());
                return Ok(());
            }

            list_notes_recursive(&target, &notes_dir)?;
        }
    }

    Ok(())
}
