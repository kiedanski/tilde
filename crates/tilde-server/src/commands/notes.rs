use tilde_cli::NotesCommands;
use tilde_core::config::Config;

use super::list_notes_recursive;

pub async fn run_notes(config_path: Option<&str>, command: NotesCommands) -> anyhow::Result<()> {
    let config = Config::load(config_path)?;
    let notes_dir = config.data_dir().join("notes");

    match command {
        NotesCommands::Search { query } => {
            if !notes_dir.exists() {
                println!("Notes directory not found: {}", notes_dir.display());
                return Ok(());
            }

            // Use grep for search — notes are plain files on disk
            let output = std::process::Command::new("grep")
                .args(["-rn", "--include=*.md", "--include=*.txt", "--color=never", &query])
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
