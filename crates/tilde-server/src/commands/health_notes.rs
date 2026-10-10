//! Mirror the monthly health notes into the LiveSync vault.
//!
//! Once `[notes.livesync]` is configured, Obsidian reads CouchDB rather than
//! the on-disk notes tree, so writing the mirror to disk would land it where
//! no device ever looks.

use tilde_health::HealthNote;
use tilde_livesync::{Client, Error};

/// Write each month to `<dir>/<YYYY-MM>.md` in the vault and return how many
/// notes changed. A month whose content is already current is skipped, so an
/// import does not push an identical revision to every Obsidian device.
pub(crate) async fn mirror_to_livesync(
    client: &Client,
    dir: &str,
    notes: &[HealthNote],
) -> anyhow::Result<usize> {
    let dir = dir.trim_matches('/');
    let mut written = 0;
    for note in notes {
        let path = if dir.is_empty() {
            format!("{}.md", note.title)
        } else {
            format!("{dir}/{}.md", note.title)
        };
        if put_generated(client, &path, &note.body).await? {
            written += 1;
        }
    }
    Ok(written)
}

/// Replace `path` with `body` whatever revision is current. These notes are
/// generated and say that edits are lost, so a concurrent change is re-read
/// once and overwritten rather than reported as a conflict.
async fn put_generated(client: &Client, path: &str, body: &str) -> anyhow::Result<bool> {
    for _ in 0..2 {
        let current = client.get_note(path).await?;
        if current.as_ref().is_some_and(|note| note.content == body) {
            return Ok(false);
        }
        let revision = current.as_ref().map(|note| note.revision.as_str());
        match client.put_note(path, body, revision).await {
            Ok(_) => return Ok(true),
            Err(Error::Conflict | Error::AlreadyExists) => continue,
            Err(err) => return Err(err.into()),
        }
    }
    anyhow::bail!("{path} kept changing while the health notes were written")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn note(title: &str, body: &str) -> HealthNote {
        HealthNote {
            title: title.into(),
            body: body.into(),
        }
    }

    /// Point TILDE_TEST_COUCHDB at a disposable CouchDB with admin/testpassword
    /// (e.g. the container tests/livesync-oracle/run.sh starts).
    #[tokio::test]
    #[ignore = "requires a disposable CouchDB in TILDE_TEST_COUCHDB"]
    async fn mirrors_months_and_skips_unchanged() {
        let server = std::env::var("TILDE_TEST_COUCHDB").unwrap();
        let client = Client::new(&server, "tilde_health_notes", "admin", "testpassword").unwrap();
        client.create_database().await.unwrap();
        client.ensure_version_document().await.unwrap();

        let first = [note("2026-09", "# Sep\n"), note("2026-10", "# Oct\n")];
        assert_eq!(
            mirror_to_livesync(&client, "/health/", &first)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            mirror_to_livesync(&client, "health", &first).await.unwrap(),
            0
        );

        // An edit made in Obsidian is overwritten by the next import.
        let edited = client.get_note("health/2026-10.md").await.unwrap().unwrap();
        client
            .put_note("health/2026-10.md", "hand edit\n", Some(&edited.revision))
            .await
            .unwrap();
        let second = [note("2026-09", "# Sep\n"), note("2026-10", "# Oct, more\n")];
        assert_eq!(
            mirror_to_livesync(&client, "health", &second)
                .await
                .unwrap(),
            1
        );
        let oct = client.get_note("health/2026-10.md").await.unwrap().unwrap();
        assert_eq!(oct.content, "# Oct, more\n");
    }
}
