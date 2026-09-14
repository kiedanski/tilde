//! Maildir storage with atomic writes (tmp → cur)

use anyhow::{Context, Result, bail};
use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

/// Turn an untrusted name into a safe *relative* path under the Maildir root.
///
/// Mailbox names arrive straight off the wire in the IMAP server's `LIST`
/// response, so a hostile or compromised server chooses them. `base.join(name)`
/// with an absolute name such as `/etc/cron.d` silently discards `base`
/// entirely — no `..` needed — and `../..` walks out of the tree.
///
/// Hierarchy is preserved for benign names (`INBOX/Archive` stays nested);
/// anything that could relocate the path is refused.
pub fn sanitize_relative_name(name: &str) -> Result<PathBuf> {
    if name.is_empty() {
        bail!("Empty Maildir name");
    }
    if name.chars().any(|c| c.is_control()) {
        bail!("Maildir name contains control characters: {:?}", name);
    }

    let mut out = PathBuf::new();
    for component in Path::new(name).components() {
        match component {
            Component::Normal(part) => {
                let part = part
                    .to_str()
                    .with_context(|| format!("Maildir name is not valid UTF-8: {:?}", name))?;
                // A component of nothing but dots is either a no-op or a
                // traversal; on platforms where `..` is not parsed as
                // ParentDir it would still be one on disk.
                if part.chars().all(|c| c == '.') {
                    bail!("Maildir name contains a dot-only segment: {:?}", name);
                }
                out.push(part);
            }
            Component::CurDir => {}
            Component::ParentDir => {
                bail!(
                    "Maildir name escapes the Maildir root with `..`: {:?}",
                    name
                )
            }
            Component::RootDir | Component::Prefix(_) => {
                bail!("Absolute Maildir name refused: {:?}", name)
            }
        }
    }

    if out.as_os_str().is_empty() {
        bail!("Maildir name has no usable segments: {:?}", name);
    }
    Ok(out)
}

/// Resolve `.` and `..` textually, without touching the filesystem.
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Canonicalise the part of `path` that exists, then append the rest with
/// `.`/`..` resolved. Works for paths that have not been created yet, while
/// still resolving symlinks in the part that has.
fn canonicalize_best_effort(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<OsString> = Vec::new();

    loop {
        if let Ok(real) = existing.canonicalize() {
            let mut out = real;
            for part in tail.iter().rev() {
                out.push(part);
            }
            return normalize_lexically(&out);
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return normalize_lexically(path),
        }
    }
}

/// Confirm `candidate` resolves inside `root`.
///
/// `Path::starts_with` is component-wise and never resolves `..`, so it cannot
/// prove this on its own.
fn ensure_within(root: &Path, candidate: &Path) -> Result<()> {
    let root_real = canonicalize_best_effort(root);
    let candidate_real = canonicalize_best_effort(candidate);
    if candidate_real.starts_with(&root_real) {
        Ok(())
    } else {
        bail!(
            "Maildir path escapes {}: {} resolves to {}",
            root.display(),
            candidate.display(),
            candidate_real.display()
        )
    }
}

/// Writes emails to Maildir format with atomic semantics.
pub struct MaildirWriter {
    base_path: PathBuf,
}

impl MaildirWriter {
    pub fn new(base_path: &Path) -> Result<Self> {
        Ok(Self {
            base_path: base_path.to_path_buf(),
        })
    }

    /// Resolve `<base>/<account>/<folder>`, refusing anything that would leave
    /// the Maildir root. Does not touch the filesystem.
    fn resolve_folder(&self, account: &str, folder: &str) -> Result<PathBuf> {
        let account_rel =
            sanitize_relative_name(account).context("Invalid Maildir account name")?;
        let folder_rel = sanitize_relative_name(folder).context("Invalid Maildir folder name")?;
        let path = self.base_path.join(account_rel).join(folder_rel);
        ensure_within(&self.base_path, &path)?;
        Ok(path)
    }

    /// Ensure Maildir subdirectories exist for account/folder.
    pub fn ensure_dirs(&self, account: &str, folder: &str) -> Result<PathBuf> {
        let folder_path = self.resolve_folder(account, folder)?;
        fs::create_dir_all(folder_path.join("cur"))?;
        fs::create_dir_all(folder_path.join("new"))?;
        fs::create_dir_all(folder_path.join("tmp"))?;
        Ok(folder_path)
    }

    /// Atomically write an email to Maildir: tmp/ → cur/
    /// Returns the relative path within the Maildir tree.
    pub fn write_message(
        &self,
        account: &str,
        folder: &str,
        uid: u32,
        raw_bytes: &[u8],
    ) -> Result<String> {
        let folder_path = self.ensure_dirs(account, folder)?;
        let unique_name = format!(
            "{}.{}.{}",
            jiff::Timestamp::now().as_second(),
            Uuid::new_v4(),
            uid
        );

        // Write to tmp/ first
        let tmp_path = folder_path.join("tmp").join(&unique_name);
        fs::write(&tmp_path, raw_bytes)
            .with_context(|| format!("Failed to write to tmp: {:?}", tmp_path))?;

        // Atomic move to cur/ with flags suffix
        let cur_name = format!("{}:2,S", unique_name); // S = Seen flag
        let cur_path = folder_path.join("cur").join(&cur_name);
        fs::rename(&tmp_path, &cur_path).with_context(|| {
            format!(
                "Failed to rename tmp → cur: {:?} → {:?}",
                tmp_path, cur_path
            )
        })?;

        // Return relative path — derived from the sanitized folder path so it
        // always matches what was actually written.
        let rel_dir = folder_path
            .strip_prefix(&self.base_path)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default();
        let rel_path = format!("{}/cur/{}", rel_dir, cur_name);
        Ok(rel_path)
    }
}

/// Reads emails from Maildir format.
pub struct MaildirReader {
    base_path: PathBuf,
}

impl MaildirReader {
    pub fn new(base_path: &Path) -> Self {
        Self {
            base_path: base_path.to_path_buf(),
        }
    }

    /// List all accounts (top-level directories).
    pub fn list_accounts(&self) -> Result<Vec<String>> {
        let mut accounts = Vec::new();
        if !self.base_path.exists() {
            return Ok(accounts);
        }
        for entry in fs::read_dir(&self.base_path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir()
                && let Some(name) = entry.file_name().to_str()
            {
                accounts.push(name.to_string());
            }
        }
        accounts.sort();
        Ok(accounts)
    }

    /// List all folders for an account.
    pub fn list_folders(&self, account: &str) -> Result<Vec<String>> {
        let mut folders = Vec::new();
        let account_rel =
            sanitize_relative_name(account).context("Invalid Maildir account name")?;
        let account_path = self.base_path.join(account_rel);
        ensure_within(&self.base_path, &account_path)?;
        if !account_path.exists() {
            return Ok(folders);
        }
        for entry in fs::read_dir(&account_path)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                // Check if it has cur/ subdirectory (valid Maildir folder)
                if entry.path().join("cur").exists()
                    && let Some(name) = entry.file_name().to_str()
                {
                    folders.push(name.to_string());
                }
            }
        }
        folders.sort();
        Ok(folders)
    }

    /// Iterate over all messages in a folder (cur/ and new/).
    pub fn read_folder(&self, account: &str, folder: &str) -> Result<Vec<MaildirMessage>> {
        let account_rel =
            sanitize_relative_name(account).context("Invalid Maildir account name")?;
        let folder_rel = sanitize_relative_name(folder).context("Invalid Maildir folder name")?;
        let folder_path = self.base_path.join(account_rel).join(folder_rel);
        ensure_within(&self.base_path, &folder_path)?;
        let mut messages = Vec::new();

        for subdir in &["cur", "new"] {
            let dir_path = folder_path.join(subdir);
            if !dir_path.exists() {
                continue;
            }
            for entry in fs::read_dir(&dir_path)? {
                let entry = entry?;
                if entry.file_type()?.is_file() {
                    let filename = entry.file_name().to_string_lossy().to_string();
                    let raw = fs::read(entry.path())?;
                    let rel_dir = folder_path
                        .strip_prefix(&self.base_path)
                        .map(|p| p.to_string_lossy().to_string())
                        .unwrap_or_default();
                    let rel_path = format!("{}/{}/{}", rel_dir, subdir, filename);
                    messages.push(MaildirMessage {
                        path: rel_path,
                        raw,
                    });
                }
            }
        }

        Ok(messages)
    }

    /// Read a single message by its relative Maildir path.
    pub fn read_message(&self, rel_path: &str) -> Result<Vec<u8>> {
        let rel = sanitize_relative_name(rel_path).context("Invalid Maildir message path")?;
        let full_path = self.base_path.join(rel);
        ensure_within(&self.base_path, &full_path)?;
        fs::read(&full_path).with_context(|| format!("Failed to read message at {:?}", full_path))
    }
}

pub struct MaildirMessage {
    pub path: String,
    pub raw: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "tilde_maildir_{}_{}_{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_absolute_mailbox_name_is_refused() {
        // The headline case: no `..` at all, but `base.join("/etc/cron.d")`
        // throws the base away.
        assert!(sanitize_relative_name("/etc/cron.d").is_err());
        assert!(sanitize_relative_name("/").is_err());
    }

    #[test]
    fn test_traversing_mailbox_names_are_refused() {
        for name in [
            "../../etc",
            "INBOX/../../../etc",
            "..",
            ".",
            "",
            "INBOX/../..",
            "a/./../..",
        ] {
            assert!(
                sanitize_relative_name(name).is_err(),
                "{:?} should have been refused",
                name
            );
        }
        assert!(sanitize_relative_name("INBOX\nX-Evil: 1").is_err());
    }

    #[test]
    fn test_benign_mailbox_names_are_preserved() {
        for name in [
            "INBOX",
            "Sent",
            "INBOX/Archive",
            "INBOX.Archive",
            "[Gmail]/All Mail",
            "Travel/2026 - Japan",
        ] {
            assert_eq!(
                sanitize_relative_name(name).unwrap(),
                PathBuf::from(name),
                "{:?} is a legitimate mailbox name and must be preserved",
                name
            );
        }
    }

    #[test]
    fn test_write_message_refuses_absolute_folder_name() {
        let base = scratch("escape");
        let maildir = base.join("maildir");
        let victim = base.join("victim");
        fs::create_dir_all(&maildir).unwrap();
        fs::create_dir_all(&victim).unwrap();

        let writer = MaildirWriter::new(&maildir).unwrap();
        let hostile = victim.to_str().unwrap().to_string();
        let result = writer.write_message("personal", &hostile, 1, b"From: evil\r\n\r\nhi\r\n");

        assert!(
            result.is_err(),
            "an absolute LIST mailbox name must be refused, got {:?}",
            result
        );
        // Without the fix, ensure_dirs would have created these and the
        // message would be sitting in victim/cur/.
        assert!(
            !victim.join("cur").exists(),
            "a Maildir was created outside the base at {}",
            victim.display()
        );
        assert!(!victim.join("tmp").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_write_message_refuses_traversing_folder_name() {
        let base = scratch("traverse");
        let maildir = base.join("maildir");
        fs::create_dir_all(&maildir).unwrap();

        let writer = MaildirWriter::new(&maildir).unwrap();
        assert!(
            writer
                .write_message("personal", "../../escaped", 1, b"x")
                .is_err()
        );
        assert!(!base.join("escaped").exists());
        assert!(!base.parent().unwrap().join("escaped").exists());

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_write_and_read_message_roundtrip() {
        let base = scratch("roundtrip");
        let maildir = base.join("maildir");

        let writer = MaildirWriter::new(&maildir).unwrap();
        let rel = writer
            .write_message("personal", "INBOX/Archive", 42, b"From: a\r\n\r\nbody\r\n")
            .expect("ordinary nested mailbox names must still work");

        assert!(
            rel.starts_with("personal/INBOX/Archive/cur/"),
            "got {}",
            rel
        );

        let reader = MaildirReader::new(&maildir);
        assert_eq!(
            reader.read_message(&rel).unwrap(),
            b"From: a\r\n\r\nbody\r\n"
        );
        assert_eq!(
            reader.list_accounts().unwrap(),
            vec!["personal".to_string()]
        );
        assert_eq!(
            reader
                .read_folder("personal", "INBOX/Archive")
                .unwrap()
                .len(),
            1
        );

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn test_read_message_refuses_escaping_path() {
        let base = scratch("read_escape");
        let maildir = base.join("maildir");
        fs::create_dir_all(&maildir).unwrap();
        let secret = base.join("secret.txt");
        fs::write(&secret, b"top secret").unwrap();

        let reader = MaildirReader::new(&maildir);
        assert!(reader.read_message("../secret.txt").is_err());
        assert!(reader.read_message(secret.to_str().unwrap()).is_err());

        let _ = fs::remove_dir_all(&base);
    }
}
