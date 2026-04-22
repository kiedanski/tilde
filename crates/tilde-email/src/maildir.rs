//! Maildir storage with atomic writes (tmp → cur)

use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

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

    /// Ensure Maildir subdirectories exist for account/folder.
    pub fn ensure_dirs(&self, account: &str, folder: &str) -> Result<PathBuf> {
        let folder_path = self.base_path.join(account).join(folder);
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

        // Return relative path
        let rel_path = format!("{}/{}/cur/{}", account, folder, cur_name);
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
        let account_path = self.base_path.join(account);
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
        let folder_path = self.base_path.join(account).join(folder);
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
                    let rel_path = format!("{}/{}/{}/{}", account, folder, subdir, filename);
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
        let full_path = self.base_path.join(rel_path);
        fs::read(&full_path).with_context(|| format!("Failed to read message at {:?}", full_path))
    }
}

pub struct MaildirMessage {
    pub path: String,
    pub raw: Vec<u8>,
}
