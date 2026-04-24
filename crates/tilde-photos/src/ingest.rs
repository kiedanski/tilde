//! Photo ingestion pipeline
//!
//! Processes files from _inbox/ and _library-drop/ directories.

use crate::{is_encrypted, is_photo_ext, is_video_ext, metadata, organize, validate_magic_bytes};
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

/// Process a single file from the _inbox/ directory.
///
/// 1. Validate file type by magic bytes
/// 2. Read metadata via ExifTool
/// 3. Compute destination via organization pattern
/// 4. Move file to organized location
/// 5. Index in database
pub fn process_inbox_file(
    conn: &Connection,
    file_path: &Path,
    photos_base: &Path,
    organization_pattern: &str,
) -> Result<IngestResult> {
    let filename = file_path
        .file_name()
        .context("No filename")?
        .to_string_lossy()
        .to_string();

    info!(file = %filename, "Processing inbox file");

    // Dedup: skip files already processed (prevents re-processing on restart)
    let sha256 = crate::compute_sha256(file_path)?;
    let already_processed: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM photos WHERE original_sha256 = ?1",
        rusqlite::params![sha256],
        |row| row.get(0),
    )?;
    if already_processed {
        debug!(file = %filename, "Inbox file already processed, skipping");
        return Ok(IngestResult::AlreadyProcessed);
    }

    // Step 1: Validate magic bytes
    let content_type = match validate_magic_bytes(file_path) {
        Some(ct) => ct.to_string(),
        None => {
            // Fall back to extension-based type
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if is_photo_ext(ext) {
                format!("image/{}", ext.to_lowercase())
            } else if is_video_ext(ext) {
                format!("video/{}", ext.to_lowercase())
            } else {
                return copy_to_errors(
                    file_path,
                    photos_base,
                    "Unsupported file type: magic bytes not recognized and extension not a known photo/video type",
                );
            }
        }
    };

    // Step 2: Handle encrypted files
    if is_encrypted(&content_type) {
        info!(file = %filename, "Encrypted file detected, storing as opaque blob");
        let dest = photos_base.join(&filename);
        if dest != file_path {
            std::fs::copy(file_path, &dest)
                .context("Failed to copy encrypted file")?;
        }
        let photo_id = crate::index_photo(conn, &dest, photos_base, &content_type)?;
        return Ok(IngestResult::Indexed {
            photo_id,
            destination: dest,
        });
    }

    // Step 3: Read metadata via ExifTool
    let metadata = match metadata::read_metadata(file_path) {
        Ok(m) => m,
        Err(e) => {
            warn!(file = %filename, error = %e, "Failed to read metadata, using defaults");
            metadata::PhotoMetadata::default()
        }
    };

    // Step 4: Check if metadata is sufficient for organization
    if !organize::has_sufficient_metadata(&metadata) {
        info!(file = %filename, "Insufficient metadata, moving to _untriaged/");
        let untriaged_dir = photos_base.join("_untriaged");
        std::fs::create_dir_all(&untriaged_dir)?;
        let dest = untriaged_dir.join(&filename);
        let dest = unique_path(&dest);
        std::fs::copy(file_path, &dest)
            .context("Failed to copy file to untriaged")?;
        let photo_id = crate::index_photo(conn, &dest, photos_base, &content_type)?;
        return Ok(IngestResult::Untriaged {
            photo_id,
            destination: dest,
        });
    }

    // Step 5: Compute destination
    let rel_dest = organize::compute_destination(organization_pattern, &metadata, &filename)
        .context("Failed to compute organization destination")?;

    let dest = photos_base.join(&rel_dest);

    // Ensure destination directory exists
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Step 6: Copy file (keep original in inbox so upload clients don't re-upload)
    let dest = unique_path(&dest);
    std::fs::copy(file_path, &dest)
        .context("Failed to copy file to organized destination")?;

    // Step 7: Index in database
    let photo_id = crate::index_photo(conn, &dest, photos_base, &content_type)?;

    info!(file = %filename, dest = %dest.display(), photo_id = %photo_id, "Photo organized and indexed");

    Ok(IngestResult::Indexed {
        photo_id,
        destination: dest,
    })
}

/// Process a single file from the _library-drop/ directory.
/// Preserves user's directory structure, bypasses organization.
pub fn process_library_drop_file(
    conn: &Connection,
    file_path: &Path,
    photos_base: &Path,
    library_drop_dir: &Path,
) -> Result<IngestResult> {
    let filename = file_path
        .file_name()
        .context("No filename")?
        .to_string_lossy()
        .to_string();

    info!(file = %filename, "Processing library-drop file");

    // Dedup: skip files already processed
    let sha256 = crate::compute_sha256(file_path)?;
    let already_processed: bool = conn.query_row(
        "SELECT COUNT(*) > 0 FROM photos WHERE original_sha256 = ?1",
        rusqlite::params![sha256],
        |row| row.get(0),
    )?;
    if already_processed {
        debug!(file = %filename, "Library-drop file already processed, skipping");
        return Ok(IngestResult::AlreadyProcessed);
    }

    // Validate magic bytes
    let content_type = match validate_magic_bytes(file_path) {
        Some(ct) => ct.to_string(),
        None => {
            let ext = file_path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if is_photo_ext(ext) || is_video_ext(ext) {
                format!("image/{}", ext.to_lowercase())
            } else {
                return copy_to_errors(file_path, photos_base, "Unsupported file type");
            }
        }
    };

    // Preserve directory structure relative to _library-drop/
    let rel_path = file_path
        .strip_prefix(library_drop_dir)
        .unwrap_or(Path::new(&filename));

    let dest = photos_base.join(rel_path);
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let dest = unique_path(&dest);
    std::fs::copy(file_path, &dest)
        .context("Failed to copy library-drop file")?;

    let photo_id = crate::index_photo(conn, &dest, photos_base, &content_type)?;

    info!(file = %filename, dest = %dest.display(), "Library-drop file indexed");

    Ok(IngestResult::Indexed {
        photo_id,
        destination: dest,
    })
}

/// Copy a file to the _errors/ directory with an error description sidecar
fn copy_to_errors(file_path: &Path, photos_base: &Path, error_msg: &str) -> Result<IngestResult> {
    let errors_dir = photos_base.join("_errors");
    std::fs::create_dir_all(&errors_dir)?;

    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let dest = unique_path(&errors_dir.join(&filename));
    std::fs::copy(file_path, &dest)
        .context("Failed to copy file to errors")?;

    // Write error sidecar
    let sidecar_path = dest.with_extension(format!(
        "{}.error.txt",
        dest.extension()
            .map(|e| e.to_string_lossy().to_string())
            .unwrap_or_default()
    ));
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    std::fs::write(
        &sidecar_path,
        format!(
            "Error processing file: {}\nTimestamp: {}\nOriginal path: {}\nDescription: {}\n",
            filename,
            now,
            file_path.display(),
            error_msg,
        ),
    )?;

    warn!(file = %filename, error = %error_msg, "File moved to _errors/");

    Ok(IngestResult::Error {
        destination: dest,
        error: error_msg.to_string(),
    })
}

/// Result of processing a single file
#[derive(Debug)]
pub enum IngestResult {
    Indexed {
        photo_id: String,
        destination: PathBuf,
    },
    Untriaged {
        photo_id: String,
        destination: PathBuf,
    },
    Error {
        destination: PathBuf,
        error: String,
    },
    AlreadyProcessed,
}

/// Scan and process all files in _inbox/
pub fn process_inbox(
    conn: &Connection,
    photos_base: &Path,
    organization_pattern: &str,
) -> Result<Vec<IngestResult>> {
    let inbox = photos_base.join("_inbox");
    if !inbox.exists() {
        return Ok(vec![]);
    }

    let mut results = Vec::new();
    process_dir_recursive(
        conn,
        &inbox,
        photos_base,
        organization_pattern,
        &mut results,
    )?;
    Ok(results)
}

fn process_dir_recursive(
    conn: &Connection,
    dir: &Path,
    photos_base: &Path,
    organization_pattern: &str,
    results: &mut Vec<IngestResult>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            // Skip special directories
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            process_dir_recursive(conn, &path, photos_base, organization_pattern, results)?;
            continue;
        }

        match process_inbox_file(conn, &path, photos_base, organization_pattern) {
            Ok(result) => results.push(result),
            Err(e) => {
                error!(file = %path.display(), error = %e, "Failed to process inbox file");
                if let Ok(r) = copy_to_errors(&path, photos_base, &e.to_string()) {
                    results.push(r);
                }
            }
        }
    }
    Ok(())
}

/// Scan and process all files in _library-drop/
pub fn process_library_drop(conn: &Connection, photos_base: &Path) -> Result<Vec<IngestResult>> {
    let library_drop = photos_base.join("_library-drop");
    if !library_drop.exists() {
        return Ok(vec![]);
    }

    let mut results = Vec::new();
    process_library_drop_recursive(
        conn,
        &library_drop,
        photos_base,
        &library_drop,
        &mut results,
    )?;
    Ok(results)
}

fn process_library_drop_recursive(
    conn: &Connection,
    dir: &Path,
    photos_base: &Path,
    library_drop_root: &Path,
    results: &mut Vec<IngestResult>,
) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            let name = path.file_name().unwrap().to_string_lossy();
            if name.starts_with('.') {
                continue;
            }
            process_library_drop_recursive(conn, &path, photos_base, library_drop_root, results)?;
            continue;
        }

        match process_library_drop_file(conn, &path, photos_base, library_drop_root) {
            Ok(result) => results.push(result),
            Err(e) => {
                error!(file = %path.display(), error = %e, "Failed to process library-drop file");
                if let Ok(r) = copy_to_errors(&path, photos_base, &e.to_string()) {
                    results.push(r);
                }
            }
        }
    }
    Ok(())
}

/// Re-check an untriaged file: if it now has sufficient metadata (date), organize it.
/// Returns Some(destination) if organized, None if still insufficient.
pub fn reprocess_untriaged_file(
    conn: &Connection,
    file_path: &Path,
    photos_base: &Path,
    organization_pattern: &str,
) -> Result<Option<PathBuf>> {
    let filename = file_path
        .file_name()
        .context("No filename")?
        .to_string_lossy()
        .to_string();

    // Re-read metadata from the file (it may have been edited)
    let metadata = metadata::read_metadata(file_path)?;

    if !organize::has_sufficient_metadata(&metadata) {
        return Ok(None); // Still no date
    }

    // Compute organized destination
    let rel_dest = organize::compute_destination(organization_pattern, &metadata, &filename)
        .context("Failed to compute destination")?;
    let dest = photos_base.join(&rel_dest);

    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let dest = unique_path(&dest);

    info!(file = %filename, dest = %dest.display(), "Re-organizing untriaged file");

    // Move from _untriaged to organized (not copy — we're fixing placement)
    atomic_move(file_path, &dest)?;

    // Update DB file path
    let old_rel = file_path
        .strip_prefix(photos_base)
        .map(|p| format!("photos/{}", p.to_string_lossy()))
        .unwrap_or_default();
    let new_rel = dest
        .strip_prefix(photos_base)
        .map(|p| format!("photos/{}", p.to_string_lossy()))
        .unwrap_or_default();
    let new_parent = std::path::Path::new(&new_rel)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    conn.execute(
        "UPDATE files SET path = ?1, parent_path = ?2 WHERE path = ?3",
        rusqlite::params![new_rel, new_parent, old_rel],
    )?;

    Ok(Some(dest))
}

/// Scan _untriaged/ and re-organize any files that now have sufficient metadata.
pub fn reprocess_untriaged(
    conn: &Connection,
    photos_base: &Path,
    organization_pattern: &str,
) -> Result<u32> {
    let untriaged = photos_base.join("_untriaged");
    if !untriaged.exists() {
        return Ok(0);
    }

    let mut count = 0;
    for entry in std::fs::read_dir(&untriaged)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        match reprocess_untriaged_file(conn, &path, photos_base, organization_pattern) {
            Ok(Some(dest)) => {
                info!(dest = %dest.display(), "Untriaged file organized");
                count += 1;
            }
            Ok(None) => {} // Still insufficient metadata
            Err(e) => {
                debug!(file = %path.display(), error = %e, "Failed to reprocess untriaged file");
            }
        }
    }

    Ok(count)
}

/// Atomic file move: try rename first, fall back to copy+delete for cross-filesystem moves
pub fn atomic_move(src: &Path, dst: &Path) -> Result<()> {
    debug!(src = %src.display(), dst = %dst.display(), "Moving file");

    match std::fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            // Cross-filesystem: copy then delete
            std::fs::copy(src, dst).context("Failed to copy file during cross-filesystem move")?;
            std::fs::remove_file(src)
                .context("Failed to remove source after cross-filesystem copy")?;
            Ok(())
        }
    }
}

/// Generate a unique path by appending a counter if the file already exists
fn unique_path(path: &Path) -> PathBuf {
    if !path.exists() {
        return path.to_path_buf();
    }

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new("."));

    for i in 1..1000 {
        let candidate = parent.join(format!("{}-{}{}", stem, i, ext));
        if !candidate.exists() {
            return candidate;
        }
    }

    // Fallback: use UUID
    let uuid = uuid::Uuid::new_v4();
    parent.join(format!("{}-{}{}", stem, &uuid.to_string()[..8], ext))
}

/// Check if a file's size is stable (not still being written)
pub fn is_file_stable(path: &Path, wait_secs: u64) -> bool {
    let size1 = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return false,
    };

    std::thread::sleep(std::time::Duration::from_secs(wait_secs));

    let size2 = match std::fs::metadata(path) {
        Ok(m) => m.len(),
        Err(_) => return false,
    };

    size1 == size2 && size1 > 0
}
