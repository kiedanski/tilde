//! Content-addressed store for previous file versions.
//!
//! Three-way merge needs the *base* version a writing client was working from
//! (plan.md §5). Rather than keeping full history, versions are archived
//! **on overwrite**: just before a PUT replaces a file, the outgoing bytes are
//! copied here. That captures exactly the versions a merge could need, and costs
//! nothing on reads.
//!
//! Blobs are keyed by the full sha256 of their content and sharded by the first
//! two hex characters so no single directory grows without bound.

use std::path::{Path, PathBuf};

/// Path a blob with this digest lives at.
pub fn blob_path(blobs_root: &Path, sha256: &str) -> PathBuf {
    blobs_root.join(&sha256[..2]).join(sha256)
}

/// Copy a file's current contents into the store, returning its sha256.
///
/// Idempotent: content already present is left alone, so re-archiving an
/// unchanged file costs one `stat`.
pub fn archive_version(blobs_root: &Path, src: &Path) -> std::io::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let mut file = std::fs::File::open(src)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 65536];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let sha256 = format!("{:x}", hasher.finalize());

    let dest = blob_path(blobs_root, &sha256);
    if dest.exists() {
        return Ok(sha256);
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // Write via a temp file in the same directory, then rename, so a crash
    // never leaves a blob whose contents do not match its name.
    let tmp = dest.with_extension("tmp");
    std::fs::copy(src, &tmp)?;
    std::fs::rename(&tmp, &dest)?;

    Ok(sha256)
}

/// Archive a file whose digest the caller already knows.
///
/// [`archive_version`] hashes the whole file *before* its "already present"
/// short-circuit, so callers that hold the digest — the stat cache has it — paid
/// a full sequential read on every call. On the GET path that meant re-reading
/// the entire file to serve a 2-byte range request.
pub fn archive_version_known_sha(
    blobs_root: &Path,
    src: &Path,
    sha256: &str,
) -> std::io::Result<()> {
    if sha256.len() < 2 {
        return Ok(()); // not a usable digest; nothing to key a blob on
    }
    let dest = blob_path(blobs_root, sha256);
    if dest.exists() {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = dest.with_extension(format!("tmp{}", std::process::id()));
    std::fs::copy(src, &tmp)?;
    std::fs::rename(&tmp, &dest)?;
    Ok(())
}

/// Read an archived version back, or `None` if it is not in the store.
pub fn read_version(blobs_root: &Path, sha256: &str) -> Option<Vec<u8>> {
    std::fs::read(blob_path(blobs_root, sha256)).ok()
}

/// Delete blobs not present in `referenced`, returning how many were removed.
///
/// Callers pass every digest still reachable: the current version of each file
/// plus every version recorded in `client_base_versions`.
pub fn gc_versions(blobs_root: &Path, referenced: &[String]) -> std::io::Result<usize> {
    if !blobs_root.exists() {
        return Ok(0);
    }
    let keep: std::collections::HashSet<&str> = referenced.iter().map(|s| s.as_str()).collect();
    let mut removed = 0;

    for shard in std::fs::read_dir(blobs_root)?.flatten() {
        if !shard.path().is_dir() {
            continue;
        }
        for blob in std::fs::read_dir(shard.path())?.flatten() {
            let name = blob.file_name().to_string_lossy().to_string();
            if keep.contains(name.as_str()) {
                continue;
            }
            if std::fs::remove_file(blob.path()).is_ok() {
                removed += 1;
            }
        }
        // Drop the shard directory if it is now empty.
        let _ = std::fs::remove_dir(shard.path());
    }

    Ok(removed)
}

/// Largest file we will attempt to merge. Beyond this a stale write falls back
/// to overwrite-and-archive: the displaced version is still recoverable from the
/// blob store, but we do not hold three copies of a huge file in memory.
pub const MERGE_MAX_BYTES: usize = 1024 * 1024;

/// What a three-way merge produced.
#[derive(Debug, PartialEq, Eq)]
pub enum MergeOutcome {
    /// Both sides applied cleanly.
    Clean(String),
    /// Overlapping edits; the text carries `<<<<<<<`/`=======`/`>>>>>>>` markers
    /// for the user to resolve in their editor.
    Conflicted(String),
}

/// Three-way merge of `ours` (what is on disk now) and `theirs` (the incoming
/// write) against their common `base`.
///
/// Returns `None` when a merge should not be attempted at all: non-UTF-8 content
/// on any side, or anything over [`MERGE_MAX_BYTES`].
pub fn merge_three_way(base: &[u8], ours: &[u8], theirs: &[u8]) -> Option<MergeOutcome> {
    if base.len() > MERGE_MAX_BYTES
        || ours.len() > MERGE_MAX_BYTES
        || theirs.len() > MERGE_MAX_BYTES
    {
        return None;
    }
    let base = std::str::from_utf8(base).ok()?;
    let ours = std::str::from_utf8(ours).ok()?;
    let theirs = std::str::from_utf8(theirs).ok()?;

    match diffy::merge(base, ours, theirs) {
        Ok(merged) => Some(MergeOutcome::Clean(merged)),
        Err(conflicted) => Some(MergeOutcome::Conflicted(conflicted)),
    }
}

#[cfg(test)]
mod merge_tests {
    use super::*;

    const BASE: &str = "line A\nline B\nline C\n";

    #[test]
    fn non_overlapping_edits_merge_cleanly() {
        let ours = "line A\nline B\nline C\nappended by laptop\n";
        let theirs = "prepended by phone\nline A\nline B\nline C\n";

        let out = merge_three_way(BASE.as_bytes(), ours.as_bytes(), theirs.as_bytes()).unwrap();

        match out {
            MergeOutcome::Clean(text) => {
                assert!(text.contains("appended by laptop"), "lost ours:\n{}", text);
                assert!(
                    text.contains("prepended by phone"),
                    "lost theirs:\n{}",
                    text
                );
            }
            MergeOutcome::Conflicted(text) => {
                panic!("edits do not overlap and should merge cleanly:\n{}", text)
            }
        }
    }

    #[test]
    fn overlapping_edits_produce_conflict_markers() {
        let ours = "line A\nlaptop rewrote B\nline C\n";
        let theirs = "line A\nphone rewrote B\nline C\n";

        let out = merge_three_way(BASE.as_bytes(), ours.as_bytes(), theirs.as_bytes()).unwrap();

        match out {
            MergeOutcome::Conflicted(text) => {
                assert!(text.contains("<<<<<<<"), "missing markers:\n{}", text);
                assert!(text.contains(">>>>>>>"), "missing markers:\n{}", text);
                // Neither side may be silently dropped.
                assert!(text.contains("laptop rewrote B"));
                assert!(text.contains("phone rewrote B"));
            }
            MergeOutcome::Clean(text) => {
                panic!("both sides changed the same line:\n{}", text)
            }
        }
    }

    #[test]
    fn an_untouched_side_is_a_fast_forward() {
        let theirs = "line A\nline B\nline C\nonly theirs changed\n";

        let out = merge_three_way(BASE.as_bytes(), BASE.as_bytes(), theirs.as_bytes()).unwrap();

        assert_eq!(out, MergeOutcome::Clean(theirs.to_string()));
    }

    #[test]
    fn binary_content_is_not_merged() {
        let bin = &[0xff, 0xfe, 0x00, 0x01][..];
        assert!(merge_three_way(bin, bin, bin).is_none());
    }

    #[test]
    fn oversized_content_is_not_merged() {
        let big = vec![b'a'; MERGE_MAX_BYTES + 1];
        assert!(merge_three_way(b"x", b"y", &big).is_none());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sha_of(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        format!("{:x}", h.finalize())
    }

    #[test]
    fn archive_stores_content_by_digest() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        let src = dir.path().join("a.txt");
        std::fs::write(&src, "version 1").unwrap();

        let sha = archive_version(&blobs, &src).unwrap();

        assert_eq!(sha, sha_of(b"version 1"));
        assert_eq!(read_version(&blobs, &sha).unwrap(), b"version 1");
    }

    #[test]
    fn archive_is_idempotent() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        let src = dir.path().join("a.txt");
        std::fs::write(&src, "same").unwrap();

        let a = archive_version(&blobs, &src).unwrap();
        let b = archive_version(&blobs, &src).unwrap();

        assert_eq!(a, b);
        assert!(blob_path(&blobs, &a).exists());
    }

    #[test]
    fn read_version_returns_none_for_unknown_digest() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        assert!(read_version(&blobs, &sha_of(b"never archived")).is_none());
    }

    #[test]
    fn archive_shards_by_digest_prefix() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        let src = dir.path().join("a.txt");
        std::fs::write(&src, "shard me").unwrap();

        let sha = archive_version(&blobs, &src).unwrap();

        assert!(
            blobs.join(&sha[..2]).is_dir(),
            "blobs must shard so one directory does not grow without bound"
        );
    }

    #[test]
    fn gc_removes_unreferenced_blobs() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        let src = dir.path().join("a.txt");

        std::fs::write(&src, "referenced").unwrap();
        let keep = archive_version(&blobs, &src).unwrap();
        std::fs::write(&src, "orphaned").unwrap();
        let drop = archive_version(&blobs, &src).unwrap();

        let removed = gc_versions(&blobs, &[keep.clone()]).unwrap();

        assert_eq!(removed, 1);
        assert!(
            read_version(&blobs, &keep).is_some(),
            "referenced blob kept"
        );
        assert!(read_version(&blobs, &drop).is_none(), "orphan removed");
    }

    #[test]
    fn gc_on_empty_store_is_a_noop() {
        let dir = TempDir::new().unwrap();
        let blobs = dir.path().join("blobs");
        assert_eq!(gc_versions(&blobs, &[]).unwrap(), 0);
    }
}
