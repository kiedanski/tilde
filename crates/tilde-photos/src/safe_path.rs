//! Path containment helpers for untrusted path fragments.
//!
//! Photo destinations are built from data we do not control — XMP `trip:` tags
//! written by whoever produced the file, and `files.path` rows derived from
//! them — and are then handed to `create_dir_all`, `rename`, `remove_file` and
//! `symlink`. [`Path::starts_with`] cannot be used on its own to prove
//! containment because it is component-wise and never resolves `..`:
//!
//! ```text
//! Path::new("/a/b/photos").join("2026/01-../../../etc").starts_with("/a/b/photos") == true
//! ```
//!
//! The helpers here normalise first and compare afterwards.

use anyhow::{Result, bail};
use std::ffi::OsString;
use std::path::{Component, Path, PathBuf};

/// Sanitise one untrusted string so it is safe to use as a *single* path
/// component (e.g. the value of a `trip:` tag).
///
/// `{-trip}` is a supported pattern variable, so the value is kept rather than
/// dropped; only its ability to carry structure is removed. Path separators and
/// control characters become `_`. A value made of nothing but dots (`.`, `..`,
/// `...`) has no name in it and is either a no-op or a parent-directory
/// traversal, so it is rejected.
///
/// Returns `None` when nothing usable is left.
pub fn sanitize_component(raw: &str) -> Option<String> {
    let cleaned: String = raw
        .chars()
        .map(|c| {
            if c == '/' || c == '\\' || c == std::path::MAIN_SEPARATOR || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();

    let cleaned = cleaned.trim();
    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        return None;
    }
    Some(cleaned.to_string())
}

/// Resolve `.` and `..` textually, without touching the filesystem.
pub fn normalize_lexically(path: &Path) -> PathBuf {
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

/// Canonicalise as much of `path` as exists on disk, then append whatever is
/// left with `.`/`..` resolved lexically.
///
/// Unlike [`std::fs::canonicalize`] this works for destinations that have not
/// been created yet, while still resolving symlinks in the part that does
/// exist — so a symlinked intermediate directory cannot be used to slip out of
/// a root that a purely textual check would consider safe.
pub fn canonicalize_best_effort(path: &Path) -> PathBuf {
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

/// Confirm that `candidate` resolves to a location inside `root`.
pub fn ensure_within(root: &Path, candidate: &Path) -> Result<()> {
    let root_real = canonicalize_best_effort(root);
    let candidate_real = canonicalize_best_effort(candidate);

    if candidate_real.starts_with(&root_real) {
        Ok(())
    } else {
        bail!(
            "Path escapes {}: {} resolves to {}",
            root.display(),
            candidate.display(),
            candidate_real.display()
        )
    }
}

/// Boolean form of [`ensure_within`].
pub fn is_within(root: &Path, candidate: &Path) -> bool {
    ensure_within(root, candidate).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_starts_with_alone_is_not_containment() {
        // The reason this module exists: `starts_with` is component-wise.
        let root = Path::new("/a/b/photos");
        let escaped = root.join("2026/01-../../../../etc");
        assert!(escaped.starts_with(root));
        assert!(!is_within(root, &escaped));
    }

    #[test]
    fn test_sanitize_component_strips_separators() {
        assert_eq!(sanitize_component("jamaica").as_deref(), Some("jamaica"));
        assert_eq!(
            sanitize_component("italy/rome").as_deref(),
            Some("italy_rome")
        );
        assert_eq!(
            sanitize_component("/etc/cron.d").as_deref(),
            Some("_etc_cron.d")
        );
        assert_eq!(
            sanitize_component("a\\b").as_deref(),
            Some("a_b"),
            "backslashes are separators on some platforms"
        );
        assert_eq!(
            sanitize_component("../../../../etc").as_deref(),
            Some(".._.._.._.._etc")
        );
        assert_eq!(sanitize_component("nul\0byte").as_deref(), Some("nul_byte"));
        assert_eq!(sanitize_component("new\nline").as_deref(), Some("new_line"));
    }

    #[test]
    fn test_sanitize_component_rejects_unusable_values() {
        assert_eq!(sanitize_component(""), None);
        assert_eq!(sanitize_component("   "), None);
        assert_eq!(sanitize_component("."), None);
        assert_eq!(sanitize_component(".."), None);
        assert_eq!(sanitize_component("...."), None);
        // `/` collapses to `_`, but `/..` keeps a dot-only body? No — it becomes
        // `_..`, which is a perfectly ordinary (contained) directory name.
        assert_eq!(sanitize_component("/..").as_deref(), Some("_.."));
    }

    #[test]
    fn test_sanitize_component_output_is_a_single_component() {
        for raw in [
            "../../../../etc",
            "/etc/cron.d",
            "a/b/c",
            "..\\..\\windows",
            " spaced ",
        ] {
            let cleaned = sanitize_component(raw).expect("value should survive sanitising");
            let as_path = PathBuf::from(&cleaned);
            let components: Vec<_> = as_path.components().collect();
            assert_eq!(
                components.len(),
                1,
                "{:?} sanitised to {:?}, which is not one component",
                raw,
                cleaned
            );
            assert!(matches!(components[0], Component::Normal(_)));
        }
    }

    #[test]
    fn test_normalize_lexically() {
        assert_eq!(
            normalize_lexically(Path::new("/a/b/./c/../d")),
            PathBuf::from("/a/b/d")
        );
        assert_eq!(
            normalize_lexically(Path::new("a/../../b")),
            PathBuf::from("../b")
        );
    }

    #[test]
    fn test_ensure_within_real_directories() {
        let base = std::env::temp_dir().join(format!("tilde_safe_path_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let root = base.join("photos");
        let outside = base.join("outside");
        std::fs::create_dir_all(root.join("2026/01")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        assert!(is_within(&root, &root.join("2026/01/IMG.jpg")));
        assert!(is_within(&root, &root.join("does/not/exist/yet.jpg")));
        assert!(!is_within(
            &root,
            &root.join("2026/01/../../../outside/x.jpg")
        ));
        assert!(!is_within(&root, &outside.join("x.jpg")));

        // A symlinked directory inside the root must not become an exit.
        #[cfg(unix)]
        {
            let link = root.join("link");
            std::os::unix::fs::symlink(&outside, &link).unwrap();
            assert!(
                !is_within(&root, &link.join("x.jpg")),
                "symlinked directory should not pass containment"
            );
        }

        let _ = std::fs::remove_dir_all(&base);
    }
}
