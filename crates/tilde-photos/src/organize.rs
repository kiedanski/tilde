//! Photo organization pattern engine
//!
//! Computes destination paths from photo metadata using configurable patterns.

use crate::ingest::atomic_move;
use crate::metadata::PhotoMetadata;
use crate::safe_path;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::{Component, Path, PathBuf};
use tracing::{info, warn};

/// Compute the organized destination path for a photo based on its metadata and the pattern.
///
/// Pattern variables:
/// - `{year}` — year from DateTimeOriginal
/// - `{month:02}` — zero-padded month
/// - `{day:02}` — zero-padded day
/// - `{-trip}` — trip name from trip: tag (prefixed with hyphen), empty if none
///
/// The `trip:` value is untrusted (it comes from the file's own XMP tags), so
/// it is sanitized into a single path component before substitution; see
/// [`crate::safe_path::sanitize_component`].
///
/// Returns None if the metadata is insufficient (no date) or if the rendered
/// path would not be a plain relative path.
pub fn compute_destination(
    pattern: &str,
    metadata: &PhotoMetadata,
    filename: &str,
) -> Option<PathBuf> {
    let date_str = metadata.date_time_original.as_ref()?;

    // Parse year/month/day from ISO 8601 date
    let (year, month, day) = parse_date_components(date_str)?;

    // Find trip tag
    let trip = metadata
        .tags
        .iter()
        .find(|t| t.starts_with("trip:"))
        .map(|t| t[5..].to_string());

    let mut result = pattern.to_string();
    result = result.replace("{year}", &year.to_string());
    result = result.replace("{month:02}", &format!("{:02}", month));
    result = result.replace("{day:02}", &format!("{:02}", day));

    // Handle {-trip} — includes leading hyphen only if trip exists.
    //
    // The trip value comes from the file's XMP dc:subject tags, i.e. from
    // whoever produced the photo, so it is untrusted input that is about to
    // become a path component (`{month:02}{-trip}` renders as `01-<trip>`).
    // `{-trip}` stays a supported variable — only the value is made safe.
    let trip_component = trip.as_deref().and_then(safe_path::sanitize_component);
    if let Some(ref name) = trip_component {
        if trip.as_deref() != Some(name.as_str()) {
            warn!(
                raw = ?trip,
                sanitized = %name,
                "Sanitized unsafe trip: tag before using it as a path component"
            );
        }
        result = result.replace("{-trip}", &format!("-{}", name));
    } else {
        if trip.is_some() {
            warn!(raw = ?trip, "Dropped unusable trip: tag from organization path");
        }
        result = result.replace("{-trip}", "");
    }

    let mut path = PathBuf::from(result);
    path.push(filename);

    // Belt and braces: whatever the pattern and filename contained, the result
    // must be a plain relative path. Anything else (a root, a `..`) would let
    // `photos_base.join(dest)` land outside the photos tree.
    if path
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        warn!(dest = %path.display(), "Refusing organization destination that is not a plain relative path");
        return None;
    }

    Some(path)
}

/// Parse year, month, day from a date string (ISO 8601 or EXIF format)
fn parse_date_components(date_str: &str) -> Option<(i32, u32, u32)> {
    let s = date_str.trim();
    // EXIF/XMP date strings come from untrusted files and are not guaranteed to
    // be ASCII. `&s[..10]` panics when byte 10 is not a character boundary, so
    // take the checked slice instead (which also subsumes the length check).
    let head = s.get(..10)?;

    // Try ISO 8601: "2025-01-15T..." or EXIF: "2025:01:15 ..."
    // Decide on the date part only: an EXIF date with a negative UTC offset
    // ("2025:01:15 09:15:30-03:00") contains a '-' outside the first 10 bytes.
    let parts: Vec<&str> = if head.contains('-') {
        head.split('-').collect()
    } else {
        head.split(':').collect()
    };

    if parts.len() >= 3 {
        let year: i32 = parts[0].parse().ok()?;
        let month: u32 = parts[1].parse().ok()?;
        let day: u32 = parts[2].parse().ok()?;
        if (1..=12).contains(&month) && (1..=31).contains(&day) {
            return Some((year, month, day));
        }
    }

    None
}

/// Determine if a photo has sufficient metadata for organization
pub fn has_sufficient_metadata(metadata: &PhotoMetadata) -> bool {
    metadata.date_time_original.is_some()
}

/// Re-organize a photo after a tag change, moving it to the new destination
/// if the organization pattern produces a different path.
///
/// Returns Some(new_rel_path) if the file was moved, None if no move was needed.
/// Skips re-organization if the photo has manually_placed=1.
pub fn reorganize_after_tag_change(
    conn: &Connection,
    photo_uuid: &str,
    photos_base: &Path,
    organization_pattern: &str,
    metadata: &PhotoMetadata,
) -> Result<Option<String>> {
    // Check manually_placed flag
    let manually_placed: bool = conn
        .query_row(
            "SELECT manually_placed FROM photos WHERE id = ?1",
            [photo_uuid],
            |row| row.get::<_, i32>(0).map(|v| v != 0),
        )
        .context("Failed to query manually_placed flag")?;

    if manually_placed {
        return Ok(None);
    }

    // Get current file path
    let current_rel_path: String = conn
        .query_row(
            "SELECT f.path FROM photos p JOIN files f ON p.file_id = f.id WHERE p.id = ?1",
            [photo_uuid],
            |row| row.get(0),
        )
        .context("Failed to query current photo path")?;

    // The current_rel_path is relative to data_dir (e.g., "photos/2025/01/IMG.jpg")
    // photos_base is the photos/ directory itself
    // Strip the "photos/" prefix to get the path within photos_base
    let photos_prefix = "photos/";
    let current_within_photos = current_rel_path
        .strip_prefix(photos_prefix)
        .unwrap_or(&current_rel_path);

    let current_full = photos_base.join(current_within_photos);
    let filename = current_full
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    // Compute new destination based on updated metadata
    let new_rel = match compute_destination(organization_pattern, metadata, &filename) {
        Some(p) => p,
        None => return Ok(None), // Can't compute destination (no date), skip
    };

    let new_rel_str = new_rel.to_string_lossy().to_string();

    // No change needed
    if current_within_photos == new_rel_str {
        return Ok(None);
    }

    // Perform the move
    let new_full = photos_base.join(&new_rel);

    // This sink renames over whatever is already at the destination, so prove
    // both ends stay inside the photos root before creating anything.
    safe_path::ensure_within(photos_base, &current_full)
        .context("Refusing to move a photo from outside the photos directory")?;
    safe_path::ensure_within(photos_base, &new_full)
        .context("Refusing to re-organize a photo outside the photos directory")?;

    // Create parent directory
    if let Some(parent) = new_full.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create destination directory for photo reorganization")?;
    }

    info!(
        photo = photo_uuid,
        from = current_within_photos,
        to = %new_rel_str,
        "Re-organizing photo after tag change"
    );

    atomic_move(&current_full, &new_full)?;

    // Update the file path in the database
    let new_db_path = format!("photos/{}", new_rel_str);
    let new_parent = Path::new(&new_db_path)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    conn.execute(
        "UPDATE files SET path = ?1, parent_path = ?2 WHERE id = (SELECT file_id FROM photos WHERE id = ?3)",
        rusqlite::params![new_db_path, new_parent, photo_uuid],
    )?;

    Ok(Some(new_db_path))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metadata(date: Option<&str>, tags: Vec<&str>) -> PhotoMetadata {
        PhotoMetadata {
            date_time_original: date.map(|s| s.to_string()),
            tags: tags.into_iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }
    }

    #[test]
    fn test_basic_pattern() {
        let meta = make_metadata(Some("2025-01-15T14:30:00"), vec![]);
        let dest = compute_destination("{year}/{month:02}", &meta, "IMG_001.jpg");
        assert_eq!(dest.unwrap(), PathBuf::from("2025/01/IMG_001.jpg"));
    }

    #[test]
    fn test_pattern_with_trip() {
        let meta = make_metadata(Some("2025-06-20T09:00:00"), vec!["trip:jamaica"]);
        let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG_002.jpg");
        assert_eq!(dest.unwrap(), PathBuf::from("2025/06-jamaica/IMG_002.jpg"));
    }

    #[test]
    fn test_pattern_without_trip() {
        let meta = make_metadata(Some("2025-06-20T09:00:00"), vec!["landscape"]);
        let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG_003.jpg");
        assert_eq!(dest.unwrap(), PathBuf::from("2025/06/IMG_003.jpg"));
    }

    #[test]
    fn test_no_date_returns_none() {
        let meta = make_metadata(None, vec![]);
        let dest = compute_destination("{year}/{month:02}", &meta, "IMG_004.jpg");
        assert!(dest.is_none());
    }

    /// Reproduces the *unfixed* substitution: the raw `trip:` value dropped
    /// straight into the `{month:02}{-trip}` component. Used to prove the
    /// escape tests are asserting something real.
    fn raw_render(trip: &str) -> PathBuf {
        PathBuf::from(format!("2025/01-{}", trip)).join("IMG.jpg")
    }

    fn escapes(root: &Path, rel: &Path) -> bool {
        !safe_path::is_within(root, &root.join(rel))
    }

    #[test]
    fn test_escape_arithmetic_needs_four_dotdot_segments() {
        let root = Path::new("/a/b/photos");

        // The `01-` prefix swallows the first `..`, so three `..` segments
        // still land inside the photos root — a three-dotdot test case would
        // be a false negative.
        assert!(
            !escapes(root, &raw_render("../../..")),
            "three `..` segments should NOT escape; the test must use four"
        );

        // Four do escape, all the way out to /a/b.
        assert!(escapes(root, &raw_render("../../../..")));

        // And component-wise `starts_with` is blind to it, which is exactly
        // why the old code looked safe.
        assert!(root.join(raw_render("../../../..")).starts_with(root));
    }

    #[test]
    fn test_trip_tag_with_traversal_cannot_escape() {
        let root = Path::new("/a/b/photos");
        let meta = make_metadata(
            Some("2025-01-15T10:00:00"),
            vec!["trip:../../../../etc/cron.d"],
        );

        let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG.jpg")
            .expect("{-trip} must keep working for hostile values, just safely");

        assert!(
            dest.components().all(|c| matches!(c, Component::Normal(_))),
            "destination must be a plain relative path, got {:?}",
            dest
        );
        assert!(
            !escapes(root, &dest),
            "sanitized destination still escaped the photos root: {:?}",
            dest
        );

        // Non-vacuity: the identical value escapes without the sanitizer.
        assert!(
            escapes(root, &raw_render("../../../../etc/cron.d")),
            "the unsanitized form must escape, otherwise this test proves nothing"
        );
    }

    #[test]
    fn test_trip_tag_path_separators_are_flattened() {
        let meta = make_metadata(Some("2025-06-20T09:00:00"), vec!["trip:italy/rome"]);
        let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG.jpg").unwrap();
        assert_eq!(dest, PathBuf::from("2025/06-italy_rome/IMG.jpg"));
    }

    #[test]
    fn test_trip_tag_absolute_value_stays_relative() {
        let meta = make_metadata(Some("2025-06-20T09:00:00"), vec!["trip:/etc/cron.d"]);
        let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG.jpg").unwrap();
        assert_eq!(dest, PathBuf::from("2025/06-_etc_cron.d/IMG.jpg"));
        assert!(dest.is_relative());
    }

    #[test]
    fn test_trip_tag_dot_only_value_is_dropped() {
        for value in ["trip:..", "trip:.", "trip:   "] {
            let meta = make_metadata(Some("2025-06-20T09:00:00"), vec![value]);
            let dest = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG.jpg").unwrap();
            assert_eq!(
                dest,
                PathBuf::from("2025/06/IMG.jpg"),
                "{:?} should render as if there were no trip tag",
                value
            );
        }
    }

    #[test]
    fn test_non_ascii_date_does_not_panic() {
        // Each of these is >= 10 bytes but has a multi-byte character
        // straddling byte 10, which made `&s[..10]` panic.
        for date in [
            "2025-01-1\u{e9}",
            "2025-01-1\u{e9}T14:30:00",
            "20\u{e9}5:01:15 10:00:00",
            "\u{65e5}\u{672c}\u{8a9e}\u{3067}\u{3059}",
        ] {
            let meta = make_metadata(Some(date), vec![]);
            // Must not panic; the result may legitimately be None.
            let _ = compute_destination("{year}/{month:02}{-trip}", &meta, "IMG.jpg");
            let _ = parse_date_components(date);
        }
    }

    #[test]
    fn test_exif_date_with_negative_utc_offset() {
        // "2025:01:15 09:15:30-03:00" has a '-' after the date part; deciding
        // the separator from the whole string picked the wrong one.
        assert_eq!(
            parse_date_components("2025:01:15 09:15:30-03:00"),
            Some((2025, 1, 15))
        );
    }

    #[test]
    fn test_pattern_with_day() {
        let meta = make_metadata(Some("2025-03-05T12:00:00"), vec![]);
        let dest = compute_destination("{year}/{month:02}/{day:02}", &meta, "IMG_005.jpg");
        assert_eq!(dest.unwrap(), PathBuf::from("2025/03/05/IMG_005.jpg"));
    }
}
