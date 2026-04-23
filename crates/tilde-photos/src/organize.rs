//! Photo organization pattern engine
//!
//! Computes destination paths from photo metadata using configurable patterns.

use crate::exiftool::PhotoMetadata;
use crate::ingest::atomic_move;
use anyhow::{Context, Result};
use rusqlite::Connection;
use std::path::{Path, PathBuf};
use tracing::info;

/// Compute the organized destination path for a photo based on its metadata and the pattern.
///
/// Pattern variables:
/// - `{year}` — year from DateTimeOriginal
/// - `{month:02}` — zero-padded month
/// - `{day:02}` — zero-padded day
/// - `{-trip}` — trip name from trip: tag (prefixed with hyphen), empty if none
///
/// Returns None if the metadata is insufficient (no date).
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

    // Handle {-trip} — includes leading hyphen only if trip exists
    if let Some(ref trip_name) = trip {
        result = result.replace("{-trip}", &format!("-{}", trip_name));
    } else {
        result = result.replace("{-trip}", "");
    }

    let mut path = PathBuf::from(result);
    path.push(filename);
    Some(path)
}

/// Parse year, month, day from a date string (ISO 8601 or EXIF format)
fn parse_date_components(date_str: &str) -> Option<(i32, u32, u32)> {
    let s = date_str.trim();
    if s.len() < 10 {
        return None;
    }

    // Try ISO 8601: "2025-01-15T..." or EXIF: "2025:01:15 ..."
    let parts: Vec<&str> = if s.contains('-') {
        s[..10].split('-').collect()
    } else {
        s[..10].split(':').collect()
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
    let current_within_photos = if current_rel_path.starts_with(photos_prefix) {
        &current_rel_path[photos_prefix.len()..]
    } else {
        &current_rel_path
    };

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

    #[test]
    fn test_pattern_with_day() {
        let meta = make_metadata(Some("2025-03-05T12:00:00"), vec![]);
        let dest = compute_destination("{year}/{month:02}/{day:02}", &meta, "IMG_005.jpg");
        assert_eq!(dest.unwrap(), PathBuf::from("2025/03/05/IMG_005.jpg"));
    }
}
