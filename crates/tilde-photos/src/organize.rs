//! Photo organization pattern engine
//!
//! Computes destination paths from photo metadata using configurable patterns.

use crate::exiftool::PhotoMetadata;
use std::path::PathBuf;

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
