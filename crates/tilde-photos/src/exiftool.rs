//! ExifTool subprocess integration for reading/writing photo metadata

use std::path::Path;
use std::process::Command;
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use tracing::debug;

/// Metadata extracted from a photo via ExifTool
#[derive(Debug, Clone, Default)]
pub struct PhotoMetadata {
    pub date_time_original: Option<String>,
    pub camera_make: Option<String>,
    pub camera_model: Option<String>,
    pub lens: Option<String>,
    pub focal_length_mm: Option<f64>,
    pub aperture: Option<f64>,
    pub iso: Option<i32>,
    pub exposure_time: Option<String>,
    pub gps_latitude: Option<f64>,
    pub gps_longitude: Option<f64>,
    pub gps_altitude: Option<f64>,
    pub orientation: Option<i32>,
    pub width: Option<i32>,
    pub height: Option<i32>,
    pub tags: Vec<String>,
}

/// Raw JSON output from ExifTool
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExifToolOutput {
    #[serde(alias = "DateTimeOriginal")]
    date_time_original: Option<String>,
    #[serde(alias = "Make")]
    make: Option<String>,
    #[serde(alias = "Model")]
    model: Option<String>,
    #[serde(alias = "LensModel", alias = "Lens")]
    lens_model: Option<String>,
    #[serde(alias = "FocalLength")]
    focal_length: Option<String>,
    #[serde(alias = "FNumber")]
    f_number: Option<f64>,
    #[serde(alias = "ISO")]
    #[serde(rename = "ISO")]
    iso: Option<serde_json::Value>,
    #[serde(alias = "ExposureTime")]
    exposure_time: Option<String>,
    #[serde(alias = "GPSLatitude")]
    #[serde(rename = "GPSLatitude")]
    gps_latitude: Option<serde_json::Value>,
    #[serde(alias = "GPSLongitude")]
    #[serde(rename = "GPSLongitude")]
    gps_longitude: Option<serde_json::Value>,
    #[serde(alias = "GPSAltitude")]
    #[serde(rename = "GPSAltitude")]
    gps_altitude: Option<serde_json::Value>,
    #[serde(alias = "Orientation")]
    orientation: Option<serde_json::Value>,
    #[serde(alias = "ImageWidth")]
    image_width: Option<i32>,
    #[serde(alias = "ImageHeight")]
    image_height: Option<i32>,
    #[serde(alias = "Subject")]
    subject: Option<serde_json::Value>,
    #[serde(alias = "Keywords")]
    keywords: Option<serde_json::Value>,
}

/// Check if exiftool is available
pub fn is_available() -> bool {
    Command::new("exiftool")
        .arg("-ver")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Read metadata from a photo file using ExifTool
pub fn read_metadata(path: &Path) -> Result<PhotoMetadata> {
    let _timeout_secs = 30;

    debug!(path = %path.display(), "Reading metadata via ExifTool");

    let output = Command::new("exiftool")
        .arg("-json")
        .arg("-n")  // numeric values (no string formatting)
        .arg("-G0") // group names
        .arg("-DateTimeOriginal")
        .arg("-Make")
        .arg("-Model")
        .arg("-LensModel")
        .arg("-FocalLength")
        .arg("-FNumber")
        .arg("-ISO")
        .arg("-ExposureTime")
        .arg("-GPSLatitude")
        .arg("-GPSLongitude")
        .arg("-GPSAltitude")
        .arg("-Orientation")
        .arg("-ImageWidth")
        .arg("-ImageHeight")
        .arg("-Subject")
        .arg("-Keywords")
        .arg(path.as_os_str())
        .output()
        .context("Failed to run exiftool")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("exiftool failed: {}", stderr);
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    // ExifTool with -G0 outputs grouped keys like "EXIF:DateTimeOriginal"
    // We need to parse the JSON and extract values regardless of group prefix
    let raw: Vec<serde_json::Value> = serde_json::from_str(&stdout)
        .context("Failed to parse exiftool JSON output")?;

    let obj = raw.first()
        .and_then(|v| v.as_object())
        .context("Empty exiftool output")?;

    let mut meta = PhotoMetadata::default();

    // Helper to find a value by suffix key (ignoring group prefix)
    let find_value = |suffix: &str| -> Option<&serde_json::Value> {
        obj.iter()
            .find(|(k, _)| k.ends_with(suffix) || k.as_str() == suffix)
            .map(|(_, v)| v)
    };

    // Date
    if let Some(v) = find_value("DateTimeOriginal") {
        if let Some(s) = v.as_str() {
            // Convert EXIF date format (2025:01:15 14:30:00) to ISO 8601
            meta.date_time_original = Some(normalize_exif_date(s));
        }
    }

    // Camera
    meta.camera_make = find_value("Make").and_then(|v| v.as_str()).map(|s| s.to_string());
    meta.camera_model = find_value("Model").and_then(|v| v.as_str()).map(|s| s.to_string());
    meta.lens = find_value("LensModel").and_then(|v| v.as_str()).map(|s| s.to_string());

    // Focal length (might be string like "50" or number)
    if let Some(v) = find_value("FocalLength") {
        meta.focal_length_mm = v.as_f64().or_else(|| {
            v.as_str().and_then(|s| s.trim_end_matches(" mm").parse().ok())
        });
    }

    meta.aperture = find_value("FNumber").and_then(|v| v.as_f64());

    // ISO can be number or string
    if let Some(v) = find_value("ISO") {
        meta.iso = v.as_i64().map(|n| n as i32)
            .or_else(|| v.as_str().and_then(|s| s.parse().ok()));
    }

    meta.exposure_time = find_value("ExposureTime").and_then(|v| {
        v.as_str().map(|s| s.to_string()).or_else(|| {
            v.as_f64().map(|f| {
                if f < 1.0 { format!("1/{}", (1.0 / f).round() as i32) }
                else { format!("{}", f) }
            })
        })
    });

    // GPS
    meta.gps_latitude = find_value("GPSLatitude").and_then(|v| v.as_f64());
    meta.gps_longitude = find_value("GPSLongitude").and_then(|v| v.as_f64());
    meta.gps_altitude = find_value("GPSAltitude").and_then(|v| v.as_f64());

    // Orientation
    if let Some(v) = find_value("Orientation") {
        meta.orientation = v.as_i64().map(|n| n as i32);
    }

    // Dimensions
    meta.width = find_value("ImageWidth").and_then(|v| v.as_i64()).map(|n| n as i32);
    meta.height = find_value("ImageHeight").and_then(|v| v.as_i64()).map(|n| n as i32);

    // Tags from XMP Subject and IPTC Keywords
    let mut tags: Vec<String> = Vec::new();
    for key in &["Subject", "Keywords"] {
        if let Some(v) = find_value(key) {
            match v {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        if let Some(s) = item.as_str() {
                            if !tags.contains(&s.to_string()) {
                                tags.push(s.to_string());
                            }
                        }
                    }
                }
                serde_json::Value::String(s) => {
                    if !tags.contains(s) {
                        tags.push(s.clone());
                    }
                }
                _ => {}
            }
        }
    }
    meta.tags = tags;

    Ok(meta)
}

/// Write tags to a photo file using ExifTool (XMP dc:Subject + IPTC Keywords)
pub fn write_tags(path: &Path, tags: &[String]) -> Result<()> {
    debug!(path = %path.display(), tags = ?tags, "Writing tags via ExifTool");

    let mut cmd = Command::new("exiftool");
    cmd.arg("-overwrite_original");

    // Clear existing tags first
    cmd.arg("-Subject=");
    cmd.arg("-Keywords=");

    // Write new tags
    for tag in tags {
        cmd.arg(format!("-Subject={}", tag));
        cmd.arg(format!("-Keywords={}", tag));
    }

    cmd.arg(path.as_os_str());

    let output = cmd.output().context("Failed to run exiftool for writing tags")?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!("exiftool write failed: {}", stderr);
    }

    Ok(())
}

/// Remove specific tags from a photo file
pub fn remove_tags(path: &Path, tags_to_remove: &[String]) -> Result<()> {
    // Read current tags, remove specified ones, write back
    let meta = read_metadata(path)?;
    let remaining: Vec<String> = meta.tags.into_iter()
        .filter(|t| !tags_to_remove.contains(t))
        .collect();
    write_tags(path, &remaining)
}

/// Classify a tag's prefix (trip:, event:, person:, favorite, or plain)
pub fn classify_tag_prefix(tag: &str) -> Option<String> {
    if tag.starts_with("trip:") {
        Some("trip".to_string())
    } else if tag.starts_with("event:") {
        Some("event".to_string())
    } else if tag.starts_with("person:") {
        Some("person".to_string())
    } else if tag == "favorite" {
        Some("favorite".to_string())
    } else {
        None
    }
}

/// Normalize EXIF date format to ISO 8601
fn normalize_exif_date(s: &str) -> String {
    // EXIF format: "2025:01:15 14:30:00" or "2025:01:15 14:30:00+03:00"
    // Target: "2025-01-15T14:30:00"
    let s = s.trim();
    if s.len() >= 19 {
        let date_part = &s[..10].replace(':', "-");
        let time_part = &s[11..];
        format!("{}T{}", date_part, time_part)
    } else {
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_exif_date() {
        assert_eq!(
            normalize_exif_date("2025:01:15 14:30:00"),
            "2025-01-15T14:30:00"
        );
        assert_eq!(
            normalize_exif_date("2025:06:20 09:15:30+03:00"),
            "2025-06-20T09:15:30+03:00"
        );
    }

    #[test]
    fn test_classify_tag_prefix() {
        assert_eq!(classify_tag_prefix("trip:jamaica"), Some("trip".to_string()));
        assert_eq!(classify_tag_prefix("event:wedding"), Some("event".to_string()));
        assert_eq!(classify_tag_prefix("person:kids"), Some("person".to_string()));
        assert_eq!(classify_tag_prefix("favorite"), Some("favorite".to_string()));
        assert_eq!(classify_tag_prefix("landscape"), None);
    }
}
