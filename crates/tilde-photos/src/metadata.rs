//! Photo/video metadata reading and XMP tag management
//!
//! Uses nom-exif (pure Rust) for EXIF and video container metadata,
//! and xmp_toolkit (Adobe C++ SDK) for XMP tag read/write.
//! Replaces the previous exiftool subprocess approach.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, warn};

/// Metadata extracted from a photo or video file
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

/// Read metadata from a photo or video file.
///
/// Uses nom-exif for EXIF fields (photos) and container metadata (videos).
/// Uses xmp_toolkit for XMP dc:subject tags.
pub fn read_metadata(path: &Path) -> Result<PhotoMetadata> {
    debug!(path = %path.display(), "Reading metadata");

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();

    let mut meta = if is_video_ext(&ext) {
        read_video_metadata(path).unwrap_or_else(|e| {
            warn!(path = %path.display(), error = %e, "Failed to read video metadata");
            PhotoMetadata::default()
        })
    } else {
        read_image_exif(path).unwrap_or_else(|e| {
            warn!(path = %path.display(), error = %e, "Failed to read image EXIF");
            PhotoMetadata::default()
        })
    };

    // Read XMP tags (works for photos; videos rarely have XMP)
    match read_xmp_tags(path) {
        Ok(tags) => meta.tags = tags,
        Err(e) => debug!(path = %path.display(), error = %e, "No XMP tags found"),
    }

    Ok(meta)
}

/// Read EXIF from image files (JPEG, HEIC, TIFF, PNG)
fn read_image_exif(path: &Path) -> Result<PhotoMetadata> {
    use nom_exif::{ExifIter, ExifTag, MediaParser, MediaSource};

    let ms = MediaSource::file_path(path).context("Failed to open file for EXIF reading")?;
    let mut parser = MediaParser::new();
    let iter: ExifIter = parser.parse(ms).context("Failed to parse EXIF data")?;

    // Parse GPS before converting to Exif (must be done on ExifIter)
    let gps = iter.parse_gps_info().ok().flatten();

    let exif: nom_exif::Exif = iter.into();
    let mut meta = PhotoMetadata::default();

    // Date — try to get as time components for clean ISO 8601 formatting
    if let Some(entry) = exif.get(ExifTag::DateTimeOriginal) {
        meta.date_time_original = Some(format_entry_as_date(entry));
    }

    // Camera info
    meta.camera_make = exif
        .get(ExifTag::Make)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());
    meta.camera_model = exif
        .get(ExifTag::Model)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());
    meta.lens = exif
        .get(ExifTag::LensModel)
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string());

    // Shooting parameters
    if let Some(entry) = exif.get(ExifTag::FocalLength) {
        meta.focal_length_mm = entry_to_f64(entry);
    }
    if let Some(entry) = exif.get(ExifTag::FNumber) {
        meta.aperture = entry_to_f64(entry);
    }
    if let Some(entry) = exif.get(ExifTag::ISOSpeedRatings) {
        meta.iso = entry
            .as_u16()
            .map(|n| n as i32)
            .or_else(|| entry.as_u32().map(|n| n as i32));
    }
    if let Some(entry) = exif.get(ExifTag::ExposureTime) {
        if let Some(r) = entry.as_urational() {
            let f = r.as_float();
            meta.exposure_time = Some(if f < 1.0 && f > 0.0 {
                format!("1/{}", (1.0 / f).round() as i32)
            } else {
                format!("{}", f)
            });
        } else {
            meta.exposure_time = Some(entry.to_string());
        }
    }

    // GPS
    if let Some(ref gps_info) = gps {
        meta.gps_latitude = Some(gps_to_decimal_lat(gps_info));
        meta.gps_longitude = Some(gps_to_decimal_lon(gps_info));
        meta.gps_altitude = Some(gps_info.altitude.as_float());
    }

    // Orientation
    if let Some(entry) = exif.get(ExifTag::Orientation) {
        meta.orientation = entry.as_u16().map(|n| n as i32);
    }

    // Dimensions — try ExifImageWidth first (actual pixel dimensions), fall back to ImageWidth
    meta.width = exif
        .get(ExifTag::ExifImageWidth)
        .or_else(|| exif.get(ExifTag::ImageWidth))
        .and_then(|v| v.as_u32().or_else(|| v.as_u16().map(|n| n as u32)))
        .map(|n| n as i32);
    meta.height = exif
        .get(ExifTag::ExifImageHeight)
        .or_else(|| exif.get(ExifTag::ImageHeight))
        .and_then(|v| v.as_u32().or_else(|| v.as_u16().map(|n| n as u32)))
        .map(|n| n as i32);

    Ok(meta)
}

/// Read metadata from video containers (MP4, MOV, MKV, WebM)
fn read_video_metadata(path: &Path) -> Result<PhotoMetadata> {
    use nom_exif::{MediaParser, MediaSource, TrackInfo, TrackInfoTag};

    let ms = MediaSource::file_path(path).context("Failed to open video file")?;
    let mut parser = MediaParser::new();
    let info: TrackInfo = parser.parse(ms).context("Failed to parse video metadata")?;

    let mut meta = PhotoMetadata::default();

    // Creation date from container metadata
    if let Some(dt) = info.get(TrackInfoTag::CreateDate) {
        meta.date_time_original = Some(format_entry_as_date(dt));
    }

    // Dimensions
    if let Some(v) = info.get(TrackInfoTag::ImageWidth) {
        meta.width = v.as_u32().map(|n| n as i32);
    }
    if let Some(v) = info.get(TrackInfoTag::ImageHeight) {
        meta.height = v.as_u32().map(|n| n as i32);
    }

    // GPS (some phone videos embed GPS in container)
    if let Some(gps_info) = info.get_gps_info() {
        meta.gps_latitude = Some(gps_to_decimal_lat(gps_info));
        meta.gps_longitude = Some(gps_to_decimal_lon(gps_info));
        meta.gps_altitude = Some(gps_info.altitude.as_float());
    }

    // Make/Model (some phones embed this)
    if let Some(v) = info.get(TrackInfoTag::Make) {
        meta.camera_make = v.as_str().map(|s| s.trim().to_string());
    }
    if let Some(v) = info.get(TrackInfoTag::Model) {
        meta.camera_model = v.as_str().map(|s| s.trim().to_string());
    }

    Ok(meta)
}

/// Read XMP dc:subject tags from a file
fn read_xmp_tags(path: &Path) -> Result<Vec<String>> {
    use xmp_toolkit::{OpenFileOptions, XmpFile};

    let mut xmp_file = XmpFile::new().context("Failed to create XmpFile")?;

    // Open for reading only; try smart handler first, fall back to packet scanning
    xmp_file
        .open_file(
            path,
            OpenFileOptions::default()
                .only_xmp()
                .use_smart_handler(),
        )
        .or_else(|_| {
            xmp_file.open_file(path, OpenFileOptions::default().use_packet_scanning())
        })
        .context("Failed to open file for XMP reading")?;

    let xmp = match xmp_file.xmp() {
        Some(x) => x,
        None => return Ok(vec![]),
    };

    let mut tags: Vec<String> = xmp
        .property_array(xmp_toolkit::xmp_ns::DC, "subject")
        .map(|v| v.value)
        .filter(|s| !s.is_empty())
        .collect();
    tags.dedup();

    Ok(tags)
}

/// Write tags to a photo file as XMP dc:subject
pub fn write_tags(path: &Path, tags: &[String]) -> Result<()> {
    use xmp_toolkit::{OpenFileOptions, XmpFile, XmpMeta, XmpValue};

    debug!(path = %path.display(), tags = ?tags, "Writing XMP tags");

    let mut xmp_file = XmpFile::new().context("Failed to create XmpFile")?;
    xmp_file
        .open_file(
            path,
            OpenFileOptions::default()
                .for_update()
                .use_smart_handler(),
        )
        .context("Failed to open file for XMP writing")?;

    let mut xmp = xmp_file
        .xmp()
        .unwrap_or_else(|| XmpMeta::new().unwrap());

    let dc_ns = xmp_toolkit::xmp_ns::DC;

    // Clear existing dc:subject
    let _ = xmp.delete_property(dc_ns, "subject");

    // Write new tags as dc:subject bag
    for tag in tags {
        xmp.append_array_item(
            dc_ns,
            &XmpValue::from("subject").set_is_array(true),
            &XmpValue::from(tag.as_str()),
        )
        .context("Failed to append XMP array item")?;
    }

    xmp_file
        .put_xmp(&xmp)
        .context("Failed to write XMP to file")?;
    xmp_file.close();

    Ok(())
}

/// Remove specific tags from a photo file
pub fn remove_tags(path: &Path, tags_to_remove: &[String]) -> Result<()> {
    let meta = read_metadata(path)?;
    let remaining: Vec<String> = meta
        .tags
        .into_iter()
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

// --- Helpers ---

fn is_video_ext(ext: &str) -> bool {
    matches!(ext, "mp4" | "mov" | "avi" | "mkv" | "webm" | "3gp")
}

/// Convert an EntryValue to f64 (handles URational, IRational, and numeric types)
fn entry_to_f64(entry: &nom_exif::EntryValue) -> Option<f64> {
    entry
        .as_urational()
        .map(|r| r.as_float())
        .or_else(|| entry.as_irational().map(|r| r.as_float()))
        .or_else(|| entry.as_u32().map(|n| n as f64))
        .or_else(|| entry.as_u16().map(|n| n as f64))
}

/// Format an EntryValue as an ISO 8601 date string
fn format_entry_as_date(entry: &nom_exif::EntryValue) -> String {
    // Try time components first for clean formatting
    if let Some((naive_dt, offset)) = entry.as_time_components() {
        return if let Some(ofs) = offset {
            format!("{}{}", naive_dt.format("%Y-%m-%dT%H:%M:%S"), ofs)
        } else {
            naive_dt.format("%Y-%m-%dT%H:%M:%S").to_string()
        };
    }
    // Fall back to string representation
    let s = entry.to_string();
    normalize_exif_date(&s)
}

/// Normalize EXIF date format to ISO 8601
fn normalize_exif_date(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 19 {
        let date_part = &s[..10].replace(':', "-");
        let time_part = &s[11..];
        format!("{}T{}", date_part, time_part)
    } else {
        s.to_string()
    }
}

/// Convert GPSInfo latitude to decimal degrees
fn gps_to_decimal_lat(gps: &nom_exif::GPSInfo) -> f64 {
    let lat = &gps.latitude;
    // LatLng is a tuple struct: LatLng(degrees, minutes, seconds)
    let degrees = lat.0.as_float();
    let minutes = lat.1.as_float();
    let seconds = lat.2.as_float();
    let decimal = degrees + minutes / 60.0 + seconds / 3600.0;
    if gps.latitude_ref == 'S' {
        -decimal
    } else {
        decimal
    }
}

/// Convert GPSInfo longitude to decimal degrees
fn gps_to_decimal_lon(gps: &nom_exif::GPSInfo) -> f64 {
    let lon = &gps.longitude;
    let degrees = lon.0.as_float();
    let minutes = lon.1.as_float();
    let seconds = lon.2.as_float();
    let decimal = degrees + minutes / 60.0 + seconds / 3600.0;
    if gps.longitude_ref == 'W' {
        -decimal
    } else {
        decimal
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
        assert_eq!(
            classify_tag_prefix("trip:jamaica"),
            Some("trip".to_string())
        );
        assert_eq!(
            classify_tag_prefix("event:wedding"),
            Some("event".to_string())
        );
        assert_eq!(
            classify_tag_prefix("person:kids"),
            Some("person".to_string())
        );
        assert_eq!(
            classify_tag_prefix("favorite"),
            Some("favorite".to_string())
        );
        assert_eq!(classify_tag_prefix("landscape"), None);
    }
}
