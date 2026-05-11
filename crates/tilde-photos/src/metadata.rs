//! Photo/video metadata reading and XMP tag management
//!
//! Uses nom-exif (pure Rust) for EXIF and video container metadata,
//! and xmp_toolkit (Adobe C++ SDK) for XMP tag read/write.
//! Replaces the previous exiftool subprocess approach.

use anyhow::{Context, Result};
use std::path::Path;
use tracing::{debug, info, warn};

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

    // Fallback: if no date from EXIF/container, try to parse from filename.
    // Covers WhatsApp (IMG-20260509-WA0013.jpg), screenshots (Screenshot_20260101-123456.png),
    // and other apps that embed dates in filenames but strip EXIF.
    if meta.date_time_original.is_none()
        && let Some(date) = parse_date_from_filename(path)
    {
        debug!(path = %path.display(), date = %date, "Date extracted from filename");
        // Write the date into the file's EXIF so other apps can read it
        // and re-ingestion doesn't lose the date.
        if let Err(e) = write_exif_date(path, &date) {
            debug!(path = %path.display(), error = %e, "Could not write EXIF date (non-fatal)");
        }
        meta.date_time_original = Some(date);
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
            OpenFileOptions::default().only_xmp().use_smart_handler(),
        )
        .or_else(|_| xmp_file.open_file(path, OpenFileOptions::default().use_packet_scanning()))
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
            OpenFileOptions::default().for_update().use_smart_handler(),
        )
        .context("Failed to open file for XMP writing")?;

    let mut xmp = xmp_file.xmp().unwrap_or_else(|| XmpMeta::new().unwrap());

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

/// Write DateTimeOriginal (and CreateDate) into a JPEG file's EXIF data.
/// The date string should be ISO 8601 format (e.g. "2026-05-09T00:00:00").
/// Converts to EXIF format "YYYY:MM:DD HH:MM:SS" before writing.
/// Non-JPEG files are silently skipped (EXIF writing only supports JPEG).
fn write_exif_date(path: &Path, iso_date: &str) -> Result<()> {
    use little_exif::exif_tag::ExifTag;
    use little_exif::metadata::Metadata;

    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("")
        .to_lowercase();
    if ext != "jpg" && ext != "jpeg" {
        return Ok(()); // Only JPEG supported for EXIF writing
    }

    // Convert "2026-05-09T14:30:00" → "2026:05:09 14:30:00"
    let exif_date = if iso_date.len() >= 19 {
        format!(
            "{}:{}:{} {}",
            &iso_date[0..4],
            &iso_date[5..7],
            &iso_date[8..10],
            &iso_date[11..19]
        )
    } else if iso_date.len() >= 10 {
        format!(
            "{}:{}:{} 00:00:00",
            &iso_date[0..4],
            &iso_date[5..7],
            &iso_date[8..10]
        )
    } else {
        return Ok(());
    };

    let mut metadata = Metadata::new();
    metadata.set_tag(ExifTag::DateTimeOriginal(exif_date.clone()));
    metadata.set_tag(ExifTag::CreateDate(exif_date));

    metadata
        .write_to_file(path)
        .map_err(|e| anyhow::anyhow!("Failed to write EXIF: {:?}", e))?;

    info!(path = %path.display(), "Wrote EXIF DateTimeOriginal from filename");
    Ok(())
}

/// Try to extract a date from common filename patterns when EXIF is missing.
///
/// Supported patterns:
/// - `IMG-20260509-WA0013.jpg`  (WhatsApp)
/// - `VID-20260509-WA0001.mp4`  (WhatsApp video)
/// - `IMG_20260509_143456.jpg`  (Android camera)
/// - `Screenshot_20260509-143456.png` (Android screenshot)
/// - `PXL_20260509_143456789.jpg` (Pixel camera)
/// - `20260509_143456.jpg` (bare timestamp)
fn parse_date_from_filename(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;

    // Skip dotfiles (e.g. .nfs.20051026.3f4c) — not real photos
    if stem.starts_with('.') {
        return None;
    }

    // Look for an 8-digit date (YYYYMMDD) anywhere in the filename
    let digits: Vec<(usize, &str)> = stem.match_indices(|c: char| c.is_ascii_digit()).collect();

    // Find runs of 8+ consecutive digits
    let mut i = 0;
    while i < digits.len() {
        // Find the start of a digit run
        let run_start = digits[i].0;
        let mut run_end = run_start + 1;
        let mut j = i + 1;
        while j < digits.len() && digits[j].0 == run_end {
            run_end += 1;
            j += 1;
        }
        let run_len = run_end - run_start;

        if run_len >= 8 {
            let date_part = &stem[run_start..run_start + 8];
            let year: u32 = date_part[0..4].parse().ok()?;
            let month: u32 = date_part[4..6].parse().ok()?;
            let day: u32 = date_part[6..8].parse().ok()?;

            if (1900..=2100).contains(&year) && (1..=12).contains(&month) && (1..=31).contains(&day)
            {
                // Try to extract time if there are 6 more digits (HHMMSS)
                if run_len >= 14 {
                    let time_part = &stem[run_start + 8..run_start + 14];
                    let hour: u32 = time_part[0..2].parse().unwrap_or(0);
                    let min: u32 = time_part[2..4].parse().unwrap_or(0);
                    let sec: u32 = time_part[4..6].parse().unwrap_or(0);
                    if hour < 24 && min < 60 && sec < 60 {
                        return Some(format!(
                            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                            year, month, day, hour, min, sec
                        ));
                    }
                }
                // Also check if time follows after a separator (- or _)
                let after_date = run_start + 8;
                if after_date < stem.len() {
                    let sep = stem.as_bytes().get(after_date).copied();
                    if matches!(sep, Some(b'-') | Some(b'_')) && after_date + 7 <= stem.len() {
                        let time_candidate = &stem[after_date + 1..];
                        if time_candidate.len() >= 6 {
                            let time_part = &time_candidate[..6];
                            if time_part.chars().all(|c| c.is_ascii_digit()) {
                                let hour: u32 = time_part[0..2].parse().unwrap_or(99);
                                let min: u32 = time_part[2..4].parse().unwrap_or(99);
                                let sec: u32 = time_part[4..6].parse().unwrap_or(99);
                                if hour < 24 && min < 60 && sec < 60 {
                                    return Some(format!(
                                        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}",
                                        year, month, day, hour, min, sec
                                    ));
                                }
                            }
                        }
                    }
                }
                // Date only, no time
                return Some(format!("{:04}-{:02}-{:02}T00:00:00", year, month, day));
            }
        }

        i = j;
    }

    None
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

    #[test]
    fn test_parse_date_from_filename_whatsapp() {
        let path = Path::new("IMG-20260509-WA0013.jpg");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-05-09T00:00:00".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_whatsapp_video() {
        let path = Path::new("VID-20260325-WA0001.mp4");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-03-25T00:00:00".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_android_camera() {
        let path = Path::new("IMG_20260320_204959055.jpg");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-03-20T20:49:59".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_screenshot() {
        let path = Path::new("Screenshot_20260101-143456.png");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-01-01T14:34:56".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_pixel() {
        let path = Path::new("PXL_20260509_143456789.jpg");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-05-09T14:34:56".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_bare_timestamp() {
        let path = Path::new("20260509_143456.jpg");
        assert_eq!(
            parse_date_from_filename(path),
            Some("2026-05-09T14:34:56".to_string())
        );
    }

    #[test]
    fn test_parse_date_from_filename_no_date() {
        assert_eq!(parse_date_from_filename(Path::new("photo.jpg")), None);
        assert_eq!(parse_date_from_filename(Path::new("DSC_1234.jpg")), None);
    }

    #[test]
    fn test_parse_date_from_filename_invalid_date() {
        // Month 13 — invalid
        assert_eq!(
            parse_date_from_filename(Path::new("IMG-20261309-WA0001.jpg")),
            None
        );
    }

    #[test]
    fn test_parse_date_from_filename_dotfiles_skipped() {
        // Dotfiles with digits should not be treated as photos
        assert_eq!(
            parse_date_from_filename(Path::new(".nfs.20051026.3f4c")),
            None
        );
        assert_eq!(parse_date_from_filename(Path::new(".DS_Store")), None);
    }

    #[test]
    fn test_write_exif_date_roundtrip() {
        // Create a minimal JPEG, write EXIF date, read it back
        let dir = std::env::temp_dir().join("tilde_exif_write_test");
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let jpeg_path = dir.join("test.jpg");
        // Create a tiny valid JPEG using the image crate
        let img = image::RgbImage::new(8, 8);
        img.save(&jpeg_path).unwrap();

        // Write EXIF date
        write_exif_date(&jpeg_path, "2026-05-09T14:30:00").unwrap();

        // Read it back with nom-exif to verify
        let meta = read_metadata(&jpeg_path).unwrap();
        assert!(
            meta.date_time_original.is_some(),
            "DateTimeOriginal should be present after writing"
        );
        let date = meta.date_time_original.unwrap();
        assert!(
            date.contains("2026") && date.contains("05") && date.contains("09"),
            "Date should contain 2026-05-09, got: {}",
            date
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
