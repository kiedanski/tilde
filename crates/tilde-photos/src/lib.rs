//! tilde-photos: photo ingestion, metadata, thumbnails, organization

pub mod exiftool;
pub mod ingest;
pub mod organize;
pub mod thumbnail;
pub mod watcher;

use rusqlite::Connection;
use std::path::Path;

/// Photo extensions we support
pub const PHOTO_EXTENSIONS: &[&str] = &[
    "jpg", "jpeg", "png", "webp", "heic", "heif", "tiff", "tif", "raw", "cr2", "nef", "arw",
];

/// Video extensions (for thumbnail extraction via ffmpeg)
pub const VIDEO_EXTENSIONS: &[&str] = &["mp4", "mov", "avi", "mkv", "webm"];

/// Check if a file extension is a supported photo type
pub fn is_photo_ext(ext: &str) -> bool {
    PHOTO_EXTENSIONS.contains(&ext.to_lowercase().as_str())
}

/// Check if a file extension is a supported video type
pub fn is_video_ext(ext: &str) -> bool {
    VIDEO_EXTENSIONS.contains(&ext.to_lowercase().as_str())
}

/// Check if a file is a supported media type (photo or video)
pub fn is_media_ext(ext: &str) -> bool {
    is_photo_ext(ext) || is_video_ext(ext)
}

/// Magic bytes for file type validation
pub fn validate_magic_bytes(path: &Path) -> Option<&'static str> {
    use std::fs::File;
    use std::io::Read;

    let mut file = File::open(path).ok()?;
    let mut header = [0u8; 16];
    let n = file.read(&mut header).ok()?;
    if n < 4 {
        return None;
    }

    // JPEG: FF D8 FF
    if header[0] == 0xFF && header[1] == 0xD8 && header[2] == 0xFF {
        return Some("image/jpeg");
    }
    // PNG: 89 50 4E 47
    if header[0..4] == [0x89, 0x50, 0x4E, 0x47] {
        return Some("image/png");
    }
    // WebP: RIFF....WEBP
    if n >= 12 && &header[0..4] == b"RIFF" && &header[8..12] == b"WEBP" {
        return Some("image/webp");
    }
    // HEIC/HEIF: ftyp at offset 4
    if n >= 12 && &header[4..8] == b"ftyp" {
        let brand = &header[8..12];
        if brand == b"heic"
            || brand == b"heix"
            || brand == b"hevc"
            || brand == b"mif1"
            || brand == b"msf1"
        {
            return Some("image/heic");
        }
        // MP4/MOV video
        if brand == b"isom"
            || brand == b"mp41"
            || brand == b"mp42"
            || brand == b"M4V "
            || brand == b"qt  "
        {
            return Some("video/mp4");
        }
    }
    // TIFF: 49 49 2A 00 (little-endian) or 4D 4D 00 2A (big-endian)
    if (header[0..4] == [0x49, 0x49, 0x2A, 0x00]) || (header[0..4] == [0x4D, 0x4D, 0x00, 0x2A]) {
        return Some("image/tiff");
    }
    // GIF
    if n >= 6 && &header[0..3] == b"GIF" {
        return Some("image/gif");
    }

    // Encrypted file detection
    if header[0] == 0x85 || (header[0] >= 0xC0 && header[0] <= 0xCF) {
        return Some("application/pgp-encrypted");
    }
    if n >= 16 && &header[0..3] == b"age" {
        return Some("application/age-encrypted");
    }

    None
}

/// Check if a content type indicates an encrypted file
pub fn is_encrypted(content_type: &str) -> bool {
    content_type.contains("encrypted") || content_type.contains("pgp")
}

/// Compute the blob store path for a photo UUID with two-level directory sharding.
/// Returns: blobs/by-id/<first2>/<next2>/<uuid>.<ext>
pub fn blob_store_path(data_dir: &Path, uuid: &str, ext: &str) -> std::path::PathBuf {
    let uuid_clean = uuid.replace('-', "");
    let first2 = &uuid_clean[..2.min(uuid_clean.len())];
    let next2 = if uuid_clean.len() > 2 {
        &uuid_clean[2..4.min(uuid_clean.len())]
    } else {
        "00"
    };
    data_dir
        .join("blobs")
        .join("by-id")
        .join(first2)
        .join(next2)
        .join(format!("{}.{}", uuid, ext))
}

/// Copy a photo to the content-addressed blob store.
pub fn store_blob(
    data_dir: &Path,
    source: &Path,
    uuid: &str,
) -> anyhow::Result<std::path::PathBuf> {
    let ext = source.extension().and_then(|e| e.to_str()).unwrap_or("bin");
    let blob_path = blob_store_path(data_dir, uuid, ext);
    if let Some(parent) = blob_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // Copy (not move) so the organized file stays in place
    if !blob_path.exists() {
        std::fs::copy(source, &blob_path)?;
    }
    Ok(blob_path)
}

/// Index a single photo file into the database, reading metadata via ExifTool
pub fn index_photo(
    conn: &Connection,
    file_path: &Path,
    photos_base: &Path,
    content_type: &str,
) -> anyhow::Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;

    let rel_path = file_path
        .strip_prefix(photos_base)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| file_path.file_name().unwrap().to_string_lossy().to_string());

    // Compute SHA-256
    let mut file = std::fs::File::open(file_path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let sha256 = format!("{:x}", hasher.finalize());

    let meta = file_path.metadata()?;
    let size = meta.len() as i64;
    let file_id = uuid::Uuid::new_v4().to_string();
    let photo_id = file_id.clone();
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    // Store blob in content-addressed store with two-level sharding
    if let Some(data_dir) = photos_base.parent()
        && let Err(e) = store_blob(data_dir, file_path, &photo_id)
    {
        tracing::warn!(error = %e, "Failed to store blob (non-fatal)");
    }
    let filename = file_path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = format!(
        "photos/{}",
        file_path
            .parent()
            .and_then(|p| p.strip_prefix(photos_base).ok())
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_default()
    );

    let encrypted = is_encrypted(content_type);

    // Read EXIF metadata via ExifTool (if available and not encrypted)
    let exif = if !encrypted {
        exiftool::read_metadata(file_path).ok()
    } else {
        None
    };

    let taken_at = exif.as_ref().and_then(|e| e.date_time_original.clone());
    let camera_make = exif.as_ref().and_then(|e| e.camera_make.clone());
    let camera_model = exif.as_ref().and_then(|e| e.camera_model.clone());
    let lens = exif.as_ref().and_then(|e| e.lens.clone());
    let focal_length = exif.as_ref().and_then(|e| e.focal_length_mm);
    let aperture = exif.as_ref().and_then(|e| e.aperture);
    let iso = exif.as_ref().and_then(|e| e.iso);
    let exposure = exif.as_ref().and_then(|e| e.exposure_time.clone());
    let gps_lat = exif.as_ref().and_then(|e| e.gps_latitude);
    let gps_lon = exif.as_ref().and_then(|e| e.gps_longitude);
    let gps_alt = exif.as_ref().and_then(|e| e.gps_altitude);
    let orientation = exif.as_ref().and_then(|e| e.orientation);
    let width = exif.as_ref().and_then(|e| e.width);
    let height = exif.as_ref().and_then(|e| e.height);
    let tags_json = exif.as_ref().and_then(|e| {
        if e.tags.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&e.tags).unwrap())
        }
    });

    // Insert file entry
    conn.execute(
        "INSERT OR IGNORE INTO files (id, path, parent_path, name, size_bytes, content_type, etag, sha256, is_directory, created_at, modified_at, hlc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 0, ?9, ?10, ?11)",
        rusqlite::params![
            file_id,
            format!("photos/{}", rel_path),
            parent,
            filename,
            size,
            content_type,
            format!("\"{}\"", &sha256[..16]),
            sha256,
            now, now, now,
        ],
    )?;

    // Insert photo entry
    conn.execute(
        "INSERT OR IGNORE INTO photos (id, file_id, original_sha256, current_sha256, width, height, taken_at, camera_make, camera_model, lens, focal_length_mm, aperture, iso, exposure_time, gps_latitude, gps_longitude, gps_altitude, orientation, content_readable, tags_json, created_at, updated_at, hlc)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18, ?19, ?20, ?21, ?22, ?23)",
        rusqlite::params![
            photo_id, file_id,
            sha256, sha256,
            width, height,
            taken_at, camera_make, camera_model, lens,
            focal_length, aperture, iso, exposure,
            gps_lat, gps_lon, gps_alt, orientation,
            if encrypted { 0 } else { 1 },
            tags_json,
            now, now, now,
        ],
    )?;

    // Insert tags
    if let Some(ref exif_data) = exif {
        for tag_str in &exif_data.tags {
            let prefix = exiftool::classify_tag_prefix(tag_str);
            conn.execute(
                "INSERT OR IGNORE INTO photo_tags (photo_id, tag, prefix) VALUES (?1, ?2, ?3)",
                rusqlite::params![photo_id, tag_str, prefix],
            )?;
        }
    }

    // Compute blurhash if the file is a readable image
    if !encrypted {
        match thumbnail::compute_blurhash(file_path) {
            Ok(hash) => {
                conn.execute(
                    "UPDATE photos SET blurhash = ?1 WHERE id = ?2",
                    rusqlite::params![hash, photo_id],
                )?;
            }
            Err(e) => {
                tracing::debug!(error = %e, "Failed to compute blurhash (non-fatal)");
            }
        }
    }

    Ok(photo_id)
}

/// Create a thumbnail generation job in the jobs queue.
/// Returns the job ID.
pub fn create_thumbnail_job(
    conn: &Connection,
    photo_id: &str,
    file_path: &str,
    cache_dir: &str,
    quality: u8,
) -> anyhow::Result<i64> {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let payload = serde_json::json!({
        "photo_id": photo_id,
        "file_path": file_path,
        "cache_dir": cache_dir,
        "quality": quality,
    });
    conn.execute(
        "INSERT INTO jobs (job_type, payload_json, status, created_at) VALUES ('thumbnail', ?1, 'pending', ?2)",
        rusqlite::params![payload.to_string(), now],
    )?;
    let id = conn.last_insert_rowid();
    Ok(id)
}

/// Process pending jobs from the jobs queue.
/// Returns the number of jobs processed.
pub fn process_pending_jobs(
    conn: &Connection,
    max_jobs: usize,
) -> anyhow::Result<usize> {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    let mut processed = 0;
    for _ in 0..max_jobs {
        // Fetch next pending job
        let job = conn.query_row(
            "SELECT id, job_type, payload_json, attempts, max_attempts FROM jobs WHERE status = 'pending' ORDER BY created_at ASC LIMIT 1",
            [],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        );

        let (job_id, job_type, payload_json, attempts, max_attempts) = match job {
            Ok(j) => j,
            Err(rusqlite::Error::QueryReturnedNoRows) => break,
            Err(e) => return Err(e.into()),
        };

        // Mark as running
        conn.execute(
            "UPDATE jobs SET status = 'running', started_at = ?1, attempts = attempts + 1 WHERE id = ?2",
            rusqlite::params![now, job_id],
        )?;

        let result = match job_type.as_str() {
            "thumbnail" => process_thumbnail_job(&payload_json),
            _ => Err(anyhow::anyhow!("Unknown job type: {}", job_type)),
        };

        match result {
            Ok(()) => {
                conn.execute(
                    "UPDATE jobs SET status = 'completed', completed_at = ?1 WHERE id = ?2",
                    rusqlite::params![now, job_id],
                )?;
            }
            Err(e) => {
                let error_msg = format!("{}", e);
                if attempts + 1 >= max_attempts {
                    conn.execute(
                        "UPDATE jobs SET status = 'failed', error_message = ?1 WHERE id = ?2",
                        rusqlite::params![error_msg, job_id],
                    )?;
                } else {
                    conn.execute(
                        "UPDATE jobs SET status = 'pending', error_message = ?1, started_at = NULL WHERE id = ?2",
                        rusqlite::params![error_msg, job_id],
                    )?;
                }
            }
        }

        processed += 1;
    }

    Ok(processed)
}

fn process_thumbnail_job(payload_json: &str) -> anyhow::Result<()> {
    let payload: serde_json::Value = serde_json::from_str(payload_json)?;
    let photo_id = payload.get("photo_id").and_then(|v| v.as_str()).unwrap_or("");
    let file_path = payload.get("file_path").and_then(|v| v.as_str()).unwrap_or("");
    let cache_dir = payload.get("cache_dir").and_then(|v| v.as_str()).unwrap_or("");
    let quality = payload.get("quality").and_then(|v| v.as_u64()).unwrap_or(80) as u8;

    let file = std::path::Path::new(file_path);
    let cache = std::path::Path::new(cache_dir);
    let ext = file.extension().and_then(|e| e.to_str()).unwrap_or("");

    if is_photo_ext(ext) {
        thumbnail::generate_thumbnails(file, photo_id, cache, quality)?;
    } else if is_video_ext(ext) {
        thumbnail::generate_video_thumbnail(file, photo_id, cache, quality, 60)?;
    }

    Ok(())
}
