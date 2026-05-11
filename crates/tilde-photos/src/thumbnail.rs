//! Thumbnail generation for photos
//!
//! Generates WebP thumbnails at 256px (square crop) and 1920px (longest edge).

use anyhow::{Context, Result, bail};
use image::DynamicImage;
use image::imageops::FilterType;
use std::path::{Path, PathBuf};
#[cfg(feature = "heic")]
use std::sync::Mutex;
use tracing::{debug, info};

/// Single-slot semaphore for HEIC decoding only.
/// HEIC files can use 200+ MB during decode (20 MP × 3 bytes × overhead),
/// so we serialize them to prevent OOM. JPEG/PNG are cheap and run freely.
#[cfg(feature = "heic")]
static HEIC_DECODE_LOCK: Mutex<()> = Mutex::new(());

/// Check if a file is HEIC/HEIF based on extension
fn is_heic(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| {
            let lower = e.to_lowercase();
            lower == "heic" || lower == "heif"
        })
        .unwrap_or(false)
}

/// Decode a HEIC/HEIF file using libheif-rs, returning an image::DynamicImage
#[cfg(feature = "heic")]
fn decode_heic(path: &Path) -> Result<DynamicImage> {
    use libheif_rs::{ColorSpace, HeifContext, LibHeif, RgbChroma};

    let lib_heif = LibHeif::new();
    let ctx = HeifContext::read_from_file(path.to_str().unwrap_or_default())
        .context("Failed to read HEIC file")?;
    let handle = ctx
        .primary_image_handle()
        .context("Failed to get primary image handle")?;

    let width = handle.width();
    let height = handle.height();

    // Guard against crafted images with absurd dimensions (OOM prevention)
    const MAX_MEGAPIXELS: u64 = 200; // 200 MP covers all consumer cameras
    let pixels = (width as u64)
        .checked_mul(height as u64)
        .unwrap_or(u64::MAX);
    if pixels > MAX_MEGAPIXELS * 1_000_000 {
        bail!(
            "HEIC image too large: {}x{} ({} MP exceeds {} MP cap)",
            width,
            height,
            pixels / 1_000_000,
            MAX_MEGAPIXELS
        );
    }

    let img = lib_heif
        .decode(&handle, ColorSpace::Rgb(RgbChroma::Rgb), None)
        .context("Failed to decode HEIC image")?;
    let plane = img
        .planes()
        .interleaved
        .context("Failed to get interleaved plane from HEIC")?;
    let data = plane.data;
    let stride = plane.stride;

    // Copy row-by-row to handle stride != width*3
    let capacity = (width as usize)
        .checked_mul(height as usize)
        .and_then(|p| p.checked_mul(3))
        .context("Image dimensions overflow")?;
    let mut rgb_data = Vec::with_capacity(capacity);
    for y in 0..height as usize {
        let row_start = y * stride;
        let row_end = row_start + (width as usize * 3);
        if row_end <= data.len() {
            rgb_data.extend_from_slice(&data[row_start..row_end]);
        }
    }

    let img_buf = image::RgbImage::from_raw(width, height, rgb_data)
        .context("Failed to create image buffer from HEIC data")?;

    Ok(DynamicImage::ImageRgb8(img_buf))
}

/// Open an image, using libheif-rs for HEIC/HEIF files when available.
/// HEIC decoding is serialized via HEIC_DECODE_LOCK to prevent OOM.
/// JPEG/PNG run without any lock.
fn open_image(path: &Path) -> Result<DynamicImage> {
    #[cfg(feature = "heic")]
    if is_heic(path) {
        debug!(path = %path.display(), "Decoding HEIC via libheif (serialized)");
        let _guard = HEIC_DECODE_LOCK
            .lock()
            .map_err(|e| anyhow::anyhow!("HEIC decode lock poisoned: {}", e))?;
        return decode_heic(path);
    }
    #[cfg(not(feature = "heic"))]
    if is_heic(path) {
        bail!("HEIC support not available (built without 'heic' feature)");
    }
    image::open(path).context("Failed to open image for thumbnail generation")
}

/// Generate a 256px square-crop thumbnail for a photo.
///
/// Returns the path to the generated 256px WebP thumbnail.
/// Uses a single-slot semaphore to prevent OOM on large HEIC files.
pub fn generate_thumbnails(
    source: &Path,
    photo_uuid: &str,
    cache_dir: &Path,
    quality: u8,
) -> Result<ThumbnailResult> {
    generate_thumbnails_inner(source, photo_uuid, cache_dir, quality)
}

/// Result of thumbnail generation, includes the path and an optional blurhash
/// computed from the already-loaded 256px thumbnail (avoids re-reading the full image).
pub struct ThumbnailResult {
    pub path_256: PathBuf,
    pub blurhash: Option<String>,
}

/// Inner implementation without the lock (called from generate_video_thumbnail too)
fn generate_thumbnails_inner(
    source: &Path,
    photo_uuid: &str,
    cache_dir: &Path,
    quality: u8,
) -> Result<ThumbnailResult> {
    let thumb_dir = cache_dir.join("thumbnails").join(photo_uuid);
    std::fs::create_dir_all(&thumb_dir)?;

    let path_256 = thumb_dir.join("256.webp");

    debug!(source = %source.display(), uuid = %photo_uuid, "Generating thumbnail");

    let img = open_image(source)?;

    // 256px square crop
    let thumb_256 = img.resize_to_fill(256, 256, FilterType::Lanczos3);
    save_webp(&thumb_256, &path_256, quality)?;

    // Compute blurhash from the already-loaded 256px thumbnail (not the full image)
    let blurhash = compute_blurhash_from_image(&thumb_256);

    info!(uuid = %photo_uuid, "Thumbnails generated");

    Ok(ThumbnailResult { path_256, blurhash })
}

/// Compute a blurhash string from an already-loaded image (e.g. the 256px thumbnail).
/// This avoids re-reading the full-resolution source file.
fn compute_blurhash_from_image(img: &DynamicImage) -> Option<String> {
    let small = img.resize_exact(32, 32, FilterType::Nearest);
    let rgba = small.to_rgba8();
    let pixels = rgba.as_raw();

    let x_comp = 4;
    let y_comp = 3;

    let mut dc_r: f64 = 0.0;
    let mut dc_g: f64 = 0.0;
    let mut dc_b: f64 = 0.0;

    for y in 0..32_u32 {
        for x in 0..32_u32 {
            let idx = ((y * 32 + x) * 4) as usize;
            let r = srgb_to_linear(pixels[idx]);
            let g = srgb_to_linear(pixels[idx + 1]);
            let b = srgb_to_linear(pixels[idx + 2]);
            dc_r += r;
            dc_g += g;
            dc_b += b;
        }
    }

    let count = 1024.0;
    dc_r /= count;
    dc_g /= count;
    dc_b /= count;

    let size_flag = (x_comp - 1) + (y_comp - 1) * 9;
    let mut result = String::new();
    result.push(BASE83_CHARS[size_flag as usize]);
    result.push(BASE83_CHARS[0]);
    let dc_value = encode_dc(dc_r, dc_g, dc_b);
    result.push_str(&encode_base83(dc_value, 4));
    for _j in 0..y_comp {
        for _i in 0..x_comp {
            if _i == 0 && _j == 0 {
                continue;
            }
            result.push_str(&encode_base83(0, 1));
        }
    }

    Some(result)
}

/// Compute a blurhash string from an image file.
/// Returns a short hash string suitable for placeholder display.
pub fn compute_blurhash(source: &Path) -> Result<String> {
    let img = open_image(source)?;
    // Resize to small for fast computation
    let small = img.resize_exact(32, 32, FilterType::Nearest);
    let rgba = small.to_rgba8();
    let pixels = rgba.as_raw();

    // Simple blurhash-like encoding (4x3 components)
    let x_comp = 4;
    let y_comp = 3;

    let mut dc_r: f64 = 0.0;
    let mut dc_g: f64 = 0.0;
    let mut dc_b: f64 = 0.0;

    for y in 0..32_u32 {
        for x in 0..32_u32 {
            let idx = ((y * 32 + x) * 4) as usize;
            let r = srgb_to_linear(pixels[idx]);
            let g = srgb_to_linear(pixels[idx + 1]);
            let b = srgb_to_linear(pixels[idx + 2]);
            dc_r += r;
            dc_g += g;
            dc_b += b;
        }
    }

    let count = 1024.0; // 32 * 32
    dc_r /= count;
    dc_g /= count;
    dc_b /= count;

    // Encode size flag + DC value as base83
    let size_flag = (x_comp - 1) + (y_comp - 1) * 9;
    let mut result = String::new();
    result.push(BASE83_CHARS[size_flag as usize]);

    // Quantized max AC value (simplified)
    result.push(BASE83_CHARS[0]);

    // DC value
    let dc_value = encode_dc(dc_r, dc_g, dc_b);
    result.push_str(&encode_base83(dc_value, 4));

    // AC values (simplified - just use average color components)
    for _j in 0..y_comp {
        for _i in 0..x_comp {
            if _i == 0 && _j == 0 {
                continue;
            }
            result.push_str(&encode_base83(0, 1));
        }
    }

    Ok(result)
}

const BASE83_CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
    'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b',
    'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u',
    'v', 'w', 'x', 'y', 'z', '#', '$', '%', '*', '+', ',', '-', '.', ':', ';', '=', '?', '@', '[',
    ']', '^', '_', '{', '|', '}', '~',
];

fn srgb_to_linear(value: u8) -> f64 {
    let v = value as f64 / 255.0;
    if v <= 0.04045 {
        v / 12.92
    } else {
        ((v + 0.055) / 1.055).powf(2.4)
    }
}

fn linear_to_srgb(value: f64) -> u32 {
    let v = value.clamp(0.0, 1.0);
    let srgb = if v <= 0.0031308 {
        v * 12.92
    } else {
        1.055 * v.powf(1.0 / 2.4) - 0.055
    };
    (srgb * 255.0 + 0.5) as u32
}

fn encode_dc(r: f64, g: f64, b: f64) -> u32 {
    let r_int = linear_to_srgb(r);
    let g_int = linear_to_srgb(g);
    let b_int = linear_to_srgb(b);
    (r_int << 16) + (g_int << 8) + b_int
}

fn encode_base83(value: u32, length: usize) -> String {
    let mut result = String::new();
    for i in (0..length).rev() {
        let digit = (value / 83u32.pow(i as u32)) % 83;
        result.push(BASE83_CHARS[digit as usize]);
    }
    result
}

/// Generate a thumbnail for a video using ffmpeg
pub fn generate_video_thumbnail(
    source: &Path,
    photo_uuid: &str,
    cache_dir: &Path,
    quality: u8,
    _timeout_secs: u64,
) -> Result<ThumbnailResult> {
    let thumb_dir = cache_dir.join("thumbnails").join(photo_uuid);
    std::fs::create_dir_all(&thumb_dir)?;

    // Extract first frame via ffmpeg to a temp PNG
    let temp_png = thumb_dir.join("_temp_frame.png");

    let output = std::process::Command::new("ffmpeg")
        .arg("-y")
        .arg("-i")
        .arg(source.as_os_str())
        .arg("-vframes")
        .arg("1")
        .arg("-q:v")
        .arg("2")
        .arg(temp_png.as_os_str())
        .output()
        .context("Failed to run ffmpeg for video thumbnail")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        bail!(
            "ffmpeg failed: {}",
            stderr.chars().take(500).collect::<String>()
        );
    }

    // Generate thumbnails from the extracted frame (already under lock, use inner)
    let result = generate_thumbnails_inner(&temp_png, photo_uuid, cache_dir, quality);

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_png);

    result
}

/// Save a thumbnail image as JPEG with the specified quality (0-100).
/// We use JPEG instead of WebP because the `image` crate's WebP encoder
/// only supports lossless mode, which produces ~90 KB per 256px thumbnail.
/// JPEG at quality 80 gives ~10-20 KB — a 5-8x reduction.
fn save_webp(img: &image::DynamicImage, path: &Path, quality: u8) -> Result<()> {
    // Save as JPEG despite the .webp extension (clients don't care about
    // the extension — they use Content-Type from the DAV response).
    // Convert to RGB8 since JPEG doesn't support alpha.
    let rgb = img.to_rgb8();
    let file = std::fs::File::create(path).context("Failed to create thumbnail file")?;
    let mut encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(file, quality);
    encoder
        .encode(
            &rgb,
            rgb.width(),
            rgb.height(),
            image::ExtendedColorType::Rgb8,
        )
        .context("Failed to encode JPEG thumbnail")?;
    Ok(())
}

/// Compute a simple blurhash-like placeholder string
/// This is a simplified version — for production, use a proper blurhash crate
pub fn compute_blurhash_placeholder(source: &Path) -> Option<String> {
    let img = open_image(source).ok()?;
    let small = img.resize_exact(4, 3, FilterType::Nearest);
    let rgb = small.to_rgb8();

    // Encode as base64 of averaged color blocks
    let mut colors = Vec::new();
    for pixel in rgb.pixels() {
        colors.push(format!("{:02x}{:02x}{:02x}", pixel[0], pixel[1], pixel[2]));
    }
    Some(colors.join(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heic_thumbnail_generation() {
        let temp_dir = std::env::temp_dir().join("tilde_heic_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Create a test HEIC by encoding a simple image
        let heic_path = temp_dir.join("test.heic");

        // Use heif-enc if available, otherwise skip
        let jpeg_path = temp_dir.join("input.jpg");
        // Create a simple JPEG using the image crate
        let mut img = image::RgbImage::new(200, 150);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([255, 100, 50]);
        }
        img.save(&jpeg_path).unwrap();

        // Convert to HEIC using heif-enc command
        let output = std::process::Command::new("heif-enc")
            .arg(&jpeg_path)
            .arg("-o")
            .arg(&heic_path)
            .output();

        match output {
            Ok(o) if o.status.success() => {}
            _ => {
                eprintln!("heif-enc not available, skipping HEIC test");
                return;
            }
        }

        assert!(heic_path.exists(), "HEIC file should exist");

        // Test thumbnail generation
        let cache_dir = temp_dir.join("cache");
        let result = generate_thumbnails(&heic_path, "test-heic-uuid", &cache_dir, 80).unwrap();

        assert!(result.path_256.exists(), "256px thumbnail should exist");
        assert!(
            std::fs::metadata(&result.path_256).unwrap().len() > 0,
            "256px thumbnail should not be empty"
        );
        assert!(
            result.blurhash.is_some(),
            "Blurhash should be computed from thumbnail"
        );

        // Clean up
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_heic_blurhash() {
        let temp_dir = std::env::temp_dir().join("tilde_heic_blurhash_test");
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let heic_path = temp_dir.join("test.heic");
        let jpeg_path = temp_dir.join("input.jpg");

        let mut img = image::RgbImage::new(100, 100);
        for pixel in img.pixels_mut() {
            *pixel = image::Rgb([50, 150, 200]);
        }
        img.save(&jpeg_path).unwrap();

        let output = std::process::Command::new("heif-enc")
            .arg(&jpeg_path)
            .arg("-o")
            .arg(&heic_path)
            .output();

        match output {
            Ok(o) if o.status.success() => {}
            _ => {
                eprintln!("heif-enc not available, skipping HEIC blurhash test");
                return;
            }
        }

        let hash = compute_blurhash(&heic_path).unwrap();
        assert!(!hash.is_empty(), "Blurhash should not be empty");

        let placeholder = compute_blurhash_placeholder(&heic_path);
        assert!(placeholder.is_some(), "Blurhash placeholder should be Some");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_is_heic_detection() {
        assert!(is_heic(Path::new("photo.heic")));
        assert!(is_heic(Path::new("photo.HEIC")));
        assert!(is_heic(Path::new("photo.heif")));
        assert!(is_heic(Path::new("photo.HEIF")));
        assert!(!is_heic(Path::new("photo.jpg")));
        assert!(!is_heic(Path::new("photo.png")));
    }
}

/// Create a symlink for a single photo's thumbnail in the browseable mirror directory.
/// Maps organized path (e.g. photos/2026/04/IMG.jpg) → _thumbnails/2026/04/IMG.webp
pub fn create_thumbnail_symlink(
    conn: &rusqlite::Connection,
    photo_id: &str,
    photos_base: &Path,
    cache_dir: &Path,
) -> Result<()> {
    // Get the organized file path from the DB
    let rel_path: String = conn
        .query_row(
            "SELECT f.path FROM photos p JOIN files f ON p.file_id = f.id WHERE p.id = ?1",
            [photo_id],
            |row| row.get(0),
        )
        .context("Photo not found in DB")?;

    // Strip the "photos/" prefix to get the path within photos_base
    let within_photos = rel_path.strip_prefix("photos/").unwrap_or(&rel_path);

    // Skip inbox/untriaged/errors — only mirror organized files
    if within_photos.starts_with('_') {
        return Ok(());
    }

    // Build the thumbnail source path (256px for browseable grid)
    let thumb_source = cache_dir.join("thumbnails").join(photo_id).join("256.webp");
    if !thumb_source.exists() {
        return Ok(()); // No thumbnail generated yet
    }

    // Build the symlink destination: _thumbnails/<year>/<month>/filename.webp
    let original = Path::new(within_photos);
    let stem = original
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent = original.parent().unwrap_or(Path::new(""));
    let symlink_path = photos_base
        .join("_thumbnails")
        .join(parent)
        .join(format!("{}.webp", stem));

    // Create parent directories
    if let Some(dir) = symlink_path.parent() {
        std::fs::create_dir_all(dir)?;
    }

    // Create symlink (remove existing if present)
    if symlink_path.exists() || symlink_path.symlink_metadata().is_ok() {
        let _ = std::fs::remove_file(&symlink_path);
    }

    #[cfg(unix)]
    std::os::unix::fs::symlink(&thumb_source, &symlink_path)
        .context("Failed to create thumbnail symlink")?;

    Ok(())
}

/// Rebuild the entire _thumbnails/ mirror directory from the database.
pub fn rebuild_thumbnail_mirror(
    conn: &rusqlite::Connection,
    photos_base: &Path,
    cache_dir: &Path,
) -> Result<u32> {
    let thumbnails_dir = photos_base.join("_thumbnails");

    // Clean existing mirror
    if thumbnails_dir.exists() {
        std::fs::remove_dir_all(&thumbnails_dir)?;
    }
    std::fs::create_dir_all(&thumbnails_dir)?;

    // Query all photos with thumbnails generated
    let mut stmt = conn.prepare("SELECT p.id FROM photos p WHERE p.thumbnail_256_generated = 1")?;
    let photo_ids: Vec<String> = stmt
        .query_map([], |row| row.get(0))?
        .filter_map(|r| r.ok())
        .collect();

    let mut count = 0u32;
    for photo_id in &photo_ids {
        match create_thumbnail_symlink(conn, photo_id, photos_base, cache_dir) {
            Ok(()) => count += 1,
            Err(e) => debug!(photo_id = %photo_id, error = %e, "Skipped thumbnail symlink"),
        }
    }

    info!(count = count, "Thumbnail mirror rebuilt");
    Ok(count)
}

/// Mark thumbnail as generated in the database
pub fn mark_thumbnails_generated(
    conn: &rusqlite::Connection,
    photo_id: &str,
    generated: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE photos SET thumbnail_256_generated = ?1 WHERE id = ?2",
        rusqlite::params![generated as i32, photo_id],
    )?;
    Ok(())
}
