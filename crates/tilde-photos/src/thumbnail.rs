//! Thumbnail generation for photos
//!
//! Generates WebP thumbnails at 256px (square crop) and 1920px (longest edge).

use anyhow::{Context, Result, bail};
use image::imageops::FilterType;
use std::path::{Path, PathBuf};
use tracing::{debug, info};

/// Generate thumbnails for a photo, storing them in the cache directory.
///
/// Returns (path_256, path_1920) on success.
pub fn generate_thumbnails(
    source: &Path,
    photo_uuid: &str,
    cache_dir: &Path,
    quality: u8,
) -> Result<(PathBuf, PathBuf)> {
    let thumb_dir = cache_dir.join("thumbnails").join(photo_uuid);
    std::fs::create_dir_all(&thumb_dir)?;

    let path_256 = thumb_dir.join("256.webp");
    let path_1920 = thumb_dir.join("1920.webp");

    debug!(source = %source.display(), uuid = %photo_uuid, "Generating thumbnails");

    let img = image::open(source).context("Failed to open image for thumbnail generation")?;

    // 256px square crop
    let thumb_256 = img.resize_to_fill(256, 256, FilterType::Lanczos3);
    save_webp(&thumb_256, &path_256, quality)?;

    // 1920px longest edge
    let (w, h) = (img.width(), img.height());
    let (new_w, new_h) = if w > h {
        (1920, (1920.0 * h as f64 / w as f64) as u32)
    } else {
        ((1920.0 * w as f64 / h as f64) as u32, 1920)
    };
    // Only downscale, don't upscale
    let thumb_1920 = if w > 1920 || h > 1920 {
        img.resize(new_w, new_h, FilterType::Lanczos3)
    } else {
        img.clone()
    };
    save_webp(&thumb_1920, &path_1920, quality)?;

    info!(uuid = %photo_uuid, "Thumbnails generated");

    Ok((path_256, path_1920))
}

/// Generate a thumbnail for a video using ffmpeg
pub fn generate_video_thumbnail(
    source: &Path,
    photo_uuid: &str,
    cache_dir: &Path,
    quality: u8,
    _timeout_secs: u64,
) -> Result<(PathBuf, PathBuf)> {
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

    // Generate thumbnails from the extracted frame
    let result = generate_thumbnails(&temp_png, photo_uuid, cache_dir, quality);

    // Clean up temp file
    let _ = std::fs::remove_file(&temp_png);

    result
}

/// Save an image as WebP
fn save_webp(img: &image::DynamicImage, path: &Path, _quality: u8) -> Result<()> {
    // The image crate supports WebP encoding
    img.save(path).context("Failed to save WebP thumbnail")?;
    Ok(())
}

/// Compute a simple blurhash-like placeholder string
/// This is a simplified version — for production, use a proper blurhash crate
pub fn compute_blurhash_placeholder(source: &Path) -> Option<String> {
    let img = image::open(source).ok()?;
    let small = img.resize_exact(4, 3, FilterType::Nearest);
    let rgb = small.to_rgb8();

    // Encode as base64 of averaged color blocks
    let mut colors = Vec::new();
    for pixel in rgb.pixels() {
        colors.push(format!("{:02x}{:02x}{:02x}", pixel[0], pixel[1], pixel[2]));
    }
    Some(colors.join(""))
}

/// Mark thumbnails as generated in the database
pub fn mark_thumbnails_generated(
    conn: &rusqlite::Connection,
    photo_id: &str,
    size_256: bool,
    size_1920: bool,
) -> Result<()> {
    conn.execute(
        "UPDATE photos SET thumbnail_256_generated = ?1, thumbnail_1920_generated = ?2 WHERE id = ?3",
        rusqlite::params![size_256 as i32, size_1920 as i32, photo_id],
    )?;
    Ok(())
}
