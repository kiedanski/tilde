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

/// Compute a blurhash string from an image file.
/// Returns a short hash string suitable for placeholder display.
pub fn compute_blurhash(source: &Path) -> Result<String> {
    let img = image::open(source).context("Failed to open image for blurhash")?;
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
