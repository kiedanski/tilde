//! photos MCP tools. See plan.md §8.
//!
//! Each domain module owns its tool definitions and execution, so the tool
//! surface can grow without every change colliding in `lib.rs`.
//!
//! All tools here are read-only metadata queries over the `photos` table
//! (joined to `files` for the path). Nothing in this module writes, moves or
//! deletes a photo, and no tool returns image bytes.
//!
//! ## The undated sentinel
//!
//! Migration `008_untriaged_sentinel_date.sql` gives every photo that has no
//! EXIF capture date a sentinel `taken_at` of `1800-01-01T00:00:00+00:00`, so
//! untriaged imports still show up in date-ordered listings instead of
//! vanishing on a `NULL`. That sentinel is a placeholder, not a date: it would
//! otherwise pollute "oldest photo" answers and date-range filters. Every query
//! in this module therefore treats `taken_at IS NULL` or a `1800-01-01` prefix
//! as *undated*, excludes those rows by default, and reports them as
//! `taken_at: null` with `"undated": true` rather than echoing the sentinel
//! string back to the caller.

use crate::ToolDef;
use rusqlite::{Connection, types::ToSql};
use serde_json::{Value, json};

/// Default number of rows returned when the caller gives no `limit`.
const DEFAULT_LIMIT: i64 = 50;
/// Hard ceiling on rows returned by any single call. Larger limits are clamped.
const MAX_LIMIT: i64 = 200;

/// SQL fragment matching photos that have a real EXIF capture date.
const DATED: &str = "(p.taken_at IS NOT NULL AND p.taken_at NOT LIKE '1800-01-01%')";
/// SQL fragment matching photos with no EXIF capture date (NULL or sentinel).
const UNDATED: &str = "(p.taken_at IS NULL OR p.taken_at LIKE '1800-01-01%')";

/// Columns shared by `photos.search` and `photos.recent`.
const SUMMARY_COLUMNS: &str = "p.id, f.path, p.taken_at, p.camera_make, p.camera_model, \
     p.width, p.height, p.gps_latitude, p.gps_longitude, p.tags_json";

/// Tool definitions contributed by this module.
pub fn defs() -> Vec<ToolDef> {
    vec![
        ToolDef {
            name: "photos.search".into(),
            description: "Search indexed photos by metadata (date range, camera, lens, tag, GPS \
                 presence). Read-only; never returns image bytes. All filters are ANDed; with no \
                 filters it returns the most recent photos. Dates accept either `YYYY-MM-DD` \
                 (whole day, inclusive on both ends) or a full ISO 8601 datetime; anything else \
                 is rejected with an error. `camera_make`, `camera_model` and `lens` are \
                 case-insensitive substring matches. Photos with no EXIF date carry a sentinel \
                 `taken_at` of 1800-01-01 in the database; they are EXCLUDED by default, are \
                 always excluded when `from`/`to` is given (a sentinel date is not a real date), \
                 and can otherwise be included with `include_undated: true`, where they sort last \
                 and are reported as `taken_at: null, undated: true`. Results are ordered by \
                 `taken_at` descending, then path. `limit` defaults to 50 and is clamped to 200. \
                 Returns {photos: [{id, path, taken_at, undated, camera_make, camera_model, \
                 width, height, has_gps, tags}], count, limit, truncated} where `truncated` is \
                 true when the result hit `limit` and more rows may exist — narrow the filters or \
                 raise `limit` rather than assuming the library is that small. Requires photos:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "from": {"type": "string", "description": "Earliest capture date, inclusive. 'YYYY-MM-DD' or ISO 8601 datetime."},
                    "to": {"type": "string", "description": "Latest capture date, inclusive. 'YYYY-MM-DD' covers the whole day."},
                    "camera_make": {"type": "string", "description": "Case-insensitive substring of camera make, e.g. 'fuji'."},
                    "camera_model": {"type": "string", "description": "Case-insensitive substring of camera model, e.g. 'X-T4'."},
                    "lens": {"type": "string", "description": "Case-insensitive substring of the lens name."},
                    "tag": {"type": "string", "description": "Exact tag (matched against the photo_tags table and the tags_json blob)."},
                    "has_gps": {"type": "boolean", "description": "true = only photos with GPS coordinates; false = only photos without. Omit for both."},
                    "include_undated": {"type": "boolean", "description": "Include photos with no EXIF date (default false). Ignored when 'from' or 'to' is set — those are always date-filtered."},
                    "limit": {"type": "integer", "description": "Max rows (default 50, clamped to 200)."}
                }
            }),
        },
        ToolDef {
            name: "photos.recent".into(),
            description: "List the most recently taken photos, newest EXIF capture date first \
                 (ties broken by path). Read-only metadata only; no image bytes. Photos with no \
                 EXIF date hold a sentinel `taken_at` of 1800-01-01 and are EXCLUDED unless \
                 `include_undated: true`, in which case they sort last and come back as \
                 `taken_at: null, undated: true`. This orders by capture time, NOT by import \
                 time, so a freshly imported old scan will not appear at the top. `limit` \
                 defaults to 50 and is clamped to 200. Returns {photos: [{id, path, taken_at, \
                 undated, camera_make, camera_model, width, height, has_gps, tags}], count, \
                 limit, truncated}. An empty `photos` array means the library has no dated \
                 photos, not that indexing failed — call photos.stats to tell those apart. Requires \
                 photos:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "limit": {"type": "integer", "description": "Max rows (default 50, clamped to 200)."},
                    "include_undated": {"type": "boolean", "description": "Include photos with no EXIF date, sorted last (default false)."}
                }
            }),
        },
        ToolDef {
            name: "photos.get".into(),
            description: "Fetch the full stored metadata for one photo, addressed by either `id` \
                 (photo UUID, as returned by photos.search) or `path` (exact file path as stored \
                 in the files table — not a glob, not a substring, no fuzzy matching). Exactly \
                 one of the two must be given; supplying neither or both is an error, and an \
                 unknown id/path is an error naming the value that missed, not an empty result. \
                 Read-only; returns metadata only, never image bytes. Returns {id, path, \
                 taken_at, undated, camera_make, camera_model, lens, focal_length_mm, aperture, \
                 iso, exposure_time, width, height, orientation, gps: {latitude, longitude, \
                 altitude} or null, tags, blurhash, content_readable, manually_placed, \
                 thumbnail_256_generated, thumbnail_1920_generated, original_sha256, \
                 current_sha256, size_bytes, content_type, created_at, updated_at}. Any EXIF \
                 field absent from the file is null. `taken_at` is null with `undated: true` \
                 when the photo carries the 1800-01-01 no-EXIF-date sentinel. Requires photos:read scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "Photo UUID. Mutually exclusive with 'path'."},
                    "path": {"type": "string", "description": "Exact stored file path, e.g. '/photos/2024/05/IMG_1234.jpg'. Mutually exclusive with 'id'."}
                }
            }),
        },
        ToolDef {
            name: "photos.stats".into(),
            description: "Summarise the photo library so you can orient yourself before \
                 querying: total indexed photos, how many carry a real EXIF date versus the \
                 1800-01-01 no-EXIF-date sentinel, the true capture-date range (computed over \
                 dated photos only, so the sentinel never shows up as 'earliest'), GPS coverage, \
                 thumbnail coverage, total bytes on disk, and the most common cameras. Read-only, \
                 takes no filters, and is cheap. Returns {total, dated, undated, \
                 earliest_taken_at, latest_taken_at, with_gps, without_gps, \
                 thumbnail_256_generated, thumbnail_1920_generated, total_bytes, \
                 distinct_camera_models, top_cameras: [{camera_make, camera_model, count}]} — \
                 `top_cameras` lists at most 10 entries and is therefore not a complete \
                 inventory. On an empty library `total` is 0 and both date bounds are null. Requires photos:read \
                 scope."
                .into(),
            input_schema: json!({
                "type": "object",
                "properties": {}
            }),
        },
    ]
}

/// Execute a tool owned by this module. Returns `None` if `tool` is not ours.
pub fn exec(tool: &str, conn: &Connection, params: &Value) -> Option<Result<Value, String>> {
    match tool {
        "photos.search" => Some(exec_search(conn, params)),
        "photos.recent" => Some(exec_recent(conn, params)),
        "photos.get" => Some(exec_get(conn, params)),
        "photos.stats" => Some(exec_stats(conn, params)),
        _ => None,
    }
}

/// Required scope for a tool owned by this module, if any.
pub fn required_scope(tool: &str) -> Option<&'static str> {
    match tool {
        "photos.search" | "photos.recent" | "photos.get" | "photos.stats" => Some("photos:read"),
        _ => None,
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────────

/// Clamp a caller-supplied `limit` into `1..=MAX_LIMIT`, defaulting when absent.
fn resolve_limit(args: &Value) -> i64 {
    match args.get("limit").and_then(|v| v.as_i64()) {
        Some(n) if n < 1 => 1,
        Some(n) => n.min(MAX_LIMIT),
        None => DEFAULT_LIMIT,
    }
}

/// True when `taken_at` is absent or holds the 1800-01-01 no-EXIF sentinel.
fn is_undated(taken_at: Option<&str>) -> bool {
    match taken_at {
        None => true,
        Some(t) => t.starts_with("1800-01-01"),
    }
}

/// Reject obviously non-ISO date input early, with a message that says what is
/// accepted rather than letting it silently match nothing.
fn validate_date(field: &str, value: &str) -> Result<(), String> {
    let bytes = value.as_bytes();
    let looks_iso = bytes.len() >= 10
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit);
    if looks_iso {
        Ok(())
    } else {
        Err(format!(
            "{} must be an ISO 8601 date (YYYY-MM-DD) or datetime, got {:?}",
            field, value
        ))
    }
}

/// Tags for a photo: the `photo_tags` rows unioned with the `tags_json` blob,
/// deduplicated and sorted so output is stable.
fn tags_for(conn: &Connection, photo_id: &str, tags_json: Option<&str>) -> Vec<String> {
    let mut tags: Vec<String> = Vec::new();

    if let Ok(mut stmt) = conn.prepare("SELECT tag FROM photo_tags WHERE photo_id = ?1")
        && let Ok(rows) = stmt.query_map([photo_id], |row| row.get::<_, String>(0))
    {
        tags.extend(rows.filter_map(|r| r.ok()));
    }

    if let Some(raw) = tags_json
        && let Ok(Value::Array(items)) = serde_json::from_str::<Value>(raw)
    {
        tags.extend(
            items
                .iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .filter(|s| !s.is_empty()),
        );
    }

    tags.sort();
    tags.dedup();
    tags
}

/// One row of the shared `SUMMARY_COLUMNS` projection.
struct SummaryRow {
    id: String,
    path: String,
    taken_at: Option<String>,
    camera_make: Option<String>,
    camera_model: Option<String>,
    width: Option<i64>,
    height: Option<i64>,
    gps_latitude: Option<f64>,
    gps_longitude: Option<f64>,
    tags_json: Option<String>,
}

fn read_summary_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SummaryRow> {
    Ok(SummaryRow {
        id: row.get(0)?,
        path: row.get(1)?,
        taken_at: row.get(2)?,
        camera_make: row.get(3)?,
        camera_model: row.get(4)?,
        width: row.get(5)?,
        height: row.get(6)?,
        gps_latitude: row.get(7)?,
        gps_longitude: row.get(8)?,
        tags_json: row.get(9)?,
    })
}

fn summary_to_json(conn: &Connection, row: &SummaryRow) -> Value {
    let undated = is_undated(row.taken_at.as_deref());
    json!({
        "id": row.id,
        "path": row.path,
        "taken_at": if undated { None } else { row.taken_at.clone() },
        "undated": undated,
        "camera_make": row.camera_make,
        "camera_model": row.camera_model,
        "width": row.width,
        "height": row.height,
        "has_gps": row.gps_latitude.is_some() && row.gps_longitude.is_some(),
        "tags": tags_for(conn, &row.id, row.tags_json.as_deref()),
    })
}

/// Run a `SUMMARY_COLUMNS` query and shape it into the common result envelope.
fn run_summary_query(
    conn: &Connection,
    sql: &str,
    params: &[&dyn ToSql],
    limit: i64,
) -> Result<Value, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let rows: Vec<SummaryRow> = stmt
        .query_map(params, read_summary_row)
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    let photos: Vec<Value> = rows.iter().map(|r| summary_to_json(conn, r)).collect();
    Ok(json!({
        "photos": photos,
        "count": photos.len(),
        "limit": limit,
        "truncated": photos.len() as i64 >= limit,
    }))
}

// ─── Tool implementations ────────────────────────────────────────────────

fn exec_search(conn: &Connection, args: &Value) -> Result<Value, String> {
    let mut sql = format!(
        "SELECT {} FROM photos p JOIN files f ON p.file_id = f.id WHERE 1=1",
        SUMMARY_COLUMNS
    );
    let mut params: Vec<Box<dyn ToSql>> = Vec::new();

    let from = args.get("from").and_then(|v| v.as_str());
    let to = args.get("to").and_then(|v| v.as_str());

    if let Some(from) = from {
        validate_date("from", from)?;
        // A bare YYYY-MM-DD compares against the date part so the whole day is
        // covered; a full datetime compares directly.
        if from.len() == 10 {
            params.push(Box::new(from.to_string()));
            sql.push_str(&format!(
                " AND substr(p.taken_at, 1, 10) >= ?{}",
                params.len()
            ));
        } else {
            params.push(Box::new(from.to_string()));
            sql.push_str(&format!(" AND p.taken_at >= ?{}", params.len()));
        }
    }
    if let Some(to) = to {
        validate_date("to", to)?;
        if to.len() == 10 {
            params.push(Box::new(to.to_string()));
            sql.push_str(&format!(
                " AND substr(p.taken_at, 1, 10) <= ?{}",
                params.len()
            ));
        } else {
            params.push(Box::new(to.to_string()));
            sql.push_str(&format!(" AND p.taken_at <= ?{}", params.len()));
        }
    }

    // The sentinel is not a real date: a date-filtered search never returns it,
    // whatever `include_undated` says. Without a date filter, it is opt-in.
    let date_filtered = from.is_some() || to.is_some();
    let include_undated = args
        .get("include_undated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if date_filtered || !include_undated {
        sql.push_str(&format!(" AND {}", DATED));
    }

    for (field, column) in [
        ("camera_make", "p.camera_make"),
        ("camera_model", "p.camera_model"),
        ("lens", "p.lens"),
    ] {
        if let Some(value) = args.get(field).and_then(|v| v.as_str()) {
            params.push(Box::new(format!("%{}%", value)));
            sql.push_str(&format!(" AND {} LIKE ?{}", column, params.len()));
        }
    }

    if let Some(tag) = args.get("tag").and_then(|v| v.as_str()) {
        params.push(Box::new(tag.to_string()));
        let exact = params.len();
        params.push(Box::new(format!("%\"{}\"%", tag)));
        let in_json = params.len();
        sql.push_str(&format!(
            " AND (EXISTS (SELECT 1 FROM photo_tags pt WHERE pt.photo_id = p.id AND pt.tag = ?{}) \
             OR p.tags_json LIKE ?{})",
            exact, in_json
        ));
    }

    match args.get("has_gps").and_then(|v| v.as_bool()) {
        Some(true) => {
            sql.push_str(" AND p.gps_latitude IS NOT NULL AND p.gps_longitude IS NOT NULL")
        }
        Some(false) => sql.push_str(" AND (p.gps_latitude IS NULL OR p.gps_longitude IS NULL)"),
        None => {}
    }

    let limit = resolve_limit(args);
    params.push(Box::new(limit));
    sql.push_str(&format!(
        " ORDER BY p.taken_at DESC, f.path ASC LIMIT ?{}",
        params.len()
    ));

    let refs: Vec<&dyn ToSql> = params.iter().map(|p| p.as_ref()).collect();
    run_summary_query(conn, &sql, &refs, limit)
}

fn exec_recent(conn: &Connection, args: &Value) -> Result<Value, String> {
    let limit = resolve_limit(args);
    let include_undated = args
        .get("include_undated")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let sql = format!(
        "SELECT {} FROM photos p JOIN files f ON p.file_id = f.id WHERE {} \
         ORDER BY p.taken_at DESC, f.path ASC LIMIT ?1",
        SUMMARY_COLUMNS,
        if include_undated { "1=1" } else { DATED },
    );

    run_summary_query(conn, &sql, &[&limit as &dyn ToSql], limit)
}

fn exec_get(conn: &Connection, args: &Value) -> Result<Value, String> {
    let id = args.get("id").and_then(|v| v.as_str());
    let path = args.get("path").and_then(|v| v.as_str());

    let (where_clause, key, key_kind) = match (id, path) {
        (Some(_), Some(_)) => return Err("provide exactly one of id or path, not both".to_string()),
        (Some(id), None) => ("p.id = ?1", id, "id"),
        (None, Some(path)) => ("f.path = ?1", path, "path"),
        (None, None) => return Err("one of id or path is required".to_string()),
    };

    let sql = format!(
        "SELECT p.id, f.path, p.taken_at, p.camera_make, p.camera_model, p.lens, \
         p.focal_length_mm, p.aperture, p.iso, p.exposure_time, p.width, p.height, \
         p.orientation, p.gps_latitude, p.gps_longitude, p.gps_altitude, p.tags_json, \
         p.blurhash, p.content_readable, p.manually_placed, p.thumbnail_256_generated, \
         p.thumbnail_1920_generated, p.original_sha256, p.current_sha256, p.created_at, \
         p.updated_at, f.size_bytes, f.content_type \
         FROM photos p JOIN files f ON p.file_id = f.id WHERE {}",
        where_clause
    );

    let row = conn.query_row(&sql, [key], |row| {
        let gps_latitude: Option<f64> = row.get(13)?;
        let gps_longitude: Option<f64> = row.get(14)?;
        let gps_altitude: Option<f64> = row.get(15)?;
        let taken_at: Option<String> = row.get(2)?;
        let undated = is_undated(taken_at.as_deref());
        let id: String = row.get(0)?;
        let tags_json: Option<String> = row.get(16)?;
        Ok((
            json!({
                "id": id,
                "path": row.get::<_, String>(1)?,
                "taken_at": if undated { None } else { taken_at },
                "undated": undated,
                "camera_make": row.get::<_, Option<String>>(3)?,
                "camera_model": row.get::<_, Option<String>>(4)?,
                "lens": row.get::<_, Option<String>>(5)?,
                "focal_length_mm": row.get::<_, Option<f64>>(6)?,
                "aperture": row.get::<_, Option<f64>>(7)?,
                "iso": row.get::<_, Option<i64>>(8)?,
                "exposure_time": row.get::<_, Option<String>>(9)?,
                "width": row.get::<_, Option<i64>>(10)?,
                "height": row.get::<_, Option<i64>>(11)?,
                "orientation": row.get::<_, Option<i64>>(12)?,
                "gps": match (gps_latitude, gps_longitude) {
                    (Some(lat), Some(lon)) => json!({
                        "latitude": lat,
                        "longitude": lon,
                        "altitude": gps_altitude,
                    }),
                    _ => Value::Null,
                },
                "blurhash": row.get::<_, Option<String>>(17)?,
                "content_readable": row.get::<_, i64>(18)? != 0,
                "manually_placed": row.get::<_, i64>(19)? != 0,
                "thumbnail_256_generated": row.get::<_, i64>(20)? != 0,
                "thumbnail_1920_generated": row.get::<_, i64>(21)? != 0,
                "original_sha256": row.get::<_, String>(22)?,
                "current_sha256": row.get::<_, String>(23)?,
                "created_at": row.get::<_, String>(24)?,
                "updated_at": row.get::<_, String>(25)?,
                "size_bytes": row.get::<_, i64>(26)?,
                "content_type": row.get::<_, String>(27)?,
            }),
            tags_json,
        ))
    });

    match row {
        Ok((mut photo, tags_json)) => {
            let photo_id = photo["id"].as_str().unwrap_or_default().to_string();
            photo["tags"] = json!(tags_for(conn, &photo_id, tags_json.as_deref()));
            Ok(photo)
        }
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            Err(format!("no photo found with {} {:?}", key_kind, key))
        }
        Err(e) => Err(e.to_string()),
    }
}

fn exec_stats(conn: &Connection, _args: &Value) -> Result<Value, String> {
    let scalar_i64 = |sql: &str| -> Result<i64, String> {
        conn.query_row(sql, [], |row| row.get::<_, Option<i64>>(0))
            .map(|v| v.unwrap_or(0))
            .map_err(|e| e.to_string())
    };

    let total = scalar_i64("SELECT COUNT(*) FROM photos p")?;
    let dated = scalar_i64(&format!("SELECT COUNT(*) FROM photos p WHERE {}", DATED))?;
    let undated = scalar_i64(&format!("SELECT COUNT(*) FROM photos p WHERE {}", UNDATED))?;
    let with_gps = scalar_i64(
        "SELECT COUNT(*) FROM photos p WHERE p.gps_latitude IS NOT NULL \
         AND p.gps_longitude IS NOT NULL",
    )?;
    let thumb_256 =
        scalar_i64("SELECT COUNT(*) FROM photos p WHERE p.thumbnail_256_generated = 1")?;
    let thumb_1920 =
        scalar_i64("SELECT COUNT(*) FROM photos p WHERE p.thumbnail_1920_generated = 1")?;
    let total_bytes = scalar_i64(
        "SELECT COALESCE(SUM(f.size_bytes), 0) FROM photos p JOIN files f ON p.file_id = f.id",
    )?;
    let distinct_models = scalar_i64(
        "SELECT COUNT(DISTINCT p.camera_model) FROM photos p WHERE p.camera_model IS NOT NULL",
    )?;

    // Date bounds over dated photos only, so the 1800-01-01 sentinel can never
    // be reported as the library's earliest capture.
    let (earliest, latest): (Option<String>, Option<String>) = conn
        .query_row(
            &format!(
                "SELECT MIN(p.taken_at), MAX(p.taken_at) FROM photos p WHERE {}",
                DATED
            ),
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map_err(|e| e.to_string())?;

    let mut stmt = conn
        .prepare(
            "SELECT p.camera_make, p.camera_model, COUNT(*) AS n FROM photos p \
             WHERE p.camera_make IS NOT NULL OR p.camera_model IS NOT NULL \
             GROUP BY p.camera_make, p.camera_model ORDER BY n DESC, p.camera_model ASC LIMIT 10",
        )
        .map_err(|e| e.to_string())?;
    let top_cameras: Vec<Value> = stmt
        .query_map([], |row| {
            Ok(json!({
                "camera_make": row.get::<_, Option<String>>(0)?,
                "camera_model": row.get::<_, Option<String>>(1)?,
                "count": row.get::<_, i64>(2)?,
            }))
        })
        .map_err(|e| e.to_string())?
        .filter_map(|r| r.ok())
        .collect();

    Ok(json!({
        "total": total,
        "dated": dated,
        "undated": undated,
        "earliest_taken_at": earliest,
        "latest_taken_at": latest,
        "with_gps": with_gps,
        "without_gps": total - with_gps,
        "thumbnail_256_generated": thumb_256,
        "thumbnail_1920_generated": thumb_1920,
        "total_bytes": total_bytes,
        "distinct_camera_models": distinct_models,
        "top_cameras": top_cameras,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const SENTINEL: &str = "1800-01-01T00:00:00+00:00";

    fn test_db() -> (TempDir, Connection) {
        let dir = TempDir::new().unwrap();
        let db_path = dir.path().join("t.db");
        let conn = tilde_core::db::init_db(db_path.to_str().unwrap()).unwrap();
        tilde_core::db::run_embedded_migrations(&conn).unwrap();
        (dir, conn)
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_photo(
        conn: &Connection,
        id: &str,
        path: &str,
        taken_at: Option<&str>,
        camera_make: Option<&str>,
        camera_model: Option<&str>,
        gps: Option<(f64, f64)>,
        tags_json: Option<&str>,
    ) {
        let file_id = format!("file-{}", id);
        let name = path.rsplit('/').next().unwrap_or(path);
        let parent = path.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
        conn.execute(
            "INSERT INTO files (id, path, parent_path, name, size_bytes, content_type, etag, \
             sha256, is_directory, created_at, modified_at, hlc) \
             VALUES (?1, ?2, ?3, ?4, 1024, 'image/jpeg', 'etag', 'sha', 0, \
             '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'hlc')",
            rusqlite::params![file_id, path, parent, name],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO photos (id, file_id, original_sha256, current_sha256, width, height, \
             taken_at, camera_make, camera_model, lens, focal_length_mm, aperture, iso, \
             exposure_time, gps_latitude, gps_longitude, gps_altitude, orientation, \
             content_readable, manually_placed, blurhash, thumbnail_256_generated, \
             thumbnail_1920_generated, tags_json, created_at, updated_at, hlc) \
             VALUES (?1, ?2, 'osha', 'csha', 4000, 3000, ?3, ?4, ?5, '35mm f/1.4', 35.0, 1.4, \
             200, '1/250', ?6, ?7, 12.5, 1, 1, 0, 'blur', 1, 0, ?8, \
             '2024-01-01T00:00:00Z', '2024-01-01T00:00:00Z', 'hlc')",
            rusqlite::params![
                id,
                file_id,
                taken_at,
                camera_make,
                camera_model,
                gps.map(|g| g.0),
                gps.map(|g| g.1),
                tags_json,
            ],
        )
        .unwrap();
    }

    /// A small library: two dated Fuji photos, one dated Canon, one undated.
    fn seeded() -> (TempDir, Connection) {
        let (dir, conn) = test_db();
        insert_photo(
            &conn,
            "p1",
            "/photos/2024/01/a.jpg",
            Some("2024-01-15T10:00:00+00:00"),
            Some("FUJIFILM"),
            Some("X-T4"),
            Some((51.5, -0.1)),
            Some(r#"["london","street"]"#),
        );
        insert_photo(
            &conn,
            "p2",
            "/photos/2024/06/b.jpg",
            Some("2024-06-20T18:30:00+00:00"),
            Some("FUJIFILM"),
            Some("X100V"),
            None,
            None,
        );
        insert_photo(
            &conn,
            "p3",
            "/photos/2023/03/c.jpg",
            Some("2023-03-01T08:00:00+00:00"),
            Some("Canon"),
            Some("EOS R6"),
            None,
            None,
        );
        insert_photo(
            &conn,
            "p4",
            "/photos/_inbox/scan.jpg",
            Some(SENTINEL),
            None,
            None,
            None,
            None,
        );
        (dir, conn)
    }

    fn ids(result: &Value) -> Vec<String> {
        result["photos"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap().to_string())
            .collect()
    }

    #[test]
    fn scopes_are_photos_read() {
        for def in defs() {
            assert_eq!(
                required_scope(&def.name),
                Some("photos:read"),
                "{} must require photos:read",
                def.name
            );
        }
        assert_eq!(required_scope("photos.delete"), None);
    }

    #[test]
    fn exec_returns_none_for_foreign_tools() {
        let (_dir, conn) = test_db();
        assert!(exec("notes.search", &conn, &json!({})).is_none());
    }

    #[test]
    fn search_by_camera_make_and_model() {
        let (_dir, conn) = seeded();

        let res = exec("photos.search", &conn, &json!({"camera_make": "fuji"}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1"]); // newest first
        assert_eq!(res["count"], 2);

        let res = exec("photos.search", &conn, &json!({"camera_model": "x100"}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p2"]);

        let res = exec("photos.search", &conn, &json!({"camera_make": "nikon"}))
            .unwrap()
            .unwrap();
        assert_eq!(res["count"], 0);
    }

    #[test]
    fn search_by_date_range() {
        let (_dir, conn) = seeded();

        let res = exec(
            "photos.search",
            &conn,
            &json!({"from": "2024-01-01", "to": "2024-12-31"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1"]);

        // Bare dates are inclusive of the whole day on both ends.
        let res = exec(
            "photos.search",
            &conn,
            &json!({"from": "2024-01-15", "to": "2024-01-15"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ids(&res), vec!["p1"]);

        // Full datetimes work too.
        let res = exec(
            "photos.search",
            &conn,
            &json!({"from": "2024-01-15T12:00:00+00:00"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ids(&res), vec!["p2"]);

        let err = exec("photos.search", &conn, &json!({"from": "last tuesday"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("ISO 8601"), "{}", err);
    }

    #[test]
    fn sentinel_is_excluded_from_date_queries_and_recent() {
        let (_dir, conn) = seeded();

        // Undated photos never appear by default.
        let res = exec("photos.recent", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1", "p3"]);

        // A date range that literally spans 1800 still must not surface it.
        let res = exec(
            "photos.search",
            &conn,
            &json!({"from": "1700-01-01", "to": "2030-01-01", "include_undated": true}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1", "p3"]);

        // Opt in without a date filter: sentinel sorts last, reported as undated.
        let res = exec("photos.recent", &conn, &json!({"include_undated": true}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1", "p3", "p4"]);
        let last = &res["photos"].as_array().unwrap()[3];
        assert_eq!(last["taken_at"], Value::Null);
        assert_eq!(last["undated"], true);
        assert_eq!(res["photos"][0]["undated"], false);

        // Stats report the sentinel separately and never as the earliest date.
        let stats = exec("photos.stats", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(stats["total"], 4);
        assert_eq!(stats["dated"], 3);
        assert_eq!(stats["undated"], 1);
        assert_eq!(stats["earliest_taken_at"], "2023-03-01T08:00:00+00:00");
        assert_eq!(stats["latest_taken_at"], "2024-06-20T18:30:00+00:00");
        assert_eq!(stats["with_gps"], 1);
        assert_eq!(stats["without_gps"], 3);
        assert_eq!(stats["total_bytes"], 4096);
    }

    #[test]
    fn null_taken_at_counts_as_undated() {
        let (_dir, conn) = test_db();
        insert_photo(&conn, "n1", "/photos/n.jpg", None, None, None, None, None);

        let res = exec("photos.recent", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(res["count"], 0);

        let res = exec("photos.recent", &conn, &json!({"include_undated": true}))
            .unwrap()
            .unwrap();
        assert_eq!(res["count"], 1);
        assert_eq!(res["photos"][0]["undated"], true);
    }

    #[test]
    fn recent_respects_limit_and_ordering() {
        let (_dir, conn) = seeded();

        let res = exec("photos.recent", &conn, &json!({"limit": 2}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p1"]);
        assert_eq!(res["limit"], 2);
        assert_eq!(res["truncated"], true);

        let res = exec("photos.recent", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(res["limit"], DEFAULT_LIMIT);
        assert_eq!(res["truncated"], false);

        // Out-of-range limits are clamped, not rejected.
        let res = exec("photos.recent", &conn, &json!({"limit": 100000}))
            .unwrap()
            .unwrap();
        assert_eq!(res["limit"], MAX_LIMIT);
        let res = exec("photos.recent", &conn, &json!({"limit": 0}))
            .unwrap()
            .unwrap();
        assert_eq!(res["limit"], 1);
        assert_eq!(res["count"], 1);
    }

    #[test]
    fn search_by_gps_and_tags() {
        let (_dir, conn) = seeded();
        conn.execute(
            "INSERT INTO photo_tags (photo_id, tag, prefix) VALUES ('p3', 'portrait', NULL)",
            [],
        )
        .unwrap();

        let res = exec("photos.search", &conn, &json!({"has_gps": true}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p1"]);
        assert_eq!(res["photos"][0]["has_gps"], true);

        let res = exec("photos.search", &conn, &json!({"has_gps": false}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p2", "p3"]);

        // tags_json blob
        let res = exec("photos.search", &conn, &json!({"tag": "london"}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p1"]);
        assert_eq!(res["photos"][0]["tags"], json!(["london", "street"]));

        // photo_tags table
        let res = exec("photos.search", &conn, &json!({"tag": "portrait"}))
            .unwrap()
            .unwrap();
        assert_eq!(ids(&res), vec!["p3"]);
    }

    #[test]
    fn get_returns_full_metadata_by_path_and_id() {
        let (_dir, conn) = seeded();

        let by_path = exec(
            "photos.get",
            &conn,
            &json!({"path": "/photos/2024/01/a.jpg"}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(by_path["id"], "p1");
        assert_eq!(by_path["taken_at"], "2024-01-15T10:00:00+00:00");
        assert_eq!(by_path["undated"], false);
        assert_eq!(by_path["camera_make"], "FUJIFILM");
        assert_eq!(by_path["camera_model"], "X-T4");
        assert_eq!(by_path["lens"], "35mm f/1.4");
        assert_eq!(by_path["iso"], 200);
        assert_eq!(by_path["aperture"], 1.4);
        assert_eq!(by_path["exposure_time"], "1/250");
        assert_eq!(by_path["width"], 4000);
        assert_eq!(by_path["height"], 3000);
        assert_eq!(by_path["gps"]["latitude"], 51.5);
        assert_eq!(by_path["gps"]["longitude"], -0.1);
        assert_eq!(by_path["gps"]["altitude"], 12.5);
        assert_eq!(by_path["tags"], json!(["london", "street"]));
        assert_eq!(by_path["size_bytes"], 1024);
        assert_eq!(by_path["content_type"], "image/jpeg");
        assert_eq!(by_path["thumbnail_256_generated"], true);
        assert_eq!(by_path["thumbnail_1920_generated"], false);
        assert_eq!(by_path["content_readable"], true);

        let by_id = exec("photos.get", &conn, &json!({"id": "p1"}))
            .unwrap()
            .unwrap();
        assert_eq!(by_id, by_path);

        // No GPS -> null, not a partial object.
        let b = exec("photos.get", &conn, &json!({"id": "p2"}))
            .unwrap()
            .unwrap();
        assert_eq!(b["gps"], Value::Null);

        // Sentinel is normalised away here too.
        let scan = exec("photos.get", &conn, &json!({"id": "p4"}))
            .unwrap()
            .unwrap();
        assert_eq!(scan["taken_at"], Value::Null);
        assert_eq!(scan["undated"], true);
    }

    #[test]
    fn get_errors_cleanly_on_bad_input() {
        let (_dir, conn) = seeded();

        let err = exec("photos.get", &conn, &json!({"path": "/photos/nope.jpg"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("no photo found"), "{}", err);
        assert!(err.contains("/photos/nope.jpg"), "{}", err);

        let err = exec("photos.get", &conn, &json!({"id": "does-not-exist"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("no photo found"), "{}", err);

        let err = exec("photos.get", &conn, &json!({})).unwrap().unwrap_err();
        assert!(err.contains("one of id or path is required"), "{}", err);

        let err = exec("photos.get", &conn, &json!({"id": "p1", "path": "/x"}))
            .unwrap()
            .unwrap_err();
        assert!(err.contains("exactly one"), "{}", err);
    }

    #[test]
    fn stats_on_empty_library() {
        let (_dir, conn) = test_db();
        let stats = exec("photos.stats", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(stats["total"], 0);
        assert_eq!(stats["earliest_taken_at"], Value::Null);
        assert_eq!(stats["latest_taken_at"], Value::Null);
        assert_eq!(stats["total_bytes"], 0);
        assert_eq!(stats["top_cameras"], json!([]));
    }

    #[test]
    fn stats_lists_top_cameras() {
        let (_dir, conn) = seeded();
        let stats = exec("photos.stats", &conn, &json!({})).unwrap().unwrap();
        assert_eq!(stats["distinct_camera_models"], 3);
        let cameras = stats["top_cameras"].as_array().unwrap();
        assert_eq!(cameras.len(), 3);
        assert!(
            cameras
                .iter()
                .any(|c| c["camera_model"] == "X-T4" && c["count"] == 1)
        );
    }

    #[test]
    fn every_def_has_a_schema_and_useful_description() {
        for def in defs() {
            assert_eq!(def.input_schema["type"], "object", "{}", def.name);
            assert!(
                def.description.len() > 200,
                "{} description is too thin to state behaviour",
                def.name
            );
        }
        let names: Vec<String> = defs().into_iter().map(|d| d.name).collect();
        assert_eq!(
            names,
            vec![
                "photos.search",
                "photos.recent",
                "photos.get",
                "photos.stats"
            ]
        );
    }
}
