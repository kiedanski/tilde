//! Extraction of health data from Gadgetbridge database exports into plaintext.
//!
//! A Gadgetbridge auto-export (`Gadgetbridge.db`, a sqlite database) dropped into
//! `files/health/_inbox/` is read read-only and regenerated into monthly CSV files
//! under `files/health/`. The database carries complete history, so every run
//! rewrites the affected months from scratch — the export is idempotent and the
//! source database is never modified.
//!
//! Table semantics (raw kinds, sleep-session blob layout, validity sentinels) are
//! ported from Gadgetbridge's `HuamiExtendedSampleProvider` and
//! `HuamiSleepSessionSampleProvider` — see the constants below. Amazfit/Huami
//! devices only; tables absent from an export are skipped silently so exports
//! from other device families do not fail the run.

pub mod watcher;

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use rusqlite::{Connection, OpenFlags};
use tracing::{debug, info, warn};

// HuamiExtendedSampleProvider constants (Gadgetbridge).
const KIND_OUTDOOR_RUNNING: i64 = 64;
const KIND_NOT_WORN: i64 = 115;
const KIND_CHARGING: i64 = 118;
const KIND_SLEEP: i64 = 120;
// Heart rate 255 means "no reading" in Huami minute samples.
const HR_INVALID: i64 = 255;

// Fallback sleep-stage thresholds from HuamiExtendedSampleProvider.postProcess,
// used only for minutes inside RAW_KIND==120 when no parsed session covers them.
const FALLBACK_REM_THRESHOLD: i64 = 55;
const FALLBACK_DEEP_THRESHOLD: i64 = 42;

#[derive(Debug, Default)]
pub struct ExportStats {
    pub activity_rows: usize,
    pub stress_rows: usize,
    pub respiratory_rows: usize,
    pub sleep_sessions: usize,
    pub days: usize,
    pub files_written: usize,
}

/// One parsed sleep session (night) from a `HUAMI_SLEEP_SESSION_SAMPLE` blob.
///
/// Blob layout per HuamiSleepSessionSampleProvider.SleepSession — all values
/// little-endian: 0x00 session ts (u32), 0x04 local-midnight ts (u32),
/// 0x0a/0x0c sleep start/end (u16, minutes since midnight-24h), 0x16 score (u8),
/// 0x54 stage count (u8), stages from 0x56 (5 bytes each: start u16, end u16,
/// type u8 — 4=light 5=deep 8=REM 7=awake), stage totals in minutes at
/// 0x24a REM / 0x24c light / 0x24e deep / 0x250 awake.
#[derive(Debug, Clone)]
pub struct SleepSession {
    pub midnight: i64,
    pub start: i64,
    pub end: i64,
    pub score: u8,
    pub light_min: u16,
    pub deep_min: u16,
    pub rem_min: u16,
    pub awake_min: u16,
    /// (start_ts, end_ts, stage) with unix-second bounds.
    pub stages: Vec<(i64, i64, SleepStage)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SleepStage {
    Light,
    Deep,
    Rem,
    Awake,
    Unknown,
}

impl SleepStage {
    fn label(self) -> &'static str {
        match self {
            SleepStage::Light => "light",
            SleepStage::Deep => "deep",
            SleepStage::Rem => "rem",
            SleepStage::Awake => "awake",
            SleepStage::Unknown => "unknown",
        }
    }
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes([*b.get(o)?, *b.get(o + 1)?]))
}

fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes([
        *b.get(o)?,
        *b.get(o + 1)?,
        *b.get(o + 2)?,
        *b.get(o + 3)?,
    ]))
}

/// Parse one sleep-session blob. Returns None for sessions the device reported
/// without stage data (numStages == 0), matching Gadgetbridge's own skip.
pub fn parse_sleep_session(data: &[u8]) -> Option<SleepSession> {
    let midnight = u32_at(data, 0x04)? as i64;
    let start_min = u16_at(data, 0x0a)? as i64;
    let end_min = u16_at(data, 0x0c)? as i64;
    let score = *data.get(0x16)?;
    let num_stages = *data.get(0x54)? as usize;
    if num_stages == 0 {
        return None;
    }

    // Stage minute offsets are relative to midnight minus 24h.
    let base = midnight - 24 * 3600;
    let mut stages = Vec::with_capacity(num_stages);
    for i in 0..num_stages {
        let o = 0x56 + 5 * i;
        let s = u16_at(data, o)? as i64;
        let e = u16_at(data, o + 2)? as i64;
        let stage = match *data.get(o + 4)? {
            4 => SleepStage::Light,
            5 => SleepStage::Deep,
            8 => SleepStage::Rem,
            7 => SleepStage::Awake,
            _ => SleepStage::Unknown,
        };
        stages.push((base + s * 60, base + e * 60, stage));
    }

    Some(SleepSession {
        midnight,
        start: base + start_min * 60,
        end: base + end_min * 60,
        score,
        rem_min: u16_at(data, 0x24a)?,
        light_min: u16_at(data, 0x24c)?,
        deep_min: u16_at(data, 0x24e)?,
        awake_min: u16_at(data, 0x250)?,
        stages,
    })
}

fn table_exists(conn: &Connection, name: &str) -> bool {
    conn.query_row(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1",
        [name],
        |_| Ok(()),
    )
    .is_ok()
}

/// Per-day aggregate accumulator for `daily/YYYYMM.csv`.
#[derive(Default)]
struct DayAgg {
    steps: i64,
    hr_sum: i64,
    hr_count: i64,
    hr_min: Option<i64>,
    hr_max: Option<i64>,
    hr_resting: Option<i64>,
    stress_sum: i64,
    stress_count: i64,
    stress_max: Option<i64>,
    sleep: Option<(u16, u16, u16, u16, u8)>, // light, deep, rem, awake, score
    pai_total: Option<f64>,
    spo2_min: Option<i64>,
}

struct MonthlyCsv {
    header: &'static str,
    months: BTreeMap<String, String>,
}

impl MonthlyCsv {
    fn new(header: &'static str) -> Self {
        Self {
            header,
            months: BTreeMap::new(),
        }
    }

    fn push(&mut self, month: String, line: &str) {
        let buf = self
            .months
            .entry(month)
            .or_insert_with(|| format!("{}\n", self.header));
        buf.push_str(line);
        buf.push('\n');
    }

    /// Write one file per month under `dir`, atomically (tmp + rename), only
    /// touching files whose content actually changed so mtimes stay meaningful.
    fn write(&self, dir: &Path, written: &mut usize) -> Result<()> {
        if self.months.is_empty() {
            return Ok(());
        }
        std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        for (month, content) in &self.months {
            let path = dir.join(format!("{month}.csv"));
            if std::fs::read_to_string(&path)
                .map(|c| c == *content)
                .unwrap_or(false)
            {
                continue;
            }
            let tmp = dir.join(format!(".{month}.csv.tmp"));
            std::fs::write(&tmp, content).with_context(|| format!("writing {}", tmp.display()))?;
            std::fs::rename(&tmp, &path)
                .with_context(|| format!("renaming into {}", path.display()))?;
            *written += 1;
        }
        Ok(())
    }
}

fn local(ts: i64, tz: &TimeZone) -> Option<jiff::Zoned> {
    Timestamp::from_second(ts)
        .ok()
        .map(|t| t.to_zoned(tz.clone()))
}

/// Gadgetbridge stores minute samples in unix seconds but the newer
/// `TimeSample`-family tables (stress, SpO2, PAI, resting HR, respiratory
/// rate) in unix milliseconds. Normalize on magnitude.
fn to_seconds(ts: i64) -> i64 {
    if ts > 20_000_000_000 { ts / 1000 } else { ts }
}

fn month_key(z: &jiff::Zoned) -> String {
    z.strftime("%Y%m").to_string()
}

fn day_key(z: &jiff::Zoned) -> String {
    z.strftime("%Y-%m-%d").to_string()
}

fn rfc3339(z: &jiff::Zoned) -> String {
    z.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()
}

/// Regenerate the plaintext health tree from a Gadgetbridge database export.
///
/// `gb_db` is opened read-only and never modified. Monthly CSVs are written under
/// `health_dir` (`activity/`, `heart_rate/`, `steps/`, `stress/`,
/// `respiratory_rate/`, `sleep/`, `daily/`), bucketing timestamps by `tz`.
pub fn export_gadgetbridge(gb_db: &Path, health_dir: &Path, tz: &TimeZone) -> Result<ExportStats> {
    let conn = Connection::open_with_flags(
        gb_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {} read-only", gb_db.display()))?;

    let mut stats = ExportStats::default();
    let mut days: BTreeMap<String, DayAgg> = BTreeMap::new();

    // ── Sleep sessions ───────────────────────────────────────────────────────
    // Parsed first: the per-minute export labels sleep minutes with the stage
    // the session overlay reports, exactly like Gadgetbridge's postProcess.
    let mut sessions: BTreeMap<i64, SleepSession> = BTreeMap::new(); // by midnight, last write wins
    if table_exists(&conn, "HUAMI_SLEEP_SESSION_SAMPLE") {
        let mut stmt =
            conn.prepare("SELECT DATA FROM HUAMI_SLEEP_SESSION_SAMPLE ORDER BY TIMESTAMP")?;
        let rows = stmt.query_map([], |row| row.get::<_, Option<Vec<u8>>>(0))?;
        for blob in rows.flatten().flatten() {
            if let Some(session) = parse_sleep_session(&blob) {
                sessions.insert(session.midnight, session);
            }
        }
    }

    let mut sleep_csv = MonthlyCsv::new(
        "night_of,sleep_start,sleep_end,light_min,deep_min,rem_min,awake_min,score",
    );
    for session in sessions.values() {
        let (Some(night), Some(start), Some(end)) = (
            local(session.midnight, tz),
            local(session.start, tz),
            local(session.end, tz),
        ) else {
            continue;
        };
        stats.sleep_sessions += 1;
        sleep_csv.push(
            month_key(&night),
            &format!(
                "{},{},{},{},{},{},{},{}",
                day_key(&night),
                rfc3339(&start),
                rfc3339(&end),
                session.light_min,
                session.deep_min,
                session.rem_min,
                session.awake_min,
                session.score
            ),
        );
        days.entry(day_key(&night)).or_default().sleep = Some((
            session.light_min,
            session.deep_min,
            session.rem_min,
            session.awake_min,
            session.score,
        ));
    }

    // Flattened stage ranges for the per-minute overlay.
    let stage_ranges: Vec<(i64, i64, SleepStage)> = sessions
        .values()
        .flat_map(|s| s.stages.iter().copied())
        .collect();
    let stage_at = |ts: i64| -> Option<SleepStage> {
        stage_ranges
            .iter()
            .find(|(s, e, _)| ts >= *s && ts < *e)
            .map(|(_, _, stage)| *stage)
    };

    // ── Minute-level activity ────────────────────────────────────────────────
    let mut activity_csv = MonthlyCsv::new("time,raw_kind,kind,intensity,steps,heart_rate");
    let mut hr_csv = MonthlyCsv::new("time,bpm");
    let mut steps_csv = MonthlyCsv::new("time,steps");
    if table_exists(&conn, "HUAMI_EXTENDED_ACTIVITY_SAMPLE") {
        let mut stmt = conn.prepare(
            "SELECT TIMESTAMP, RAW_KIND, RAW_INTENSITY, STEPS, HEART_RATE,
                    COALESCE(DEEP_SLEEP, 0), COALESCE(REM_SLEEP, 0)
             FROM HUAMI_EXTENDED_ACTIVITY_SAMPLE ORDER BY TIMESTAMP",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
                row.get::<_, i64>(3)?,
                row.get::<_, i64>(4)?,
                row.get::<_, i64>(5)?,
                row.get::<_, i64>(6)?,
            ))
        })?;
        for row in rows {
            let (ts, raw_kind, intensity, steps, hr, deep_raw, rem_raw) = row?;
            let Some(z) = local(ts, tz) else { continue };
            stats.activity_rows += 1;
            let month = month_key(&z);
            let day = day_key(&z);
            let time = rfc3339(&z);

            let kind = match raw_kind {
                KIND_OUTDOOR_RUNNING => "running",
                KIND_NOT_WORN => "not_worn",
                KIND_CHARGING => "charging",
                KIND_SLEEP => match stage_at(ts) {
                    Some(stage) => stage.label(),
                    // Fallback thresholds from Gadgetbridge (documented as
                    // approximate there too) for minutes no session covers.
                    None if (rem_raw & 127) > FALLBACK_REM_THRESHOLD => "rem",
                    None if (deep_raw & 127) > FALLBACK_DEEP_THRESHOLD => "deep",
                    None => "light",
                },
                _ => "",
            };

            activity_csv.push(
                month.clone(),
                &format!("{time},{raw_kind},{kind},{intensity},{steps},{hr}"),
            );

            let agg = days.entry(day).or_default();
            if steps > 0 {
                steps_csv.push(month.clone(), &format!("{time},{steps}"));
                agg.steps += steps;
            }
            if hr > 0 && hr < HR_INVALID && raw_kind != KIND_NOT_WORN && raw_kind != KIND_CHARGING {
                hr_csv.push(month, &format!("{time},{hr}"));
                agg.hr_sum += hr;
                agg.hr_count += 1;
                agg.hr_min = Some(agg.hr_min.map_or(hr, |m| m.min(hr)));
                agg.hr_max = Some(agg.hr_max.map_or(hr, |m| m.max(hr)));
            }
        }
    }

    // ── Stress ───────────────────────────────────────────────────────────────
    let mut stress_csv = MonthlyCsv::new("time,stress");
    if table_exists(&conn, "HUAMI_STRESS_SAMPLE") {
        let mut stmt =
            conn.prepare("SELECT TIMESTAMP, STRESS FROM HUAMI_STRESS_SAMPLE ORDER BY TIMESTAMP")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (ts, stress) = row?;
            let ts = to_seconds(ts);
            let Some(z) = local(ts, tz) else { continue };
            if stress <= 0 {
                continue;
            }
            stats.stress_rows += 1;
            stress_csv.push(month_key(&z), &format!("{},{stress}", rfc3339(&z)));
            let agg = days.entry(day_key(&z)).or_default();
            agg.stress_sum += stress;
            agg.stress_count += 1;
            agg.stress_max = Some(agg.stress_max.map_or(stress, |m| m.max(stress)));
        }
    }

    // ── Sleep respiratory rate ───────────────────────────────────────────────
    let mut resp_csv = MonthlyCsv::new("time,rate");
    if table_exists(&conn, "HUAMI_SLEEP_RESPIRATORY_RATE_SAMPLE") {
        let mut stmt = conn.prepare(
            "SELECT TIMESTAMP, RATE FROM HUAMI_SLEEP_RESPIRATORY_RATE_SAMPLE ORDER BY TIMESTAMP",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (ts, rate) = row?;
            let ts = to_seconds(ts);
            let Some(z) = local(ts, tz) else { continue };
            if rate <= 0 {
                continue;
            }
            stats.respiratory_rows += 1;
            resp_csv.push(month_key(&z), &format!("{},{rate}", rfc3339(&z)));
        }
    }

    // ── Daily-only sources: resting HR, PAI, SpO2 ────────────────────────────
    if table_exists(&conn, "HUAMI_HEART_RATE_RESTING_SAMPLE") {
        let mut stmt = conn.prepare(
            "SELECT TIMESTAMP, HEART_RATE FROM HUAMI_HEART_RATE_RESTING_SAMPLE ORDER BY TIMESTAMP",
        )?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (ts, hr) = row?;
            let ts = to_seconds(ts);
            if hr <= 0 || hr >= HR_INVALID {
                continue;
            }
            if let Some(z) = local(ts, tz) {
                days.entry(day_key(&z)).or_default().hr_resting = Some(hr);
            }
        }
    }
    if table_exists(&conn, "HUAMI_PAI_SAMPLE") {
        let mut stmt =
            conn.prepare("SELECT TIMESTAMP, PAI_TOTAL FROM HUAMI_PAI_SAMPLE ORDER BY TIMESTAMP")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, f64>(1)?)))?;
        for row in rows {
            let (ts, pai) = row?;
            let ts = to_seconds(ts);
            if let Some(z) = local(ts, tz) {
                days.entry(day_key(&z)).or_default().pai_total = Some(pai);
            }
        }
    }
    if table_exists(&conn, "HUAMI_SPO2_SAMPLE") {
        let mut stmt =
            conn.prepare("SELECT TIMESTAMP, SPO2 FROM HUAMI_SPO2_SAMPLE ORDER BY TIMESTAMP")?;
        let rows = stmt.query_map([], |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)))?;
        for row in rows {
            let (ts, spo2) = row?;
            let ts = to_seconds(ts);
            if spo2 <= 0 {
                continue;
            }
            if let Some(z) = local(ts, tz) {
                let agg = days.entry(day_key(&z)).or_default();
                agg.spo2_min = Some(agg.spo2_min.map_or(spo2, |m| m.min(spo2)));
            }
        }
    }

    // ── Daily summary ────────────────────────────────────────────────────────
    let mut daily_csv = MonthlyCsv::new(
        "date,steps,hr_min,hr_avg,hr_max,hr_resting,stress_avg,stress_max,\
         sleep_light_min,sleep_deep_min,sleep_rem_min,sleep_awake_min,sleep_score,pai_total,spo2_min",
    );
    let opt = |v: Option<i64>| v.map(|v| v.to_string()).unwrap_or_default();
    for (date, agg) in &days {
        stats.days += 1;
        let month = date[..7].replace('-', "");
        let hr_avg = if agg.hr_count > 0 {
            (agg.hr_sum as f64 / agg.hr_count as f64)
                .round()
                .to_string()
        } else {
            String::new()
        };
        let stress_avg = if agg.stress_count > 0 {
            (agg.stress_sum as f64 / agg.stress_count as f64)
                .round()
                .to_string()
        } else {
            String::new()
        };
        let (light, deep, rem, awake, score) = agg
            .sleep
            .map(|(l, d, r, a, s)| {
                (
                    l.to_string(),
                    d.to_string(),
                    r.to_string(),
                    a.to_string(),
                    s.to_string(),
                )
            })
            .unwrap_or_default();
        daily_csv.push(
            month,
            &format!(
                "{date},{},{},{hr_avg},{},{},{stress_avg},{},{light},{deep},{rem},{awake},{score},{},{}",
                agg.steps,
                opt(agg.hr_min),
                opt(agg.hr_max),
                opt(agg.hr_resting),
                opt(agg.stress_max),
                agg.pai_total.map(|p| format!("{p:.1}")).unwrap_or_default(),
                opt(agg.spo2_min),
            ),
        );
    }

    for (csv, sub) in [
        (&activity_csv, "activity"),
        (&hr_csv, "heart_rate"),
        (&steps_csv, "steps"),
        (&stress_csv, "stress"),
        (&resp_csv, "respiratory_rate"),
        (&sleep_csv, "sleep"),
        (&daily_csv, "daily"),
    ] {
        csv.write(&health_dir.join(sub), &mut stats.files_written)?;
    }

    info!(
        activity = stats.activity_rows,
        sleep_sessions = stats.sleep_sessions,
        days = stats.days,
        files = stats.files_written,
        "Gadgetbridge export complete"
    );
    Ok(stats)
}

/// Body-weight readings produced by the weightlog BLE daemon.
#[derive(Debug, Default)]
pub struct WeightStats {
    pub rows: usize,
    pub files_written: usize,
}

/// Regenerate `health/weight/` from a weightlog database export.
///
/// `weightlog_db` is opened read-only and never modified. The instant bucketed
/// here is `ts` — when the reading was taken on the watch, already clock-
/// corrected by the daemon — never `received_at`, which is merely when the row
/// reached the Pi over BLE and can trail the weigh-in by hours.
pub fn export_weightlog(
    weightlog_db: &Path,
    health_dir: &Path,
    tz: &TimeZone,
) -> Result<WeightStats> {
    let conn = Connection::open_with_flags(
        weightlog_db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {} read-only", weightlog_db.display()))?;

    let mut stats = WeightStats::default();
    let mut weight_csv = MonthlyCsv::new("time,kg,device");

    let mut stmt = conn.prepare("SELECT ts, kg, device_id FROM body_weights ORDER BY ts")?;
    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, f64>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    for (ts, kg, device) in rows.flatten() {
        let Some(z) = local(to_seconds(ts), tz) else {
            continue;
        };
        weight_csv.push(
            month_key(&z),
            &format!("{},{:.1},{}", rfc3339(&z), kg, device),
        );
        stats.rows += 1;
    }

    weight_csv.write(&health_dir.join("weight"), &mut stats.files_written)?;

    info!(
        rows = stats.rows,
        files = stats.files_written,
        "weightlog weight export complete"
    );
    Ok(stats)
}

/// Gadgetbridge and weightlog both drop a plain `.db` into the inbox, so the
/// exporter is picked by schema rather than by filename.
fn is_weightlog_db(path: &Path) -> bool {
    Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map(|conn| table_exists(&conn, "body_weights"))
    .unwrap_or(false)
}

#[derive(Debug, Default)]
pub struct InboxStats {
    pub export: Option<ExportStats>,
    pub weight: Option<WeightStats>,
    pub workouts_copied: usize,
}

/// Process everything currently in `health/_inbox/`: sqlite databases are
/// exported, workout files (`.fit`/`.gpx`) are copied into `health/workouts/`.
///
/// Inbox files are left in place — the phone's sync client owns that directory,
/// and removing files from under it invites re-upload loops or, worse,
/// mirrored deletion on the phone. Idempotency comes from content instead:
/// workout copies are skipped when the destination exists with the same size,
/// and the CSV regeneration only rewrites months whose content changed.
pub fn process_inbox(inbox: &Path, health_dir: &Path, tz: &TimeZone) -> Result<InboxStats> {
    let mut stats = InboxStats::default();
    let Ok(entries) = std::fs::read_dir(inbox) else {
        return Ok(stats);
    };

    let workouts_dir = health_dir.join("workouts");
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        let ext = path
            .extension()
            .map(|e| e.to_string_lossy().to_lowercase())
            .unwrap_or_default();

        match ext.as_str() {
            "db" | "sqlite" => {
                if is_weightlog_db(&path) {
                    match export_weightlog(&path, health_dir, tz) {
                        Ok(weight) => stats.weight = Some(weight),
                        Err(e) => warn!(file = %name, error = %e, "weightlog export failed"),
                    }
                } else {
                    match export_gadgetbridge(&path, health_dir, tz) {
                        Ok(export) => stats.export = Some(export),
                        Err(e) => warn!(file = %name, error = %e, "Gadgetbridge export failed"),
                    }
                }
            }
            "fit" | "gpx" => {
                let dest = workouts_dir.join(&name);
                let src_len = entry.metadata().map(|m| m.len()).unwrap_or(0);
                let same = dest.metadata().map(|m| m.len() == src_len).unwrap_or(false);
                if same {
                    continue;
                }
                std::fs::create_dir_all(&workouts_dir)?;
                let tmp = workouts_dir.join(format!(".{name}.tmp"));
                std::fs::copy(&path, &tmp)
                    .with_context(|| format!("copying {name} into workouts"))?;
                std::fs::rename(&tmp, &dest)?;
                stats.workouts_copied += 1;
            }
            _ => debug!(file = %name, "ignoring unrecognized inbox file"),
        }
    }

    Ok(stats)
}

#[derive(Debug, Default)]
pub struct NotesStats {
    pub files_written: usize,
}

#[derive(Default, Clone)]
struct NoteRow {
    weight: Option<f64>,
    steps: Option<String>,
    hr_resting: Option<String>,
    sleep_min: Option<i64>,
    sleep_score: Option<String>,
}

/// Read every `YYYYMM.csv` in `dir` as month -> data rows, header dropped.
fn monthly_csv_rows(dir: &Path) -> BTreeMap<String, Vec<Vec<String>>> {
    let mut out: BTreeMap<String, Vec<Vec<String>>> = BTreeMap::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().map(|e| e != "csv").unwrap_or(true) {
            continue;
        }
        let Some(month) = path.file_stem().map(|s| s.to_string_lossy().to_string()) else {
            continue;
        };
        if month.starts_with('.') {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.insert(
            month,
            text.lines()
                .skip(1)
                .filter(|line| !line.trim().is_empty())
                .map(|line| line.split(',').map(str::to_string).collect())
                .collect(),
        );
    }
    out
}

fn field(row: &[String], i: usize) -> Option<String> {
    row.get(i).filter(|s| !s.is_empty()).cloned()
}

fn hours_minutes(mins: i64) -> String {
    format!("{}h{:02}m", mins / 60, mins % 60)
}

/// Render the health tree as one Obsidian-friendly Markdown table per month.
///
/// Reads the CSVs this module already wrote rather than the source databases,
/// so it does not matter which artifact triggered the run — a weightlog-only
/// upload still renders the Gadgetbridge columns from the existing tree.
/// Nothing time-varying is written into the output, so an unchanged month keeps
/// its mtime instead of churning through DAV sync on every import.
pub fn export_notes(health_dir: &Path, notes_dir: &Path) -> Result<NotesStats> {
    let mut months: BTreeMap<String, BTreeMap<String, NoteRow>> = BTreeMap::new();

    // daily/: date,steps,hr_min,hr_avg,hr_max,hr_resting,stress_avg,stress_max,
    //         sleep_light_min,sleep_deep_min,sleep_rem_min,sleep_awake_min,sleep_score,…
    for (month, rows) in monthly_csv_rows(&health_dir.join("daily")) {
        let days = months.entry(month).or_default();
        for row in rows {
            let Some(date) = field(&row, 0) else { continue };
            let stage = |i: usize| row.get(i).and_then(|v| v.parse::<i64>().ok()).unwrap_or(0);
            let asleep = stage(8) + stage(9) + stage(10); // light + deep + rem, awake excluded
            let entry = days.entry(date).or_default();
            entry.steps = field(&row, 1);
            entry.hr_resting = field(&row, 5);
            entry.sleep_min = if asleep > 0 { Some(asleep) } else { None };
            entry.sleep_score = field(&row, 12);
        }
    }

    // weight/: time,kg,device — the day is the first 10 chars of the local stamp.
    for (month, rows) in monthly_csv_rows(&health_dir.join("weight")) {
        let days = months.entry(month).or_default();
        for row in rows {
            let (Some(time), Some(kg)) = (field(&row, 0), field(&row, 1)) else {
                continue;
            };
            let Ok(kg) = kg.parse::<f64>() else { continue };
            if time.len() < 10 {
                continue;
            }
            // Last reading of a day wins.
            days.entry(time[..10].to_string()).or_default().weight = Some(kg);
        }
    }

    let mut stats = NotesStats::default();
    if months.is_empty() {
        return Ok(stats);
    }
    std::fs::create_dir_all(notes_dir)
        .with_context(|| format!("creating {}", notes_dir.display()))?;

    for (month, days) in &months {
        let title = if month.len() == 6 {
            format!("{}-{}", &month[..4], &month[4..])
        } else {
            month.clone()
        };
        let mut body = String::from("---\nsource: tilde-health\ntags: [health]\n---\n\n");
        body.push_str(&format!("# Health — {title}\n\n"));
        body.push_str(
            "Generated from `files/health/`. Rewritten on every import, so edits here are lost.\n\n",
        );
        body.push_str("| Date | Weight (kg) | Steps | Resting HR | Sleep | Score |\n");
        body.push_str("| --- | ---: | ---: | ---: | ---: | ---: |\n");
        for (date, row) in days {
            body.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                date,
                row.weight.map(|w| format!("{w:.1}")).unwrap_or_default(),
                row.steps.clone().unwrap_or_default(),
                row.hr_resting.clone().unwrap_or_default(),
                row.sleep_min.map(hours_minutes).unwrap_or_default(),
                row.sleep_score.clone().unwrap_or_default(),
            ));
        }

        let path = notes_dir.join(format!("{title}.md"));
        if std::fs::read_to_string(&path)
            .map(|c| c == body)
            .unwrap_or(false)
        {
            continue;
        }
        let tmp = notes_dir.join(format!(".{title}.md.tmp"));
        std::fs::write(&tmp, &body).with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("renaming into {}", path.display()))?;
        stats.files_written += 1;
    }

    info!(files = stats.files_written, "health notes export complete");
    Ok(stats)
}

/// Resolve the configured timezone: an empty string means the system timezone.
pub fn resolve_timezone(name: &str) -> Result<TimeZone> {
    if name.is_empty() {
        return Ok(TimeZone::system());
    }
    TimeZone::get(name).with_context(|| format!("unknown timezone '{name}'"))
}

/// Background-job entry point: process the health inbox under `files_root`.
///
/// Matches the job-processor handler contract (payload is unused — a single
/// queued job covers whatever the inbox holds at execution time).
pub fn process_import_job(
    _payload_json: &str,
    files_root: &Path,
    tz_name: &str,
) -> anyhow::Result<InboxStats> {
    let tz = resolve_timezone(tz_name)?;
    let health_dir = files_root.join("health");
    process_inbox(&health_dir.join("_inbox"), &health_dir, &tz)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_db(dir: &Path) -> std::path::PathBuf {
        let db_path = dir.join("Gadgetbridge.db");
        let conn = Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE HUAMI_EXTENDED_ACTIVITY_SAMPLE (
                TIMESTAMP INTEGER NOT NULL, DEVICE_ID INTEGER NOT NULL,
                USER_ID INTEGER NOT NULL, RAW_INTENSITY INTEGER NOT NULL,
                STEPS INTEGER NOT NULL, RAW_KIND INTEGER NOT NULL,
                HEART_RATE INTEGER NOT NULL, UNKNOWN1 INTEGER, SLEEP INTEGER,
                DEEP_SLEEP INTEGER, REM_SLEEP INTEGER,
                PRIMARY KEY (TIMESTAMP, DEVICE_ID));
             CREATE TABLE HUAMI_STRESS_SAMPLE (
                TIMESTAMP INTEGER NOT NULL, DEVICE_ID INTEGER NOT NULL,
                USER_ID INTEGER NOT NULL, TYPE_NUM INTEGER NOT NULL,
                STRESS INTEGER NOT NULL, PRIMARY KEY (TIMESTAMP, DEVICE_ID));
             CREATE TABLE HUAMI_SLEEP_SESSION_SAMPLE (
                TIMESTAMP INTEGER NOT NULL, DEVICE_ID INTEGER NOT NULL,
                USER_ID INTEGER NOT NULL, DATA BLOB,
                PRIMARY KEY (TIMESTAMP, DEVICE_ID));",
        )
        .unwrap();

        // 2026-09-13 12:00:00 UTC == 09:00 in -03:00.
        let noon = 1789300800i64;
        conn.execute(
            "INSERT INTO HUAMI_EXTENDED_ACTIVITY_SAMPLE VALUES
                (?1, 1, 0, 50, 30, 80, 72, 0, 0, 0, 0),
                (?2, 1, 0, 20, 0, 80, 255, 0, 0, 0, 0),
                (?3, 1, 0, 10, 0, 115, 90, 0, 0, 0, 0)",
            [noon, noon + 60, noon + 120],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO HUAMI_STRESS_SAMPLE VALUES (?1, 1, 0, 1, 33)",
            [noon],
        )
        .unwrap();

        // Sleep session blob: midnight 2026-09-13 00:00 -03:00 = 03:00 UTC.
        let midnight = 1789268400u32;
        let mut blob = vec![0u8; 0x252];
        blob[0x04..0x08].copy_from_slice(&midnight.to_le_bytes());
        blob[0x0a..0x0c].copy_from_slice(&(23 * 60u16).to_le_bytes()); // 23:00 prev day
        blob[0x0c..0x0e].copy_from_slice(&(31 * 60u16).to_le_bytes()); // 07:00
        blob[0x16] = 88; // score
        blob[0x54] = 1;
        blob[0x56..0x58].copy_from_slice(&(23 * 60u16).to_le_bytes());
        blob[0x58..0x5a].copy_from_slice(&(24 * 60u16).to_le_bytes());
        blob[0x5a] = 5; // deep
        blob[0x24a..0x24c].copy_from_slice(&60u16.to_le_bytes()); // rem
        blob[0x24c..0x24e].copy_from_slice(&300u16.to_le_bytes()); // light
        blob[0x24e..0x250].copy_from_slice(&90u16.to_le_bytes()); // deep
        conn.execute(
            "INSERT INTO HUAMI_SLEEP_SESSION_SAMPLE VALUES (?1, 1, 0, ?2)",
            rusqlite::params![midnight as i64, blob],
        )
        .unwrap();

        db_path
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("tilde-health-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A weightlog daemon database: body weights keyed by the watch's own id.
    fn weightlog_db(dir: &Path) -> std::path::PathBuf {
        let path = dir.join("weightlog.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE body_weights (
                id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                kg REAL NOT NULL,
                ts INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                clock_offset_s INTEGER NOT NULL DEFAULT 0
             );",
        )
        .unwrap();
        // ts values are real weigh-ins from September; received_at is
        // deliberately in October, because bucketing must ignore it.
        conn.execute(
            "INSERT INTO body_weights VALUES ('a1', 'gtr4-74ca59da', 68.6, 1790337981, 1793000000, 0)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO body_weights VALUES ('a2', 'gtr4-74ca59da', 67.6, 1790511269, 1793000000, 0)",
            [],
        )
        .unwrap();
        path
    }

    #[test]
    fn exports_weightlog_weights_bucketed_by_measurement_time() {
        let dir = temp_dir("weightlog");
        let db = weightlog_db(&dir);
        let tz = TimeZone::get("America/Montevideo").unwrap();

        let stats = export_weightlog(&db, &dir.join("health"), &tz).unwrap();
        assert_eq!(stats.rows, 2);
        assert_eq!(stats.files_written, 1);

        // Both rows land in September even though received_at is in October.
        let weight = std::fs::read_to_string(dir.join("health/weight/202609.csv")).unwrap();
        assert!(weight.starts_with("time,kg,device\n"), "{weight}");
        assert!(
            weight.contains("2026-09-25T09:06:21-03:00,68.6,gtr4-74ca59da"),
            "{weight}"
        );
        assert!(
            weight.contains("2026-09-27T09:14:29-03:00,67.6,gtr4-74ca59da"),
            "{weight}"
        );
        assert!(!dir.join("health/weight/202610.csv").exists());
    }

    #[test]
    fn inbox_routes_weightlog_db_away_from_the_gadgetbridge_exporter() {
        let dir = temp_dir("weightlog-inbox");
        let inbox = dir.join("health/_inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        let db = weightlog_db(&dir);
        std::fs::rename(&db, inbox.join("weightlog.db")).unwrap();
        let tz = TimeZone::get("America/Montevideo").unwrap();

        let stats = process_inbox(&inbox, &dir.join("health"), &tz).unwrap();
        assert!(
            stats.export.is_none(),
            "must not run the Gadgetbridge exporter"
        );
        assert_eq!(stats.weight.map(|w| w.rows), Some(2));
        assert!(dir.join("health/weight/202609.csv").exists());
    }

    #[test]
    fn notes_export_merges_weight_into_the_daily_table() {
        let dir = temp_dir("notes");
        let health = dir.join("health");
        std::fs::create_dir_all(health.join("daily")).unwrap();
        std::fs::create_dir_all(health.join("weight")).unwrap();
        std::fs::write(
            health.join("daily/202609.csv"),
            "date,steps,hr_min,hr_avg,hr_max,hr_resting,stress_avg,stress_max,\
             sleep_light_min,sleep_deep_min,sleep_rem_min,sleep_awake_min,sleep_score,pai_total,spo2_min\n\
             2026-09-25,8432,48,62,140,54,30,70,200,90,42,15,81,,\n",
        )
        .unwrap();
        std::fs::write(
            health.join("weight/202609.csv"),
            "time,kg,device\n2026-09-25T09:06:21-03:00,68.6,gtr4-74ca59da\n",
        )
        .unwrap();

        let notes = dir.join("vault/health");
        let stats = export_notes(&health, &notes).unwrap();
        assert_eq!(stats.files_written, 1);

        let md = std::fs::read_to_string(notes.join("2026-09.md")).unwrap();
        assert!(md.contains("# Health — 2026-09"), "{md}");
        // Weight lands on the same row as that day's metrics; sleep is
        // light+deep+rem (200+90+42 = 332 min), awake excluded.
        assert!(
            md.contains("| 2026-09-25 | 68.6 | 8432 | 54 | 5h32m | 81 |"),
            "{md}"
        );

        // Unchanged data must not rewrite the file — otherwise every import
        // would churn the note through DAV sync.
        let again = export_notes(&health, &notes).unwrap();
        assert_eq!(again.files_written, 0);
    }

    #[test]
    fn notes_export_renders_weight_only_months() {
        let dir = temp_dir("notes-weight-only");
        let health = dir.join("health");
        std::fs::create_dir_all(health.join("weight")).unwrap();
        std::fs::write(
            health.join("weight/202609.csv"),
            "time,kg,device\n2026-09-27T09:14:29-03:00,67.6,gtr4-74ca59da\n",
        )
        .unwrap();

        let notes = dir.join("vault/health");
        assert_eq!(export_notes(&health, &notes).unwrap().files_written, 1);
        let md = std::fs::read_to_string(notes.join("2026-09.md")).unwrap();
        assert!(md.contains("| 2026-09-27 | 67.6 |"), "{md}");
    }

    #[test]
    fn exports_monthly_csvs_with_local_bucketing() {
        let dir = temp_dir("export");
        let db = fixture_db(&dir);
        let tz = TimeZone::get("America/Montevideo").unwrap();

        let stats = export_gadgetbridge(&db, &dir.join("health"), &tz).unwrap();
        assert_eq!(stats.activity_rows, 3);
        assert_eq!(stats.sleep_sessions, 1);

        let activity = std::fs::read_to_string(dir.join("health/activity/202609.csv")).unwrap();
        assert!(activity.starts_with("time,raw_kind,kind,intensity,steps,heart_rate\n"));
        assert!(activity.contains("2026-09-13T09:00:00-03:00,80,,50,30,72"));
        assert!(activity.contains(",115,not_worn,"));

        // HR 255 and not_worn minutes are excluded from heart_rate.csv.
        let hr = std::fs::read_to_string(dir.join("health/heart_rate/202609.csv")).unwrap();
        assert_eq!(hr.lines().count(), 2, "{hr}");

        let sleep = std::fs::read_to_string(dir.join("health/sleep/202609.csv")).unwrap();
        assert!(sleep.contains("2026-09-13,"), "{sleep}");
        assert!(sleep.contains(",300,90,60,0,88"), "{sleep}");

        let daily = std::fs::read_to_string(dir.join("health/daily/202609.csv")).unwrap();
        let day_line = daily.lines().find(|l| l.starts_with("2026-09-13")).unwrap();
        // steps=30, hr min/avg/max = 72 (single valid reading), stress 33.
        assert!(day_line.contains(",30,72,72,72,"), "{day_line}");
        assert!(day_line.contains(",33,33,300,90,60,0,88,"), "{day_line}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn export_is_idempotent_and_skips_unchanged_files() {
        let dir = temp_dir("idempotent");
        let db = fixture_db(&dir);
        let tz = TimeZone::get("America/Montevideo").unwrap();

        let first = export_gadgetbridge(&db, &dir.join("health"), &tz).unwrap();
        assert!(first.files_written > 0);
        let second = export_gadgetbridge(&db, &dir.join("health"), &tz).unwrap();
        assert_eq!(second.files_written, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn inbox_processing_copies_workouts_and_exports_db() {
        let dir = temp_dir("inbox");
        let inbox = dir.join("health/_inbox");
        std::fs::create_dir_all(&inbox).unwrap();
        fixture_db(&inbox);
        std::fs::write(inbox.join("2026-09-15-ride.gpx"), "<gpx/>").unwrap();
        std::fs::write(inbox.join(".hidden.gpx"), "x").unwrap();

        let tz = TimeZone::get("America/Montevideo").unwrap();
        let stats = process_inbox(&inbox, &dir.join("health"), &tz).unwrap();
        assert_eq!(stats.workouts_copied, 1);
        assert!(stats.export.is_some());
        assert!(dir.join("health/workouts/2026-09-15-ride.gpx").exists());
        // Inbox files stay in place for the sync client.
        assert!(inbox.join("Gadgetbridge.db").exists());

        // Re-run: nothing to do.
        let again = process_inbox(&inbox, &dir.join("health"), &tz).unwrap();
        assert_eq!(again.workouts_copied, 0);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sleep_blob_with_zero_stages_is_skipped() {
        let blob = vec![0u8; 0x252];
        assert!(parse_sleep_session(&blob).is_none());
    }
}
