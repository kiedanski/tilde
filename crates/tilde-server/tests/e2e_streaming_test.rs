//! End-to-end media streaming tests against the real server binary.
//!
//! Video playback in a browser depends on HTTP Range requests (RFC 9110 §14):
//!
//! - Without `Accept-Ranges` and `206 Partial Content`, seeking in a `<video>`
//!   element requires re-downloading the whole file.
//! - Safari and iOS probe with `Range: bytes=0-1` and refuse to play at all if
//!   the server answers `200`.
//! - MP4s with the `moov` atom at the end need a **suffix** range (`bytes=-N`)
//!   before playback can start.

mod common;

use common::e2e::{Client, start_server};

/// A stand-in for a media file: 1 KiB of recognisable bytes.
fn payload() -> String {
    (0..64)
        .map(|i| format!("chunk{:03}-abcdefg\n", i))
        .collect()
}

struct RangeResp {
    status: u16,
    body: Vec<u8>,
    content_range: Option<String>,
    accept_ranges: Option<String>,
    content_type: Option<String>,
}

fn get_range(client: &Client, path: &str, range: Option<&str>) -> RangeResp {
    let mut req = client
        .http
        .get(format!("{}{}", client.base_url, path))
        .basic_auth("admin", Some(&client.password));
    if let Some(r) = range {
        req = req.header("Range", r);
    }
    let resp = req.send().unwrap();
    let header = |n: &str| {
        resp.headers()
            .get(n)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    };
    RangeResp {
        status: resp.status().as_u16(),
        content_range: header("content-range"),
        accept_ranges: header("accept-ranges"),
        content_type: header("content-type"),
        body: resp.bytes().unwrap().to_vec(),
    }
}

#[test]
fn e2e_get_advertises_accept_ranges() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    c.put("/dav/files/clip.mp4", &payload());

    let r = get_range(&c, "/dav/files/clip.mp4", None);

    assert_eq!(
        r.accept_ranges.as_deref(),
        Some("bytes"),
        "players check Accept-Ranges before attempting to seek"
    );
}

#[test]
fn e2e_range_request_returns_206_with_correct_slice() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();
    c.put("/dav/files/clip.mp4", &body);

    let r = get_range(&c, "/dav/files/clip.mp4", Some("bytes=0-9"));

    assert_eq!(r.status, 206, "a Range request must return 206, not 200");
    assert_eq!(r.body, body.as_bytes()[0..=9], "wrong bytes returned");
    assert_eq!(
        r.content_range.as_deref(),
        Some(format!("bytes 0-9/{}", body.len()).as_str())
    );
}

#[test]
fn e2e_open_ended_range_returns_remainder() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();
    c.put("/dav/files/clip.mp4", &body);

    let r = get_range(&c, "/dav/files/clip.mp4", Some("bytes=100-"));

    assert_eq!(r.status, 206);
    assert_eq!(r.body, body.as_bytes()[100..]);
}

/// MP4s with a trailing `moov` atom need this before playback can begin.
#[test]
fn e2e_suffix_range_returns_tail() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();
    c.put("/dav/files/clip.mp4", &body);

    let r = get_range(&c, "/dav/files/clip.mp4", Some("bytes=-20"));

    assert_eq!(r.status, 206);
    assert_eq!(r.body, &body.as_bytes()[body.len() - 20..]);
}

/// Safari's opening probe. If this is not a 206, iOS will not play the video.
#[test]
fn e2e_safari_style_probe_returns_206() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    c.put("/dav/files/clip.mp4", &payload());

    let r = get_range(&c, "/dav/files/clip.mp4", Some("bytes=0-1"));

    assert_eq!(r.status, 206);
    assert_eq!(r.body.len(), 2);
}

#[test]
fn e2e_unsatisfiable_range_returns_416() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();
    c.put("/dav/files/clip.mp4", &body);

    let r = get_range(&c, "/dav/files/clip.mp4", Some("bytes=999999-1000000"));

    assert_eq!(r.status, 416, "out-of-range must be 416, not 200 or 206");
    assert_eq!(
        r.content_range.as_deref(),
        Some(format!("bytes */{}", body.len()).as_str()),
        "416 must report the real length so the player can recover"
    );
}

#[test]
fn e2e_malformed_range_falls_back_to_200() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();
    c.put("/dav/files/clip.mp4", &body);

    let r = get_range(&c, "/dav/files/clip.mp4", Some("furlongs=1-2"));

    assert_eq!(
        r.status, 200,
        "an unparseable Range is ignored (RFC 9110 §14.2)"
    );
    assert_eq!(r.body.len(), body.len());
}

/// `tilde-photos` ingests mov/avi/mkv (VIDEO_EXTENSIONS), but the DAV mime map
/// only knew mp4 and webm — so an iPhone .mov was served as a download.
#[test]
fn e2e_common_video_containers_get_video_mime_types() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);

    for (name, expected) in [
        ("a.mp4", "video/mp4"),
        ("b.webm", "video/webm"),
        ("c.mov", "video/quicktime"),
        ("d.mkv", "video/x-matroska"),
        ("e.avi", "video/x-msvideo"),
        ("f.m4v", "video/x-m4v"),
    ] {
        let path = format!("/dav/files/{}", name);
        c.put(&path, &payload());
        let r = get_range(&c, &path, None);
        assert_eq!(
            r.content_type.as_deref(),
            Some(expected),
            "{} must be served as video, or the browser downloads it instead of playing",
            name
        );
    }
}

/// Replicates the exact request sequence Media3/ExoPlayer's `OkHttpDataSource`
/// makes, against the `/dav/photos/` mount WebGallery actually streams from
/// (VideoPlayerViewModel.kt builds `{baseUrl}/dav/photos/{remoteOriginalPath}`).
///
/// ExoPlayer opens with no Range header (position 0, unknown length), then sends
/// `Range: bytes=N-` on every seek. When a server answers that with 200, the
/// player sets `bytesToSkip = N` and downloads-then-discards everything before
/// the seek point — which is why seeking used to re-stream the whole prefix.
#[test]
fn e2e_exoplayer_seek_pattern_on_photos_mount() {
    let (server, pws) = start_server(&["phone"]);
    let c = Client::new(&server, &pws[0]);
    let body = payload();

    // The photo pipeline organizes files into YYYY/MM on disk rather than via
    // DAV, so place it the same way — this also exercises serving a file the
    // stat cache has never seen.
    let dir = server.data_dir.join("photos/2026/05");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("clip.mp4"), &body).unwrap();

    // 1. Initial open: no Range header.
    let open = get_range(&c, "/dav/photos/2026/05/clip.mp4", None);
    assert_eq!(open.status, 200);
    assert_eq!(
        open.accept_ranges.as_deref(),
        Some("bytes"),
        "ExoPlayer will not attempt a ranged seek without this"
    );
    assert_eq!(open.content_type.as_deref(), Some("video/mp4"));

    // 2. Seek: ExoPlayer requests the remainder from the seek point.
    let seek_to = 700usize;
    let seek = get_range(
        &c,
        "/dav/photos/2026/05/clip.mp4",
        Some(&format!("bytes={}-", seek_to)),
    );

    assert_eq!(
        seek.status, 206,
        "a 200 here makes ExoPlayer download and discard the first {} bytes",
        seek_to
    );
    assert_eq!(
        seek.body.len(),
        body.len() - seek_to,
        "server must send only the remainder, not the whole file"
    );
    assert_eq!(seek.body, &body.as_bytes()[seek_to..]);
}
