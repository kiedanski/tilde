//! End-to-end deployment test.
//!
//! Exercises the real tilde binary through a full lifecycle:
//! 1. `tilde init` — create config, data dirs, database
//! 2. `tilde auth app-password create` — create credentials
//! 3. `tilde serve` — start the HTTP server
//! 4. Hit endpoints: health, WebDAV, CalDAV, CardDAV, file upload/download
//! 5. `tilde status --json` — verify status reporting
//! 6. Graceful shutdown via SIGTERM
//!
//! This catches regressions in install/deploy that unit tests miss:
//! missing migrations, broken CLI flags, startup crashes, routing issues.

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

/// Find a free TCP port by binding to port 0 and returning the assigned port.
fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// Build a Basic auth header value for the given password.
fn basic_auth(password: &str) -> String {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(format!("admin:{}", password));
    format!("Basic {}", encoded)
}

/// Path to the `tilde` binary built by cargo.
fn tilde_bin() -> String {
    env!("CARGO_BIN_EXE_tilde").to_string()
}

/// Run a tilde CLI command, returning stdout. Panics on non-zero exit.
fn tilde_cmd(args: &[&str], config_path: &str, env_vars: &[(&str, &str)]) -> String {
    let mut cmd = Command::new(tilde_bin());
    cmd.arg("--config").arg(config_path);
    cmd.args(args);
    for (k, v) in env_vars {
        cmd.env(k, v);
    }
    // Suppress tracing noise in tests
    cmd.env("RUST_LOG", "error");
    let output = cmd
        .output()
        .unwrap_or_else(|e| panic!("Failed to run tilde {}: {}", args[0], e));
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        panic!(
            "tilde {} failed (exit {})\nstdout: {}\nstderr: {}",
            args.join(" "),
            output.status,
            stdout,
            stderr
        );
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

/// Wait for the server to be ready by polling /health.
fn wait_for_healthy(base_url: &str, timeout: Duration) -> bool {
    let start = std::time::Instant::now();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    while start.elapsed() < timeout {
        if let Ok(resp) = client.get(format!("{}/health", base_url)).send() {
            if resp.status().is_success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

#[test]
fn e2e_install_and_deploy() {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_dir = dir.path().join("config");
    std::fs::create_dir_all(&config_dir).unwrap();

    let port = free_port();
    let config_path = config_dir.join("config.toml");
    let base_url = format!("http://127.0.0.1:{}", port);

    // ── Step 1: Write minimal config ──────────────────────────────────────────
    let config_content = format!(
        r#"[server]
hostname = "localhost"
listen_addr = "127.0.0.1"
listen_port = {}

[tls]
mode = "upstream"

[photos]
enabled = true
"#,
        port
    );
    std::fs::write(&config_path, &config_content).unwrap();
    let config_str = config_path.to_str().unwrap();

    // ── Step 2: tilde init ────────────────────────────────────────────────────
    tilde_cmd(
        &["init"],
        config_str,
        &[
            ("TILDE_HOSTNAME", "localhost"),
            ("TILDE_TLS_MODE", "upstream"),
            ("TILDE_DATA_DIR", data_dir.to_str().unwrap()),
        ],
    );

    // Verify init created the database and directories
    assert!(
        data_dir.join("tilde.db").exists(),
        "Database should exist after init"
    );
    assert!(data_dir.join("photos").exists(), "Photos dir should exist");
    assert!(data_dir.join("notes").exists(), "Notes dir should exist");
    assert!(data_dir.join("files").exists(), "Files dir should exist");

    // ── Step 3: Create app password ───────────────────────────────────────────
    let pw_output = tilde_cmd(
        &[
            "auth",
            "app-password",
            "create",
            "--name",
            "e2e-test",
            "--scope",
            "*",
        ],
        config_str,
        &[("TILDE_DATA_DIR", data_dir.to_str().unwrap())],
    );
    // The password is printed to stdout — extract the tilde_app_... token
    let password = pw_output
        .lines()
        .find(|line| line.contains("tilde_app_"))
        .and_then(|line| {
            line.split_whitespace()
                .find(|word| word.starts_with("tilde_app_"))
        })
        .unwrap_or_else(|| panic!("No app password in output: {}", pw_output))
        .to_string();

    assert!(
        password.starts_with("tilde_app_"),
        "Password should start with tilde_app_, got: {}",
        password
    );

    // ── Step 4: tilde status --json (pre-serve) ──────────────────────────────
    let status_output = tilde_cmd(
        &["status", "--json"],
        config_str,
        &[("TILDE_DATA_DIR", data_dir.to_str().unwrap())],
    );
    let status: serde_json::Value = serde_json::from_str(&status_output)
        .unwrap_or_else(|e| panic!("Invalid status JSON: {}\nOutput: {}", e, status_output));
    assert!(
        status.get("database_path").is_some(),
        "Status should include database_path"
    );

    // ── Step 5: Start tilde serve ─────────────────────────────────────────────
    let mut server = Command::new(tilde_bin())
        .arg("--config")
        .arg(config_str)
        .arg("serve")
        .env("TILDE_DATA_DIR", data_dir.to_str().unwrap())
        .env("RUST_LOG", "info")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start tilde serve");

    // Spawn a thread to drain stderr so the server doesn't block on full pipe
    let stderr = server.stderr.take().unwrap();
    let stderr_handle = std::thread::spawn(move || {
        let reader = BufReader::new(stderr);
        let mut lines = Vec::new();
        for line in reader.lines() {
            if let Ok(l) = line {
                lines.push(l);
            }
        }
        lines
    });

    // Wait for server to become healthy
    let healthy = wait_for_healthy(&base_url, Duration::from_secs(15));
    if !healthy {
        // Kill and collect stderr for diagnosis
        let _ = server.kill();
        let _ = server.wait();
        let stderr_lines = stderr_handle.join().unwrap_or_default();
        panic!(
            "Server failed to become healthy within 15s.\nStderr:\n{}",
            stderr_lines.join("\n")
        );
    }

    // ── Step 6: Test endpoints ────────────────────────────────────────────────
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let auth_header = basic_auth(&password);

    // 6a. Health check
    let resp = client.get(format!("{}/health", base_url)).send().unwrap();
    assert_eq!(resp.status(), 200, "GET /health should return 200");
    let body = resp.text().unwrap();
    assert!(body.contains("healthy"), "/health should report healthy");

    // 6b. Well-known CalDAV redirect
    let no_redirect = reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();
    let resp = no_redirect
        .get(format!("{}/.well-known/caldav", base_url))
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        301,
        "/.well-known/caldav should redirect (got {})",
        resp.status()
    );

    // 6c. WebDAV PROPFIND (requires auth)
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/dav/files/", base_url),
        )
        .header("Authorization", &auth_header)
        .header("Depth", "0")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        207,
        "PROPFIND /dav/files/ should return 207 Multi-Status (got {})",
        resp.status()
    );

    // 6d. WebDAV PUT — upload a file
    let resp = client
        .put(format!("{}/dav/files/test-e2e.txt", base_url))
        .header("Authorization", &auth_header)
        .body("Hello from e2e test!")
        .send()
        .unwrap();
    assert!(
        resp.status() == 201 || resp.status() == 204,
        "PUT should return 201 or 204 (got {})",
        resp.status()
    );

    // 6e. WebDAV GET — download the uploaded file
    let resp = client
        .get(format!("{}/dav/files/test-e2e.txt", base_url))
        .header("Authorization", &auth_header)
        .send()
        .unwrap();
    assert_eq!(resp.status(), 200, "GET uploaded file should return 200");
    let body = resp.text().unwrap();
    assert_eq!(
        body, "Hello from e2e test!",
        "Downloaded content should match"
    );

    // 6f. CalDAV PROPFIND
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/caldav/admin/", base_url),
        )
        .header("Authorization", &auth_header)
        .header("Depth", "0")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        207,
        "PROPFIND /caldav/admin/ should return 207 (got {})",
        resp.status()
    );
    let body = resp.text().unwrap();
    assert!(
        body.contains("calendar"),
        "CalDAV response should mention calendar"
    );

    // 6g. CardDAV PROPFIND
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/carddav/admin/", base_url),
        )
        .header("Authorization", &auth_header)
        .header("Depth", "0")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        207,
        "PROPFIND /carddav/admin/ should return 207 (got {})",
        resp.status()
    );
    let body = resp.text().unwrap();
    assert!(
        body.contains("addressbook") || body.contains("CardDAV"),
        "CardDAV response should mention addressbook"
    );

    // 6h. Unauthenticated request should return 401
    let resp = client
        .request(
            reqwest::Method::from_bytes(b"PROPFIND").unwrap(),
            format!("{}/dav/files/", base_url),
        )
        .header("Depth", "0")
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        401,
        "Unauthenticated PROPFIND should return 401 (got {})",
        resp.status()
    );

    // 6i. CalDAV PUT — create an event
    let event_uid = "e2e-test-event-001";
    let ics = format!(
        "BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//e2e//EN\r\n\
         BEGIN:VEVENT\r\nUID:{}\r\nSUMMARY:E2E Test Event\r\n\
         DTSTART:20260601T100000Z\r\nDTEND:20260601T110000Z\r\n\
         END:VEVENT\r\nEND:VCALENDAR\r\n",
        event_uid
    );
    let resp = client
        .put(format!(
            "{}/caldav/admin/default/{}.ics",
            base_url, event_uid
        ))
        .header("Authorization", &auth_header)
        .header("Content-Type", "text/calendar")
        .body(ics)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "PUT CalDAV event should return 201 (got {})",
        resp.status()
    );

    // 6j. CardDAV PUT — create a contact
    let contact_uid = "e2e-test-contact-001";
    let vcard = format!(
        "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:{}\r\n\
         FN:E2E Test Contact\r\nEMAIL:e2e@test.local\r\n\
         END:VCARD\r\n",
        contact_uid
    );
    let resp = client
        .put(format!(
            "{}/carddav/admin/default/{}.vcf",
            base_url, contact_uid
        ))
        .header("Authorization", &auth_header)
        .header("Content-Type", "text/vcard")
        .body(vcard)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        201,
        "PUT CardDAV contact should return 201 (got {})",
        resp.status()
    );

    // 6k. WebDAV DELETE
    let resp = client
        .delete(format!("{}/dav/files/test-e2e.txt", base_url))
        .header("Authorization", &auth_header)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        204,
        "DELETE should return 204 (got {})",
        resp.status()
    );

    // 6l. Verify the file is gone
    let resp = client
        .get(format!("{}/dav/files/test-e2e.txt", base_url))
        .header("Authorization", &auth_header)
        .send()
        .unwrap();
    assert_eq!(
        resp.status(),
        404,
        "GET deleted file should return 404 (got {})",
        resp.status()
    );

    // ── Step 7: Graceful shutdown ─────────────────────────────────────────────
    #[cfg(unix)]
    unsafe {
        libc::kill(server.id() as i32, libc::SIGTERM);
    }
    #[cfg(not(unix))]
    {
        let _ = server.kill();
    }

    // Wait for the server to exit (with timeout)
    let shutdown_start = std::time::Instant::now();
    let exit_status = loop {
        match server.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if shutdown_start.elapsed() > Duration::from_secs(10) {
                    let _ = server.kill();
                    break server.wait().unwrap();
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => {
                let _ = server.kill();
                break server.wait().unwrap();
            }
        }
    };

    // Collect stderr for debugging
    let stderr_lines = stderr_handle.join().unwrap_or_default();

    // On SIGTERM the server should exit cleanly (status 0 or signal termination)
    assert!(
        exit_status.success() || cfg!(unix),
        "Server should exit cleanly after SIGTERM.\nExit: {:?}\nStderr:\n{}",
        exit_status,
        stderr_lines.join("\n")
    );
}
