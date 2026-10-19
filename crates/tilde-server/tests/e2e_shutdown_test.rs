//! Stopping the real binary while a blocking thread is stuck on the network.

mod common;

use common::e2e::start_server_prepared;
use std::io::Write;
use std::time::{Duration, Instant};

/// SIGTERM must stop the server promptly while an IMAP read is blocked. The
/// email sync loop abandons that thread at shutdown, but dropping the tokio
/// runtime waited for it anyway, so in production a stop hung until systemd
/// gave up and sent SIGKILL.
#[cfg(unix)]
#[test]
fn sigterm_exits_while_an_imap_read_is_stuck() {
    // Accepts the connection, then never says a word.
    let imap = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let imap_port = imap.local_addr().unwrap().port();
    let (mut server, _) = start_server_prepared(&[], |_, config| {
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(config)
            .unwrap();
        write!(
            file,
            "\n[email]\nenabled = true\n\n[[email.accounts]]\nname = \"personal\"\n\
             imap_host = \"127.0.0.1\"\nimap_port = {imap_port}\nuse_ssl = false\n\
             username = \"u\"\npassword = \"p\"\n"
        )
        .unwrap();
    });

    // Once accepted, the sync cycle's thread is blocked waiting for a greeting.
    imap.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let _silent = loop {
        match imap.accept() {
            Ok((conn, _)) => break conn,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Err(e) => panic!("email sync never connected to the IMAP server: {e}"),
        }
    };
    std::thread::sleep(Duration::from_millis(500));

    let stop = Instant::now();
    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(server.child.id() as i32, libc::SIGTERM) };
    let status = loop {
        if let Some(status) = server.child.try_wait().unwrap() {
            break status;
        }
        assert!(
            stop.elapsed() < Duration::from_secs(10),
            "server still running 10s after SIGTERM, waiting on the stuck IMAP thread"
        );
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "SIGTERM stop exited with {status}");
}
