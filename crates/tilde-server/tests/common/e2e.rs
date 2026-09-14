//! Shared harness for end-to-end tests that drive the **real** `tilde` binary.
//!
//! The in-process `axum_test` harness never exercises `tilde serve`, which builds
//! its own `DavState`. Anything wired into only one of those paths is invisible
//! to the other — that blind spot hid a real merge bug (see plan.md §5.6), which
//! is why these exist.

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

pub fn tilde_bin() -> String {
    env!("CARGO_BIN_EXE_tilde").to_string()
}

pub fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

/// A running server plus its temp dir. Kills the process on drop, including on
/// panic, so a failing assertion never leaks a listener.
pub struct Server {
    pub child: Child,
    pub base_url: String,
    pub data_dir: std::path::PathBuf,
    pub _dir: tempfile::TempDir,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub fn run_cli(args: &[&str], config: &str, data_dir: &str) -> String {
    let output = Command::new(tilde_bin())
        .arg("--config")
        .arg(config)
        .args(args)
        .env("TILDE_DATA_DIR", data_dir)
        .env("TILDE_HOSTNAME", "localhost")
        .env("TILDE_TLS_MODE", "upstream")
        .env("RUST_LOG", "error")
        .output()
        .unwrap_or_else(|e| panic!("failed to run tilde {:?}: {}", args, e));
    if !output.status.success() {
        panic!(
            "tilde {:?} failed ({})\nstdout: {}\nstderr: {}",
            args,
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn extract_password(out: &str) -> String {
    out.split_whitespace()
        .find(|w| w.starts_with("tilde_app_"))
        .unwrap_or_else(|| panic!("no app password in output:\n{}", out))
        .to_string()
}

/// Boot a real server with `credentials.len()` distinct app passwords.
pub fn start_server(credentials: &[&str]) -> (Server, Vec<String>) {
    start_server_inner(credentials, None)
}

/// Boot against a data directory prepared by the caller — used by the upgrade
/// test, which builds a pre-migration database before any binary touches it.
/// `prepare` receives the data dir and config path before `tilde init` runs.
pub fn start_server_prepared(
    credentials: &[&str],
    prepare: impl FnOnce(&std::path::Path, &str),
) -> (Server, Vec<String>) {
    start_server_inner(credentials, Some(Box::new(prepare)))
}

type Prepare<'a> = Box<dyn FnOnce(&std::path::Path, &str) + 'a>;

fn start_server_inner(credentials: &[&str], prepare: Option<Prepare<'_>>) -> (Server, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    let data_dir = dir.path().join("data");
    let config_path = dir.path().join("config.toml");
    let port = free_port();

    std::fs::write(
        &config_path,
        format!(
            "[server]\nhostname = \"localhost\"\nlisten_addr = \"127.0.0.1\"\n\
             listen_port = {}\n\n[tls]\nmode = \"upstream\"\n",
            port
        ),
    )
    .unwrap();

    let config = config_path.to_str().unwrap().to_string();
    let data = data_dir.to_str().unwrap().to_string();

    if let Some(prepare) = prepare {
        std::fs::create_dir_all(&data_dir).unwrap();
        prepare(&data_dir, &config);
    }

    run_cli(&["init"], &config, &data);

    let passwords: Vec<String> = credentials
        .iter()
        .map(|name| {
            extract_password(&run_cli(
                &[
                    "auth",
                    "app-password",
                    "create",
                    "--name",
                    name,
                    "--scope",
                    "*",
                ],
                &config,
                &data,
            ))
        })
        .collect();

    let mut child = Command::new(tilde_bin())
        .arg("--config")
        .arg(&config)
        .arg("serve")
        .env("TILDE_DATA_DIR", &data)
        .env("RUST_LOG", "error")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to start tilde serve");

    // Drain stderr so a full pipe never blocks the server.
    if let Some(stderr) = child.stderr.take() {
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                eprintln!("[server] {}", line);
            }
        });
    }

    let base_url = format!("http://127.0.0.1:{}", port);
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let start = std::time::Instant::now();
    let mut healthy = false;
    while start.elapsed() < Duration::from_secs(30) {
        if let Ok(r) = client.get(format!("{}/health", base_url)).send()
            && r.status().is_success()
        {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    let server = Server {
        child,
        base_url,
        data_dir,
        _dir: dir,
    };
    assert!(healthy, "server did not become healthy within 30s");
    (server, passwords)
}

pub struct Client {
    pub http: reqwest::blocking::Client,
    pub base_url: String,
    pub password: String,
}

impl Client {
    pub fn new(server: &Server, password: &str) -> Self {
        Client {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()
                .unwrap(),
            base_url: server.base_url.clone(),
            password: password.to_string(),
        }
    }

    pub fn get(&self, path: &str) -> (u16, String) {
        let r = self
            .http
            .get(format!("{}{}", self.base_url, path))
            .basic_auth("admin", Some(&self.password))
            .send()
            .unwrap();
        let status = r.status().as_u16();
        (status, r.text().unwrap_or_default())
    }

    pub fn put(&self, path: &str, body: &str) -> u16 {
        self.http
            .put(format!("{}{}", self.base_url, path))
            .basic_auth("admin", Some(&self.password))
            .body(body.to_string())
            .send()
            .unwrap()
            .status()
            .as_u16()
    }
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("{:x}", h.finalize())
}

/// Create an MCP bearer token on a running instance.
pub fn create_mcp_token(server: &Server, name: &str, scopes: &str) -> String {
    let config = server.data_dir.parent().unwrap().join("config.toml");
    let out = run_cli(
        &["mcp", "token", "create", "--name", name, "--scopes", scopes],
        config.to_str().unwrap(),
        server.data_dir.to_str().unwrap(),
    );
    out.split_whitespace()
        .find(|w| w.starts_with("mcp_prod_"))
        .unwrap_or_else(|| panic!("no MCP token in output:\n{}", out))
        .to_string()
}

/// A JSON-RPC client for the `/mcp` endpoint.
pub struct Mcp {
    http: reqwest::blocking::Client,
    url: String,
    token: String,
    id: std::cell::Cell<u64>,
}

impl Mcp {
    pub fn new(server: &Server, token: &str) -> Self {
        Mcp {
            http: reqwest::blocking::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            url: format!("{}/mcp", server.base_url),
            token: token.to_string(),
            id: std::cell::Cell::new(0),
        }
    }

    pub fn rpc(&self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.id.set(self.id.get() + 1);
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": self.id.get(), "method": method, "params": params
        });
        self.http
            .post(&self.url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .unwrap()
            .json()
            .unwrap()
    }

    pub fn tool_names(&self) -> Vec<String> {
        self.rpc("tools/list", serde_json::json!({}))["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_string())
            .collect()
    }

    /// Call a tool, returning its decoded JSON payload. Panics on a JSON-RPC error.
    pub fn call(&self, tool: &str, args: serde_json::Value) -> serde_json::Value {
        let r = self.rpc(
            "tools/call",
            serde_json::json!({"name": tool, "arguments": args}),
        );
        if let Some(e) = r.get("error") {
            panic!("tool {} failed: {}", tool, e);
        }
        let text = r["result"]["content"][0]["text"].as_str().unwrap_or("null");
        serde_json::from_str(text).unwrap_or(serde_json::Value::String(text.to_string()))
    }

    /// Call a tool expecting a JSON-RPC error; returns the message.
    pub fn call_expecting_error(&self, tool: &str, args: serde_json::Value) -> String {
        let r = self.rpc(
            "tools/call",
            serde_json::json!({"name": tool, "arguments": args}),
        );
        r["error"]["message"]
            .as_str()
            .unwrap_or_else(|| panic!("expected an error from {}, got {}", tool, r))
            .to_string()
    }
}
