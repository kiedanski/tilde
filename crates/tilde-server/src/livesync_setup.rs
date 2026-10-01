use axum::{
    extract::State,
    http::{HeaderMap, StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use tilde_core::auth;

use crate::SharedState;

const SETUP_PATH: &str = "/notes/live-sync/setup";

fn private_response(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, "no-store, private".parse().unwrap());
    headers.insert("referrer-policy", "no-referrer".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert(
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'"
            .parse()
            .unwrap(),
    );
    response
}

fn unauthorized() -> Response {
    let mut response = (
        StatusCode::UNAUTHORIZED,
        "Tilde notes setup requires an app password",
    )
        .into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        "Basic realm=\"Tilde notes setup\"".parse().unwrap(),
    );
    private_response(response)
}

fn password_from_basic(headers: &HeaderMap) -> Option<String> {
    let header = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let value = header.strip_prefix("Basic ")?;
    let decoded = STANDARD.decode(value).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (_, password) = decoded.split_once(':')?;
    Some(password.to_owned())
}

pub async fn setup_page(State(state): State<SharedState>, headers: HeaderMap) -> Response {
    let Some(password) = password_from_basic(&headers) else {
        return unauthorized();
    };
    let authenticated = state
        .db
        .get()
        .ok()
        .and_then(|conn| auth::verify_app_password(&conn, &password, SETUP_PATH).ok())
        .unwrap_or(false);
    if !authenticated {
        return unauthorized();
    }

    let config = state.config();
    let Some(remote) = config.notes.livesync.as_ref() else {
        return private_response(
            (StatusCode::NOT_FOUND, "LiveSync notes are not configured").into_response(),
        );
    };
    let Some(public_url) = remote.public_url.as_ref() else {
        return private_response(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Set notes.livesync.public_url to enable Obsidian setup",
            )
                .into_response(),
        );
    };
    let (public_url, database, username, couchdb_password) = (
        public_url.clone(),
        remote.database.clone(),
        remote.username.clone(),
        remote.password.clone(),
    );
    drop(config);
    let manual_url = public_url.clone();
    let manual_database = database.clone();
    let manual_username = username.clone();
    let setup = tokio::task::spawn_blocking(move || {
        tilde_livesync::generate_setup_uri(&public_url, &database, &username, &couchdb_password)
    })
    .await;
    let Ok(Ok(setup)) = setup else {
        return private_response(
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Could not generate Obsidian setup settings",
            )
                .into_response(),
        );
    };

    // The URI contains encrypted CouchDB credentials. Keep it out of URLs,
    // browser caches, and third-party resources on this page.
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    let script = r#"async function copyField(fieldId, buttonId) {
  const field = document.getElementById(fieldId);
  const button = document.getElementById(buttonId);
  try {
    await navigator.clipboard.writeText(field.value);
    button.textContent = 'Copied';
    setTimeout(() => button.textContent = buttonId === 'copy-uri' ? 'Copy Setup URI' : 'Copy passphrase', 2500);
  } catch {
    field.focus();
    field.select();
    button.textContent = 'Selected — press ⌘C or Ctrl+C';
  }
}
document.getElementById('copy-uri').addEventListener('click', () => copyField('setup-uri', 'copy-uri'));
document.getElementById('copy-passphrase').addEventListener('click', () => copyField('setup-passphrase', 'copy-passphrase'));"#;
    let body = format!(
        r#"<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect Obsidian to Tilde</title>
<style>body{{font:16px system-ui;max-width:46rem;margin:2rem auto;padding:0 1rem;line-height:1.5}}textarea,input{{box-sizing:border-box;width:100%;padding:.7rem;font:14px monospace}}textarea{{height:7rem}}li{{margin:.6rem 0}}button{{font:inherit;padding:.6rem 1rem;margin:.4rem 0 1rem;cursor:pointer}}</style>
<h1>Connect Obsidian to Tilde</h1>
<p><strong>This page is for copying a Setup URI.</strong> Do not paste this page's address into Obsidian's CouchDB URL field.</p>
<p>If Obsidian shows separate URL, Username, Password, and Database Name fields, go back and choose <strong>Use a Setup URI</strong>.</p>
<p>Back up your vault and turn off any other service syncing this vault. Install and enable the Self-hosted LiveSync plug-in.</p>
<ol><li>Open LiveSync onboarding and choose <strong>I am adding a device to an existing synchronisation setup</strong>, even on your first device.</li>
<li>Choose <strong>Use a Setup URI</strong>. Paste the URI and passphrase below, then select <strong>Test Settings and Continue</strong> and <strong>Restart and Fetch Data</strong>.</li>
<li>If the remote is newly provisioned, choose <strong>Overwrite all with remote files</strong>, then <strong>Keep local files even if not on remote</strong>. For a vault joining a remote that already contains notes with the same paths, choose <strong>Compare time and take newer</strong>, then <strong>Keep local files even if deleted on remote</strong>, and review any conflicts afterwards.</li>
<li>If LiveSync says the remote has no saved synchronisation settings, select <strong>Use this device's settings</strong> in this fetch flow. Complete any compatibility review and select <strong>Resume synchronisation</strong>.</li>
<li>Run <strong>Self-hosted LiveSync: Sync now</strong>. Check that notes appear on both sides. Then, in LiveSync's synchronisation settings, select the <strong>LiveSync</strong> preset and apply it for ongoing sync.</li></ol>
<p><strong>Setup URI</strong> (starts with <code>obsidian://setuplivesync?settings=</code>)</p><textarea id="setup-uri" readonly spellcheck="false">{}</textarea><button type="button" id="copy-uri">Copy Setup URI</button>
<p><strong>Setup URI passphrase</strong> (copy separately)</p><input id="setup-passphrase" readonly value="{}"><button type="button" id="copy-passphrase">Copy passphrase</button>
<details><summary>Manual CouchDB connection values</summary><p>URL: <code>{}</code><br>Username: <code>{}</code><br>Database: <code>{}</code></p><p>Manual setup also requires the separate CouchDB sync password. The Tilde app password used to open this page will not work for CouchDB.</p></details>
<p>This connection is unencrypted at the vault-content layer so Tilde's MCP notes tools can read it. The connection to CouchDB should use HTTPS.</p><script nonce="{}">{}</script></html>"#,
        setup.uri,
        setup.passphrase,
        escape_html(&manual_url),
        escape_html(&manual_username),
        escape_html(&manual_database),
        nonce,
        script,
    );
    let mut response = private_response(Html(body).into_response());
    response.headers_mut().insert(
        "content-security-policy",
        format!(
            "default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-{nonce}'; frame-ancestors 'none'"
        )
        .parse()
        .unwrap(),
    );
    response
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_password_parser_rejects_malformed_headers() {
        let mut headers = HeaderMap::new();
        assert!(password_from_basic(&headers).is_none());
        headers.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert!(password_from_basic(&headers).is_none());
        headers.insert(header::AUTHORIZATION, "Basic bm9jb2xvbg==".parse().unwrap());
        assert!(password_from_basic(&headers).is_none());
    }
}
