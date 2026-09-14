//! WebDAV-Push notifications for CalDAV changes.
//!
//! Implements a simplified push mechanism: clients subscribe to a calendar
//! collection with a callback URL, and the server POSTs notifications when
//! events are created, modified, or deleted.

use rusqlite::Connection;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tracing::{info, warn};

/// How long a single push delivery may take before it is abandoned.
const PUSH_TIMEOUT: Duration = Duration::from_secs(10);
const PUSH_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Validate a client-supplied callback URL before it is stored.
///
/// The callback is fetched by the server, so an unrestricted URL turns any
/// credential that can reach a calendar collection into a request-forgery
/// primitive against whatever the server itself can reach (SSRF) -- the
/// loopback admin ports, the LAN, cloud metadata endpoints. Only plain http(s)
/// to a routable address is allowed. Literal addresses are rejected here;
/// names are re-checked after resolution, immediately before delivery.
pub fn validate_callback_url(raw: &str) -> Result<(), String> {
    let url =
        reqwest::Url::parse(raw).map_err(|_| "callback_url is not a valid URL".to_string())?;

    match url.scheme() {
        "http" | "https" => {}
        other => {
            return Err(format!(
                "callback_url scheme '{}' is not allowed (use http or https)",
                other
            ));
        }
    }

    let host = url
        .host_str()
        .ok_or_else(|| "callback_url must have a host".to_string())?;

    if host.eq_ignore_ascii_case("localhost") || host.to_ascii_lowercase().ends_with(".localhost") {
        return Err("callback_url must not target the server itself".to_string());
    }

    if let Some(ip) = parse_host_ip(host)
        && !is_routable_ip(ip)
    {
        return Err(
            "callback_url must not target a loopback, link-local or private address".to_string(),
        );
    }

    Ok(())
}

/// An IP literal host, with the brackets an IPv6 URL host carries.
fn parse_host_ip(host: &str) -> Option<IpAddr> {
    host.trim_start_matches('[')
        .trim_end_matches(']')
        .parse()
        .ok()
}

/// Whether an address is one we are willing to send a push notification to:
/// globally routable unicast only.
fn is_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_routable_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_routable_v4(v4);
            }
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return false;
            }
            let first = v6.segments()[0];
            // fc00::/7 unique-local, fe80::/10 link-local
            if first & 0xfe00 == 0xfc00 || first & 0xffc0 == 0xfe80 {
                return false;
            }
            true
        }
    }
}

fn is_routable_v4(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_unspecified()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (64..128).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
        || o[0] >= 240)
}

/// Re-check the callback after DNS resolution: a name can point anywhere, so
/// the literal-address check alone would be trivially bypassed by `a.example`
/// with an A record of 127.0.0.1.
async fn resolves_to_routable_addr(url: &reqwest::Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    if let Some(ip) = parse_host_ip(host) {
        return is_routable_ip(ip);
    }
    let port = url.port_or_known_default().unwrap_or(443);
    match tokio::net::lookup_host((host, port)).await {
        Ok(addrs) => {
            let mut saw_any = false;
            for addr in addrs {
                saw_any = true;
                if !is_routable_ip(addr.ip()) {
                    return false;
                }
            }
            saw_any
        }
        Err(_) => false,
    }
}

/// The shared delivery client: bounded in time and forbidden to follow
/// redirects, since a redirect would otherwise reach right past the address
/// checks above.
fn push_client() -> Option<&'static reqwest::Client> {
    static CLIENT: std::sync::OnceLock<Option<reqwest::Client>> = std::sync::OnceLock::new();
    CLIENT
        .get_or_init(|| {
            reqwest::Client::builder()
                .timeout(PUSH_TIMEOUT)
                .connect_timeout(PUSH_CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .ok()
        })
        .as_ref()
}

/// Register a push subscription for a calendar collection.
pub fn subscribe(
    db: &Connection,
    collection_type: &str,
    collection_id: &str,
    callback_url: &str,
    expiry_hours: u32,
) -> Result<String, String> {
    validate_callback_url(callback_url)?;

    let id = uuid::Uuid::new_v4().to_string();
    let now = jiff::Zoned::now();
    let created_at = now.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();
    let expiry = now
        .checked_add(jiff::SignedDuration::from_hours(expiry_hours as i64))
        .unwrap_or(now.clone());
    let expiry_str = expiry.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string();

    db.execute(
        "INSERT INTO push_subscriptions (id, collection_type, collection_id, callback_url, expiry, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![id, collection_type, collection_id, callback_url, expiry_str, created_at, created_at],
    ).map_err(|e| format!("Failed to create subscription: {}", e))?;

    info!(
        subscription_id = %id,
        collection_type = %collection_type,
        callback_url = %callback_url,
        "Push subscription created"
    );

    Ok(id)
}

/// List active subscriptions for a collection.
pub fn list_subscriptions(
    db: &Connection,
    collection_type: &str,
    collection_id: &str,
) -> Vec<PushSubscription> {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();

    let mut stmt = match db.prepare(
        "SELECT id, collection_type, collection_id, callback_url, expiry, created_at
         FROM push_subscriptions
         WHERE collection_type = ?1 AND collection_id = ?2 AND expiry > ?3",
    ) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    stmt.query_map(
        rusqlite::params![collection_type, collection_id, now],
        |row| {
            Ok(PushSubscription {
                id: row.get(0)?,
                collection_type: row.get(1)?,
                collection_id: row.get(2)?,
                callback_url: row.get(3)?,
                expiry: row.get(4)?,
                created_at: row.get(5)?,
            })
        },
    )
    .map(|rows| rows.filter_map(|r| r.ok()).collect())
    .unwrap_or_default()
}

/// Remove a push subscription.
pub fn unsubscribe(db: &Connection, subscription_id: &str) -> bool {
    db.execute(
        "DELETE FROM push_subscriptions WHERE id = ?1",
        [subscription_id],
    )
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// Clean up expired subscriptions.
pub fn cleanup_expired(db: &Connection) {
    let now = jiff::Zoned::now()
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string();
    let _ = db.execute("DELETE FROM push_subscriptions WHERE expiry <= ?1", [&now]);
}

/// Notify all subscribers of a change to a calendar collection.
/// This spawns background tasks — does not block the caller.
pub fn notify_change(
    db: &Connection,
    collection_type: &str,
    collection_id: &str,
    change_type: &str,
    object_uri: &str,
) {
    let subscriptions = list_subscriptions(db, collection_type, collection_id);
    if subscriptions.is_empty() {
        return;
    }

    let payload = serde_json::json!({
        "collection_type": collection_type,
        "collection_id": collection_id,
        "change_type": change_type,
        "object_uri": object_uri,
        "timestamp": jiff::Zoned::now().strftime("%Y-%m-%dT%H:%M:%S%:z").to_string(),
    });

    let payload_str = payload.to_string();

    for sub in subscriptions {
        let url = sub.callback_url.clone();
        let body = payload_str.clone();
        tokio::spawn(async move {
            if let Err(reason) = validate_callback_url(&url) {
                warn!(callback = %url, reason = %reason, "Push notification blocked");
                return;
            }
            let Ok(parsed) = reqwest::Url::parse(&url) else {
                warn!(callback = %url, "Push notification blocked: unparseable callback URL");
                return;
            };
            if !resolves_to_routable_addr(&parsed).await {
                warn!(callback = %url, "Push notification blocked: callback does not resolve to a routable address");
                return;
            }
            let Some(client) = push_client() else {
                warn!(callback = %url, "Push notification skipped: HTTP client unavailable");
                return;
            };
            match client
                .post(parsed)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
                .await
            {
                Ok(resp) => {
                    if resp.status().is_success() {
                        info!(callback = %url, "Push notification delivered");
                    } else {
                        warn!(callback = %url, status = %resp.status(), "Push notification delivery failed");
                    }
                }
                Err(e) => {
                    warn!(callback = %url, error = %e, "Push notification delivery error");
                }
            }
        });
    }
}

#[derive(Debug, Clone)]
pub struct PushSubscription {
    pub id: String,
    pub collection_type: String,
    pub collection_id: String,
    pub callback_url: String,
    pub expiry: String,
    pub created_at: String,
}
