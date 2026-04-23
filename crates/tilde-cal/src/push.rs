//! WebDAV-Push notifications for CalDAV changes.
//!
//! Implements a simplified push mechanism: clients subscribe to a calendar
//! collection with a callback URL, and the server POSTs notifications when
//! events are created, modified, or deleted.

use rusqlite::Connection;
use tracing::{info, warn};

/// Register a push subscription for a calendar collection.
pub fn subscribe(
    db: &Connection,
    collection_type: &str,
    collection_id: &str,
    callback_url: &str,
    expiry_hours: u32,
) -> Result<String, String> {
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
         WHERE collection_type = ?1 AND collection_id = ?2 AND expiry > ?3"
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
    let _ = db.execute(
        "DELETE FROM push_subscriptions WHERE expiry <= ?1",
        [&now],
    );
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
            let client = reqwest::Client::new();
            match client
                .post(&url)
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
