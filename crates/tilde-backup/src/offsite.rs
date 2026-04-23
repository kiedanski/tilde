//! S3-compatible offsite backup (works with Backblaze B2, AWS S3, MinIO, etc.)
//!
//! Uses the S3 REST API directly via reqwest + AWS Signature V4 signing.

use anyhow::{Context, Result, bail};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::path::Path;
use tracing::info;

type HmacSha256 = Hmac<Sha256>;

/// S3-compatible offsite backup configuration (resolved from env vars)
pub struct OffsiteConfig {
    pub name: String,
    pub endpoint: String,
    pub bucket: String,
    pub key_id: String,
    pub secret_key: String,
    pub region: String,
}

impl OffsiteConfig {
    /// Create from BackupOffsiteConfig by resolving env vars
    pub fn from_config(cfg: &tilde_core::config::BackupOffsiteConfig) -> Result<Self> {
        let bucket = std::env::var(&cfg.bucket_env)
            .with_context(|| format!("Missing env var: {}", cfg.bucket_env))?;
        let key_id = std::env::var(&cfg.key_id_env)
            .with_context(|| format!("Missing env var: {}", cfg.key_id_env))?;
        let secret_key = std::env::var(&cfg.key_env)
            .with_context(|| format!("Missing env var: {}", cfg.key_env))?;

        // Derive endpoint and region from config or defaults for B2
        let endpoint = if cfg.endpoint.is_empty() {
            // B2 S3-compatible endpoint — default to us-west-004
            "https://s3.us-west-004.backblazeb2.com".to_string()
        } else {
            cfg.endpoint.clone()
        };

        // Extract region from endpoint for B2 (e.g., s3.us-west-004.backblazeb2.com -> us-west-004)
        let region = extract_region(&endpoint).unwrap_or_else(|| "us-east-1".to_string());

        Ok(Self {
            name: cfg.name.clone(),
            endpoint,
            bucket,
            key_id,
            secret_key,
            region,
        })
    }
}

fn extract_region(endpoint: &str) -> Option<String> {
    // For B2: s3.us-west-004.backblazeb2.com -> us-west-004
    let host = endpoint
        .strip_prefix("https://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let host = host.trim_end_matches('/');
    if host.contains("backblazeb2.com") {
        // s3.REGION.backblazeb2.com
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() >= 3 {
            return Some(parts[1].to_string());
        }
    }
    None
}

/// Upload a local file to S3-compatible storage.
pub async fn upload_file(
    config: &OffsiteConfig,
    local_path: &Path,
    remote_key: &str,
) -> Result<()> {
    let body = std::fs::read(local_path)
        .with_context(|| format!("Failed to read {}", local_path.display()))?;

    let content_sha256 = hex::encode(Sha256::digest(&body));

    let now = jiff::Zoned::now();
    let date_stamp = now.strftime("%Y%m%d").to_string();
    let amz_date = now.strftime("%Y%m%dT%H%M%SZ").to_string();

    let url = format!("{}/{}/{}", config.endpoint, config.bucket, remote_key);

    // Build canonical request for AWS Signature V4
    let host = config.endpoint
        .strip_prefix("https://")
        .or_else(|| config.endpoint.strip_prefix("http://"))
        .unwrap_or(&config.endpoint);

    let canonical_uri = format!("/{}/{}", config.bucket, remote_key);
    let canonical_querystring = "";

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, content_sha256, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "PUT\n{}\n{}\n{}\n{}\n{}",
        canonical_uri, canonical_querystring, canonical_headers, signed_headers, content_sha256
    );

    let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, config.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = get_signature_key(
        &config.secret_key,
        &date_stamp,
        &config.region,
        "s3",
    );
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        config.key_id, credential_scope, signed_headers, signature
    );

    let client = reqwest::Client::new();
    let resp = client
        .put(&url)
        .header("Host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", &content_sha256)
        .header("Authorization", &authorization)
        .header("Content-Type", "application/octet-stream")
        .body(body)
        .send()
        .await
        .context("Failed to upload to S3")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("S3 upload failed (HTTP {}): {}", status, body);
    }

    info!(key = %remote_key, "Uploaded to offsite storage");
    Ok(())
}

/// List objects in S3-compatible storage with optional prefix.
pub async fn list_objects(
    config: &OffsiteConfig,
    prefix: Option<&str>,
) -> Result<Vec<S3Object>> {
    let now = jiff::Zoned::now();
    let date_stamp = now.strftime("%Y%m%d").to_string();
    let amz_date = now.strftime("%Y%m%dT%H%M%SZ").to_string();

    let host = config.endpoint
        .strip_prefix("https://")
        .or_else(|| config.endpoint.strip_prefix("http://"))
        .unwrap_or(&config.endpoint);

    let canonical_uri = format!("/{}", config.bucket);

    let mut query_params = vec![("list-type", "2".to_string())];
    if let Some(pfx) = prefix {
        query_params.push(("prefix", pfx.to_string()));
    }
    query_params.sort_by(|a, b| a.0.cmp(b.0));
    let canonical_querystring: String = query_params
        .iter()
        .map(|(k, v)| format!("{}={}", urlencoding(k), urlencoding(v)))
        .collect::<Vec<_>>()
        .join("&");

    let content_sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"; // empty body

    let canonical_headers = format!(
        "host:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n",
        host, content_sha256, amz_date
    );
    let signed_headers = "host;x-amz-content-sha256;x-amz-date";

    let canonical_request = format!(
        "GET\n{}\n{}\n{}\n{}\n{}",
        canonical_uri, canonical_querystring, canonical_headers, signed_headers, content_sha256
    );

    let credential_scope = format!("{}/{}/s3/aws4_request", date_stamp, config.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        amz_date,
        credential_scope,
        hex::encode(Sha256::digest(canonical_request.as_bytes()))
    );

    let signing_key = get_signature_key(&config.secret_key, &date_stamp, &config.region, "s3");
    let signature = hex::encode(hmac_sha256(&signing_key, string_to_sign.as_bytes()));

    let authorization = format!(
        "AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}",
        config.key_id, credential_scope, signed_headers, signature
    );

    let url = format!("{}/{}?{}", config.endpoint, config.bucket, canonical_querystring);

    let client = reqwest::Client::new();
    let resp = client
        .get(&url)
        .header("Host", host)
        .header("x-amz-date", &amz_date)
        .header("x-amz-content-sha256", content_sha256)
        .header("Authorization", &authorization)
        .send()
        .await
        .context("Failed to list S3 objects")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        bail!("S3 list failed (HTTP {}): {}", status, body);
    }

    let body = resp.text().await?;
    parse_list_objects_response(&body)
}

/// A simple representation of an S3 object
#[derive(Debug, Clone)]
pub struct S3Object {
    pub key: String,
    pub size: i64,
    pub last_modified: String,
}

fn parse_list_objects_response(xml: &str) -> Result<Vec<S3Object>> {
    let mut objects = Vec::new();
    // Simple XML parsing — extract <Key>, <Size>, <LastModified> from <Contents>
    let mut in_contents = false;
    let mut key = String::new();
    let mut size: i64 = 0;
    let mut last_modified = String::new();
    let mut current_tag = String::new();

    let mut reader = quick_xml::Reader::from_str(xml);
    let mut buf = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(quick_xml::events::Event::Start(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local == "Contents" {
                    in_contents = true;
                    key.clear();
                    size = 0;
                    last_modified.clear();
                }
                if in_contents {
                    current_tag = local;
                }
            }
            Ok(quick_xml::events::Event::Text(ref e)) => {
                if in_contents {
                    let text = e.unescape().unwrap_or_default().to_string();
                    match current_tag.as_str() {
                        "Key" => key = text,
                        "Size" => size = text.parse().unwrap_or(0),
                        "LastModified" => last_modified = text,
                        _ => {}
                    }
                }
            }
            Ok(quick_xml::events::Event::End(ref e)) => {
                let local = String::from_utf8_lossy(e.local_name().as_ref()).to_string();
                if local == "Contents" {
                    in_contents = false;
                    objects.push(S3Object {
                        key: key.clone(),
                        size,
                        last_modified: last_modified.clone(),
                    });
                }
                current_tag.clear();
            }
            Ok(quick_xml::events::Event::Eof) => break,
            Err(e) => bail!("XML parse error: {}", e),
            _ => {}
        }
        buf.clear();
    }

    Ok(objects)
}

// --- AWS Signature V4 helpers ---

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn get_signature_key(secret_key: &str, date_stamp: &str, region: &str, service: &str) -> Vec<u8> {
    let k_date = hmac_sha256(format!("AWS4{}", secret_key).as_bytes(), date_stamp.as_bytes());
    let k_region = hmac_sha256(&k_date, region.as_bytes());
    let k_service = hmac_sha256(&k_region, service.as_bytes());
    hmac_sha256(&k_service, b"aws4_request")
}

fn urlencoding(s: &str) -> String {
    // RFC 3986 percent-encoding
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                result.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    result
}

/// Upload a backup snapshot to offsite S3-compatible storage.
/// Returns the remote key used.
pub async fn upload_snapshot(
    config: &OffsiteConfig,
    snapshot: &super::Snapshot,
) -> Result<String> {
    let local_path = Path::new(&snapshot.archive_path);
    if !local_path.exists() {
        bail!("Snapshot archive not found: {}", snapshot.archive_path);
    }

    let filename = local_path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| format!("{}.tar.gz", snapshot.id));

    let remote_key = format!("tilde-backups/{}", filename);

    info!(
        snapshot_id = %snapshot.id,
        remote_key = %remote_key,
        size = snapshot.size_bytes,
        "Uploading snapshot to offsite storage"
    );

    upload_file(config, local_path, &remote_key).await?;

    info!(
        snapshot_id = %snapshot.id,
        remote_key = %remote_key,
        "Snapshot uploaded to offsite storage"
    );

    Ok(remote_key)
}

/// List backup snapshots in offsite storage.
pub async fn list_remote_snapshots(config: &OffsiteConfig) -> Result<Vec<S3Object>> {
    list_objects(config, Some("tilde-backups/")).await
}
