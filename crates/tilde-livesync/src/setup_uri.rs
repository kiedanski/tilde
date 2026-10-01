//! Generate a LiveSync Setup URI without a JavaScript runtime.
//!
//! The URI contains CouchDB credentials. Its passphrase must be shown through
//! an authenticated channel and kept separate from the URI when shared.

use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::Url;
use ring::{
    aead, hkdf, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use serde::Serialize;
use serde_json::json;
use std::num::NonZeroU32;

use crate::Error;

const PBKDF2_ITERATIONS: u32 = 310_000;

struct Aes256Key;

impl hkdf::KeyType for Aes256Key {
    fn len(&self) -> usize {
        32
    }
}

#[derive(Serialize)]
pub struct SetupUri {
    pub uri: String,
    pub passphrase: String,
}

/// Create an unencrypted, unobfuscated vault profile for Tilde's Rust reader.
/// The Setup URI itself is encrypted using LiveSync's `%$` format.
pub fn generate_setup_uri(
    public_url: &str,
    database: &str,
    username: &str,
    password: &str,
) -> Result<SetupUri, Error> {
    if database.is_empty()
        || database.contains(['/', '?', '#'])
        || username.is_empty()
        || password.is_empty()
    {
        return Err(Error::InvalidUrl);
    }
    let mut connection = Url::parse(public_url).map_err(|_| Error::InvalidUrl)?;
    if !matches!(connection.scheme(), "http" | "https")
        || connection.host_str().is_none()
        || connection.query().is_some()
        || connection.fragment().is_some()
        || !connection.username().is_empty()
        || connection.password().is_some()
    {
        return Err(Error::InvalidUrl);
    }
    let host = connection.host_str().ok_or(Error::InvalidUrl)?.to_owned();
    connection
        .set_username(username)
        .map_err(|_| Error::InvalidUrl)?;
    connection
        .set_password(Some(password))
        .map_err(|_| Error::InvalidUrl)?;
    connection.query_pairs_mut().append_pair("db", database);
    let profile_id = "tilde-couchdb";
    let settings = json!({
        "couchDB_URI": public_url,
        "couchDB_USER": username,
        "couchDB_PASSWORD": password,
        "couchDB_DBNAME": database,
        "encrypt": false,
        "usePathObfuscation": false,
        "passphrase": "",
        "liveSync": true,
        "syncOnSave": true,
        "syncOnStart": true,
        "batchSave": true,
        "customChunkSize": 60,
        "remoteConfigurations": {
            "tilde-couchdb": {
                "id": profile_id,
                "name": format!("CouchDB {host}"),
                "uri": format!("sls+{connection}"),
                "isEncrypted": false
            }
        },
        "activeConfigurationId": profile_id,
        "concurrencyOfReadChunksOnline": 30,
        "minimumIntervalOfReadChunksOnline": 25,
        "isConfigured": true,
        "usePluginSyncV2": true,
        "handleFilenameCaseSensitive": false,
        "configPassphraseStore": "",
        "encryptedCouchDBConnection": "",
        "encryptedPassphrase": ""
    });
    let plaintext = serde_json::to_vec(&settings).map_err(|e| Error::Unsupported(e.to_string()))?;

    let rng = SystemRandom::new();
    let mut pbkdf2_salt = [0_u8; 32];
    let mut iv = [0_u8; 12];
    let mut hkdf_salt = [0_u8; 32];
    let mut passphrase_bytes = [0_u8; 24];
    for bytes in [
        &mut pbkdf2_salt[..],
        &mut iv[..],
        &mut hkdf_salt[..],
        &mut passphrase_bytes[..],
    ] {
        rng.fill(bytes)
            .map_err(|_| Error::Unsupported("random number generation failed".into()))?;
    }
    let passphrase = URL_SAFE_NO_PAD.encode(passphrase_bytes);
    let mut master = [0_u8; 32];
    pbkdf2::derive(
        pbkdf2::PBKDF2_HMAC_SHA256,
        NonZeroU32::new(PBKDF2_ITERATIONS).expect("positive iteration count"),
        &pbkdf2_salt,
        passphrase.as_bytes(),
        &mut master,
    );
    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &hkdf_salt).extract(&master);
    let okm = prk
        .expand(&[&[]], Aes256Key)
        .map_err(|_| Error::Unsupported("HKDF failed".into()))?;
    let mut key_bytes = [0_u8; 32];
    okm.fill(&mut key_bytes)
        .map_err(|_| Error::Unsupported("HKDF failed".into()))?;
    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_256_GCM, &key_bytes)
            .map_err(|_| Error::Unsupported("AES key creation failed".into()))?,
    );
    let mut ciphertext = plaintext;
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(iv),
        aead::Aad::empty(),
        &mut ciphertext,
    )
    .map_err(|_| Error::Unsupported("Setup URI encryption failed".into()))?;
    let mut payload = Vec::with_capacity(32 + 12 + 32 + ciphertext.len());
    payload.extend_from_slice(&pbkdf2_salt);
    payload.extend_from_slice(&iv);
    payload.extend_from_slice(&hkdf_salt);
    payload.extend_from_slice(&ciphertext);
    let encrypted = format!("%${}", STANDARD.encode(payload));
    Ok(SetupUri {
        uri: format!(
            "obsidian://setuplivesync?settings={}",
            urlencoding::encode(&encrypted)
        ),
        passphrase,
    })
}
