//! Vaultwarden `/api/sync` model, decryption, and item-lookup logic.
#![allow(dead_code)]
//!
//! Faithfully ports the relevant parts of api_client.go and client.go:
//! - `decryptCipher` → `decrypt_cipher`
//! - `findItem`      → `find_item`
//! - `extractSecret` → `extract_secret`

use std::collections::HashMap;

use reqwest::Client as HttpClient;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info, warn};

use super::crypto::{decrypt_org_key, decrypt_private_key, decrypt_str, CryptoError, SymmetricKey};

#[derive(Debug, Error)]
pub enum SyncError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("secret {0:?} not found in vault")]
    NotFound(String),
    #[error("unauthorized (401); caller should refresh and retry")]
    Unauthorized,
}

// ---------------------------------------------------------------------------
// Bitwarden sync API types
// ---------------------------------------------------------------------------

/// Full response from `GET /api/sync`.
#[derive(Debug, Deserialize)]
pub struct SyncResponse {
    pub profile: SyncProfile,
    pub ciphers: Vec<SyncCipher>,
}

#[derive(Debug, Deserialize)]
pub struct SyncProfile {
    pub id: String,
    pub email: String,
    pub key: String,
    #[serde(rename = "privateKey", default)]
    pub private_key: String,
    #[serde(default)]
    pub organizations: Vec<SyncOrganization>,
}

#[derive(Debug, Deserialize)]
pub struct SyncOrganization {
    pub id: String,
    pub name: String,
    pub key: String,
}

/// Bitwarden cipher types.
pub const CIPHER_TYPE_LOGIN: u8 = 1;
pub const CIPHER_TYPE_SECURE_NOTE: u8 = 2;
pub const CIPHER_TYPE_CARD: u8 = 3;
pub const CIPHER_TYPE_IDENTITY: u8 = 4;

#[derive(Debug, Deserialize)]
pub struct SyncCipher {
    pub id: String,
    #[serde(rename = "type")]
    pub cipher_type: u8,
    #[serde(rename = "organizationId")]
    pub organization_id: Option<String>,
    pub name: String,
    pub notes: Option<String>,
    pub login: Option<SyncLogin>,
    pub card: Option<SyncCard>,
    #[serde(default)]
    pub fields: Vec<SyncField>,
}

#[derive(Debug, Deserialize)]
pub struct SyncLogin {
    pub username: Option<String>,
    pub password: Option<String>,
    pub uri: Option<String>,
    #[serde(default)]
    pub uris: Vec<SyncUri>,
}

#[derive(Debug, Deserialize)]
pub struct SyncUri {
    pub uri: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncCard {
    #[serde(rename = "cardholderName")]
    pub cardholder_name: Option<String>,
    pub number: Option<String>,
    pub code: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SyncField {
    pub name: Option<String>,
    pub value: Option<String>,
    #[serde(rename = "type", default)]
    pub field_type: u8,
}

// ---------------------------------------------------------------------------
// Decrypted item
// ---------------------------------------------------------------------------

/// A vault item after decryption.
#[derive(Debug, Clone)]
pub struct DecryptedItem {
    pub id: String,
    pub cipher_type: u8,
    pub name: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub uri: String,
    /// Custom fields by decrypted field name.
    pub fields: HashMap<String, String>,
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/// Fetch `/api/sync` and return the raw response.
///
/// Returns `Err(SyncError::Unauthorized)` on HTTP 401 so the caller can
/// refresh the token and retry.
pub async fn fetch_sync(
    http: &HttpClient,
    base_url: &str,
    access_token: &str,
) -> Result<SyncResponse, SyncError> {
    let resp = http
        .get(format!("{base_url}/api/sync"))
        .bearer_auth(access_token)
        .send()
        .await?;

    if resp.status().as_u16() == 401 {
        return Err(SyncError::Unauthorized);
    }

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(SyncError::Server { status, body });
    }

    Ok(resp.json::<SyncResponse>().await?)
}

/// Decrypt all ciphers in a sync response using the user's symmetric key
/// and any organisation keys derived from the user's RSA private key.
pub fn decrypt_vault(sync: &SyncResponse, sym_key: &SymmetricKey) -> Vec<DecryptedItem> {
    // Decrypt org keys if we have a private key.
    let mut org_keys: HashMap<String, SymmetricKey> = HashMap::new();
    if !sync.profile.organizations.is_empty() && !sync.profile.private_key.is_empty() {
        match decrypt_private_key(&sync.profile.private_key, sym_key) {
            Ok(private_key) => {
                for org in &sync.profile.organizations {
                    match decrypt_org_key(&org.key, &private_key) {
                        Ok(ok) => {
                            debug!(org_id = %org.id, "decrypted org key");
                            org_keys.insert(org.id.clone(), ok);
                        }
                        Err(e) => warn!(org_id = %org.id, err = %e, "failed to decrypt org key"),
                    }
                }
                info!(count = org_keys.len(), "decrypted org keys");
            }
            Err(e) => {
                warn!(err = %e, "failed to decrypt RSA private key; org items will be skipped")
            }
        }
    }

    let mut items = Vec::with_capacity(sync.ciphers.len());
    for cipher in &sync.ciphers {
        let key = if let Some(org_id) = &cipher.organization_id {
            if org_id.is_empty() {
                sym_key
            } else if let Some(k) = org_keys.get(org_id.as_str()) {
                k
            } else {
                debug!(cipher_id = %cipher.id, org_id = %org_id, "no org key; skipping cipher");
                continue;
            }
        } else {
            sym_key
        };

        match decrypt_cipher(cipher, key) {
            Ok(item) => items.push(item),
            Err(e) => {
                debug!(cipher_id = %cipher.id, err = %e, "failed to decrypt cipher; skipping")
            }
        }
    }

    info!(count = items.len(), "decrypted vault items");
    items
}

/// Decrypt a single cipher into a `DecryptedItem`.
pub fn decrypt_cipher(
    cipher: &SyncCipher,
    key: &SymmetricKey,
) -> Result<DecryptedItem, CryptoError> {
    let name = decrypt_str(&cipher.name, key)?;
    let notes = match &cipher.notes {
        Some(n) => decrypt_str(n, key).unwrap_or_default(),
        None => String::new(),
    };

    let mut username = String::new();
    let mut password = String::new();
    let mut uri = String::new();

    if let Some(login) = &cipher.login {
        if let Some(u) = &login.username {
            username = decrypt_str(u, key).unwrap_or_default();
        }
        if let Some(p) = &login.password {
            password = decrypt_str(p, key).unwrap_or_default();
        }
        if let Some(u) = &login.uri {
            uri = decrypt_str(u, key).unwrap_or_default();
        }
        if uri.is_empty() {
            if let Some(first_uri) = login.uris.first() {
                if let Some(u) = &first_uri.uri {
                    uri = decrypt_str(u, key).unwrap_or_default();
                }
            }
        }
    }

    let mut fields = HashMap::new();
    for field in &cipher.fields {
        let fname = field
            .name
            .as_deref()
            .map(|n| decrypt_str(n, key).unwrap_or_default())
            .unwrap_or_default();
        let fvalue = field
            .value
            .as_deref()
            .map(|v| decrypt_str(v, key).unwrap_or_default())
            .unwrap_or_default();
        if !fname.is_empty() {
            fields.insert(fname, fvalue);
        }
    }

    Ok(DecryptedItem {
        id: cipher.id.clone(),
        cipher_type: cipher.cipher_type,
        name,
        username,
        password,
        notes,
        uri,
        fields,
    })
}

/// Search `items` for `name`.
///
/// Priority:
/// 1. Exact case-insensitive match.
/// 2. Substring (partial) match.
pub fn find_item<'a>(items: &'a [DecryptedItem], name: &str) -> Option<&'a DecryptedItem> {
    let key = name.to_lowercase();

    // Exact match.
    for item in items {
        if item.name.to_lowercase() == key {
            return Some(item);
        }
    }

    // Partial match.
    for item in items {
        if item.name.to_lowercase().contains(&key) {
            debug!("partial match found for secret lookup");
            return Some(item);
        }
    }

    None
}

/// Extract the most relevant secret value from a decrypted item.
///
/// Priority (matches Go `extractSecret`):
/// 1. `login.password`
/// 2. Custom field named `value`, `secret`, `api_key`, `apikey`, or `token`
/// 3. `notes`
/// 4. First non-empty field value
pub fn extract_secret(item: &DecryptedItem) -> &str {
    if !item.password.is_empty() {
        return &item.password;
    }

    for name in &["value", "secret", "api_key", "apikey", "token"] {
        if let Some(v) = item.fields.get(*name) {
            if !v.is_empty() {
                return v;
            }
        }
    }

    if !item.notes.is_empty() {
        return &item.notes;
    }

    for v in item.fields.values() {
        if !v.is_empty() {
            return v;
        }
    }

    ""
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::crypto::SymmetricKey;
    use aes::Aes256;
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    type HmacSha256 = Hmac<Sha256>;

    fn encrypt_type2(
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> String {
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        let mut ct = padded.clone();
        Aes256CbcEnc::new(enc_key.into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ct, padded.len())
            .unwrap();

        let mut mac = HmacSha256::new_from_slice(mac_key).unwrap();
        mac.update(iv);
        mac.update(&ct);
        let mac_bytes = mac.finalize().into_bytes();

        format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(&ct),
            BASE64.encode(mac_bytes)
        )
    }

    fn make_key() -> (SymmetricKey, [u8; 32], [u8; 32]) {
        let enc_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mac_key: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
        let sym = SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };
        (sym, enc_key, mac_key)
    }

    fn make_org_key() -> (SymmetricKey, [u8; 32], [u8; 32]) {
        let enc_key: [u8; 32] = std::array::from_fn(|i| (i + 100) as u8);
        let mac_key: [u8; 32] = std::array::from_fn(|i| (i + 132) as u8);
        let sym = SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };
        (sym, enc_key, mac_key)
    }

    #[test]
    fn test_decrypt_cipher_with_org_key() {
        let (personal_key, _, _) = make_key();
        let (org_key, org_enc, org_mac) = make_org_key();
        let iv = [50u8; 16];
        let org_id = "org-123".to_string();

        let enc_name = encrypt_type2(&org_enc, &org_mac, &iv, b"ORG_SECRET");

        let cipher = SyncCipher {
            id: "cipher-1".to_string(),
            cipher_type: CIPHER_TYPE_LOGIN,
            organization_id: Some(org_id),
            name: enc_name,
            notes: None,
            login: None,
            card: None,
            fields: vec![],
        };

        // Should fail with personal key.
        assert!(decrypt_cipher(&cipher, &personal_key).is_err());

        // Should succeed with org key.
        let item = decrypt_cipher(&cipher, &org_key).unwrap();
        assert_eq!(item.name, "ORG_SECRET");
    }

    #[test]
    fn test_decrypt_cipher_personal_item() {
        let (key, enc_key, mac_key) = make_key();
        let iv = [0u8; 16];

        let enc_name = encrypt_type2(&enc_key, &mac_key, &iv, b"PERSONAL_SECRET");

        let cipher = SyncCipher {
            id: "personal-1".to_string(),
            cipher_type: CIPHER_TYPE_SECURE_NOTE,
            organization_id: None,
            name: enc_name,
            notes: None,
            login: None,
            card: None,
            fields: vec![],
        };

        let item = decrypt_cipher(&cipher, &key).unwrap();
        assert_eq!(item.name, "PERSONAL_SECRET");
    }

    #[test]
    fn test_find_item_exact() {
        let items = vec![
            DecryptedItem {
                id: "1".into(),
                cipher_type: 1,
                name: "MySecret".into(),
                username: String::new(),
                password: "pw".into(),
                notes: String::new(),
                uri: String::new(),
                fields: HashMap::new(),
            },
            DecryptedItem {
                id: "2".into(),
                cipher_type: 1,
                name: "OtherSecret".into(),
                username: String::new(),
                password: "other".into(),
                notes: String::new(),
                uri: String::new(),
                fields: HashMap::new(),
            },
        ];

        let found = find_item(&items, "mysecret").unwrap();
        assert_eq!(found.name, "MySecret");
    }

    #[test]
    fn test_find_item_partial() {
        let items = vec![DecryptedItem {
            id: "1".into(),
            cipher_type: 1,
            name: "Production API Key".into(),
            username: String::new(),
            password: "pw".into(),
            notes: String::new(),
            uri: String::new(),
            fields: HashMap::new(),
        }];

        let found = find_item(&items, "api key").unwrap();
        assert_eq!(found.name, "Production API Key");
    }

    #[test]
    fn test_find_item_not_found() {
        let items: Vec<DecryptedItem> = vec![];
        assert!(find_item(&items, "missing").is_none());
    }

    #[test]
    fn test_extract_secret_password_priority() {
        let item = DecryptedItem {
            id: "1".into(),
            cipher_type: 1,
            name: "Test".into(),
            username: String::new(),
            password: "thepassword".into(),
            notes: "the notes".into(),
            uri: String::new(),
            fields: {
                let mut m = HashMap::new();
                m.insert("value".into(), "field_value".into());
                m
            },
        };
        assert_eq!(extract_secret(&item), "thepassword");
    }

    #[test]
    fn test_extract_secret_field_priority() {
        let mut fields = HashMap::new();
        fields.insert("token".into(), "mytoken".into());

        let item = DecryptedItem {
            id: "1".into(),
            cipher_type: 2,
            name: "Test".into(),
            username: String::new(),
            password: String::new(),
            notes: "fallback notes".into(),
            uri: String::new(),
            fields,
        };
        assert_eq!(extract_secret(&item), "mytoken");
    }

    #[test]
    fn test_extract_secret_notes_fallback() {
        let item = DecryptedItem {
            id: "1".into(),
            cipher_type: 2,
            name: "Test".into(),
            username: String::new(),
            password: String::new(),
            notes: "secret note".into(),
            uri: String::new(),
            fields: HashMap::new(),
        };
        assert_eq!(extract_secret(&item), "secret note");
    }
}
