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
use tracing::{debug, warn};

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
    /// Owning organization id; `None` for personal-vault items.
    pub organization_id: Option<String>,
    pub name: String,
    pub username: String,
    pub password: String,
    pub notes: String,
    pub uri: String,
    /// Custom fields by decrypted field name.
    pub fields: HashMap<String, String>,
}

/// A decrypted vault snapshot: items plus an organization-name index.
#[derive(Debug, Clone, Default)]
pub struct VaultCache {
    pub items: Vec<DecryptedItem>,
    /// Lowercased organization name -> org ids. More than one id means the
    /// name is ambiguous. Includes orgs whose key failed to decrypt (their
    /// items are absent, so scoped lookups report "not found in vault").
    pub orgs_by_name: HashMap<String, Vec<String>>,
}

/// Counts of ciphers dropped while decrypting a sync response, for diagnostics.
///
/// Neither case is visible to a scoped or unscoped lookup — the org still resolves
/// by name (`VaultCache::orgs_by_name`), it just has no items — so a caller logs
/// this alongside the decrypted item count to distinguish "cache is broken" from
/// "the name is simply wrong".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DecryptSkips {
    /// Ciphers skipped because their organization's key was missing or failed to decrypt.
    pub no_org_key: usize,
    /// Ciphers skipped because the cipher itself failed to decrypt (e.g. bad name field).
    pub decrypt_failed: usize,
}

impl DecryptSkips {
    pub fn total(&self) -> usize {
        self.no_org_key + self.decrypt_failed
    }
}

/// Errors from a vault-scoped item lookup.
#[derive(Debug, Error)]
pub enum LookupError {
    #[error("vault (organization) {0:?} not found")]
    VaultNotFound(String),
    #[error("vault name {0:?} matches multiple organizations; use a unique name")]
    VaultAmbiguous(String),
    #[error("secret {name:?} not found in vault {vault:?} ({searched} items searched)")]
    NotFoundInVault {
        name: String,
        vault: String,
        searched: usize,
    },
    #[error("secret {name:?} not found in vault cache ({searched} items searched)")]
    NotFound { name: String, searched: usize },
}

impl LookupError {
    /// Whether this error indicates the cache may simply be stale (item recently
    /// created/moved, organization recently added) rather than a permanent
    /// configuration problem. Staleness-class errors are worth retrying after an
    /// on-demand re-sync; `VaultAmbiguous` is a naming conflict that a re-sync
    /// cannot fix.
    pub fn is_stale_miss(&self) -> bool {
        !matches!(self, LookupError::VaultAmbiguous(_))
    }
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

/// Build the case-insensitive organization-name index for a vault cache.
pub fn index_orgs(orgs: &[SyncOrganization]) -> HashMap<String, Vec<String>> {
    let mut by_name: HashMap<String, Vec<String>> = HashMap::new();
    for org in orgs {
        by_name
            .entry(org.name.to_lowercase())
            .or_default()
            .push(org.id.clone());
    }
    by_name
}

/// Decrypt all ciphers in a sync response using the user's symmetric key
/// and any organisation keys derived from the user's RSA private key.
///
/// Returns the cache alongside counts of ciphers that were silently dropped, so
/// callers can log a summary instead of leaving misses undiagnosable.
pub fn decrypt_vault(sync: &SyncResponse, sym_key: &SymmetricKey) -> (VaultCache, DecryptSkips) {
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
                debug!(count = org_keys.len(), "decrypted org keys");
            }
            Err(e) => {
                warn!(err = %e, "failed to decrypt RSA private key; org items will be skipped")
            }
        }
    }

    let mut items = Vec::with_capacity(sync.ciphers.len());
    let mut skips = DecryptSkips::default();
    for cipher in &sync.ciphers {
        let key = if let Some(org_id) = &cipher.organization_id {
            if org_id.is_empty() {
                sym_key
            } else if let Some(k) = org_keys.get(org_id.as_str()) {
                k
            } else {
                debug!(cipher_id = %cipher.id, org_id = %org_id, "no org key; skipping cipher");
                skips.no_org_key += 1;
                continue;
            }
        } else {
            sym_key
        };

        match decrypt_cipher(cipher, key) {
            Ok(item) => items.push(item),
            Err(e) => {
                debug!(cipher_id = %cipher.id, err = %e, "failed to decrypt cipher; skipping");
                skips.decrypt_failed += 1;
            }
        }
    }

    if skips.total() > 0 {
        warn!(
            no_org_key = skips.no_org_key,
            decrypt_failed = skips.decrypt_failed,
            decrypted = items.len(),
            total_ciphers = sync.ciphers.len(),
            "some ciphers were dropped while decrypting the vault; \
             affected organizations' items will report as \"not found\""
        );
    }
    debug!(count = items.len(), "decrypted vault items");

    let cache = VaultCache {
        items,
        orgs_by_name: index_orgs(&sync.profile.organizations),
    };
    (cache, skips)
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
        organization_id: cipher.organization_id.clone().filter(|id| !id.is_empty()),
        name,
        username,
        password,
        notes,
        uri,
        fields,
    })
}

/// Search `items` for `name`, optionally restricted to one organization.
///
/// Priority:
/// 1. Exact case-insensitive match.
/// 2. Substring (partial) match.
///
/// With `org_id = None`, items from the personal vault and all organizations
/// match (legacy behavior). With `org_id = Some(..)`, only items owned by
/// that organization match.
pub fn find_item<'a>(
    items: &'a [DecryptedItem],
    name: &str,
    org_id: Option<&str>,
) -> Option<&'a DecryptedItem> {
    let key = name.to_lowercase();
    let in_scope =
        |item: &DecryptedItem| org_id.is_none_or(|id| item.organization_id.as_deref() == Some(id));

    // Exact match.
    for item in items {
        if in_scope(item) && item.name.to_lowercase() == key {
            return Some(item);
        }
    }

    // Partial match.
    for item in items {
        if in_scope(item) && item.name.to_lowercase().contains(&key) {
            debug!("partial match found for secret lookup");
            return Some(item);
        }
    }

    None
}

/// Look up `name` in the cache, scoped to `vault` (an organization name,
/// case-insensitive) when given.
///
/// A scoped lookup never falls back to other vaults or the personal vault:
/// a miss inside the named organization is an error. Note that an
/// organization whose key failed to decrypt still resolves by name; its
/// items are simply absent, so lookups report `NotFoundInVault`.
pub fn lookup_item<'a>(
    cache: &'a VaultCache,
    name: &str,
    vault: Option<&str>,
) -> Result<&'a DecryptedItem, LookupError> {
    match vault {
        Some(v) => {
            let org_ids = cache
                .orgs_by_name
                .get(&v.to_lowercase())
                .ok_or_else(|| LookupError::VaultNotFound(v.to_string()))?;
            if org_ids.len() > 1 {
                return Err(LookupError::VaultAmbiguous(v.to_string()));
            }
            find_item(&cache.items, name, Some(&org_ids[0])).ok_or_else(|| {
                LookupError::NotFoundInVault {
                    name: name.to_string(),
                    vault: v.to_string(),
                    searched: cache.items.len(),
                }
            })
        }
        None => find_item(&cache.items, name, None).ok_or_else(|| LookupError::NotFound {
            name: name.to_string(),
            searched: cache.items.len(),
        }),
    }
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
        assert_eq!(item.organization_id.as_deref(), Some("org-123"));
    }

    #[test]
    fn test_decrypt_cipher_empty_org_id_normalized() {
        let (key, enc_key, mac_key) = make_key();
        let iv = [0u8; 16];

        let cipher = SyncCipher {
            id: "empty-org-1".to_string(),
            cipher_type: CIPHER_TYPE_SECURE_NOTE,
            organization_id: Some(String::new()),
            name: encrypt_type2(&enc_key, &mac_key, &iv, b"X"),
            notes: None,
            login: None,
            card: None,
            fields: vec![],
        };

        let item = decrypt_cipher(&cipher, &key).unwrap();
        assert_eq!(item.organization_id, None);
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
        assert_eq!(item.organization_id, None);
    }

    fn make_item(name: &str, org_id: Option<&str>) -> DecryptedItem {
        DecryptedItem {
            id: format!("id-{name}-{}", org_id.unwrap_or("personal")),
            cipher_type: 1,
            organization_id: org_id.map(str::to_string),
            name: name.into(),
            username: String::new(),
            password: format!("pw-{name}-{}", org_id.unwrap_or("personal")),
            notes: String::new(),
            uri: String::new(),
            fields: HashMap::new(),
        }
    }

    #[test]
    fn test_find_item_exact() {
        let items = vec![make_item("MySecret", None), make_item("OtherSecret", None)];

        let found = find_item(&items, "mysecret", None).unwrap();
        assert_eq!(found.name, "MySecret");
    }

    #[test]
    fn test_find_item_partial() {
        let items = vec![make_item("Production API Key", None)];

        let found = find_item(&items, "api key", None).unwrap();
        assert_eq!(found.name, "Production API Key");
    }

    #[test]
    fn test_find_item_not_found() {
        let items: Vec<DecryptedItem> = vec![];
        assert!(find_item(&items, "missing", None).is_none());
    }

    #[test]
    fn test_find_item_org_filter_selects_right_copy() {
        let items = vec![
            make_item("shared-name", Some("org-a")),
            make_item("shared-name", Some("org-b")),
            make_item("shared-name", None),
        ];

        let found = find_item(&items, "shared-name", Some("org-b")).unwrap();
        assert_eq!(found.password, "pw-shared-name-org-b");
    }

    #[test]
    fn test_find_item_org_filter_excludes_personal() {
        let items = vec![make_item("only-personal", None)];
        assert!(find_item(&items, "only-personal", Some("org-a")).is_none());
    }

    #[test]
    fn test_find_item_no_filter_matches_org_items() {
        let items = vec![make_item("org-item", Some("org-a"))];
        assert!(find_item(&items, "org-item", None).is_some());
    }

    #[test]
    fn test_find_item_exact_beats_partial_within_scope() {
        let items = vec![
            make_item("api key extended", Some("org-a")),
            make_item("api key", Some("org-a")),
        ];

        let found = find_item(&items, "api key", Some("org-a")).unwrap();
        assert_eq!(found.name, "api key");
    }

    fn org(id: &str, name: &str) -> SyncOrganization {
        SyncOrganization {
            id: id.into(),
            name: name.into(),
            key: String::new(),
        }
    }

    #[test]
    fn test_index_orgs_case_insensitive() {
        let index = index_orgs(&[org("org-1", "Kubernetes - Apollo")]);
        assert_eq!(
            index.get("kubernetes - apollo"),
            Some(&vec!["org-1".to_string()])
        );
    }

    #[test]
    fn test_index_orgs_duplicate_names() {
        let index = index_orgs(&[org("org-1", "Shared"), org("org-2", "shared")]);
        assert_eq!(index.get("shared").map(Vec::len), Some(2));
    }

    fn make_cache() -> VaultCache {
        VaultCache {
            items: vec![
                make_item("shared-name", Some("org-a")),
                make_item("shared-name", None),
                make_item("only-in-b", Some("org-b")),
            ],
            orgs_by_name: index_orgs(&[
                org("org-a", "Kubernetes - Apollo"),
                org("org-b", "Kubernetes - Common"),
                org("dup-1", "Duplicated"),
                org("dup-2", "Duplicated"),
            ]),
        }
    }

    #[test]
    fn test_lookup_item_scoped_success() {
        let cache = make_cache();
        let item = lookup_item(&cache, "shared-name", Some("kubernetes - apollo")).unwrap();
        assert_eq!(item.password, "pw-shared-name-org-a");
    }

    #[test]
    fn test_lookup_item_unscoped_success() {
        let cache = make_cache();
        assert!(lookup_item(&cache, "only-in-b", None).is_ok());
    }

    #[test]
    fn test_lookup_item_vault_not_found() {
        let cache = make_cache();
        let err = lookup_item(&cache, "shared-name", Some("no-such-org")).unwrap_err();
        assert!(matches!(err, LookupError::VaultNotFound(_)), "{err}");
    }

    #[test]
    fn test_lookup_item_vault_ambiguous() {
        let cache = make_cache();
        let err = lookup_item(&cache, "shared-name", Some("Duplicated")).unwrap_err();
        assert!(matches!(err, LookupError::VaultAmbiguous(_)), "{err}");
    }

    #[test]
    fn test_lookup_item_no_fallback_across_vaults() {
        // "only-in-b" exists in org-b; a lookup scoped to org-a must fail
        // rather than fall back to another vault that has the name.
        let cache = make_cache();
        let err = lookup_item(&cache, "only-in-b", Some("Kubernetes - Apollo")).unwrap_err();
        assert!(matches!(err, LookupError::NotFoundInVault { .. }), "{err}");
    }

    #[test]
    fn test_lookup_item_unscoped_not_found() {
        let cache = make_cache();
        let err = lookup_item(&cache, "missing", None).unwrap_err();
        assert!(matches!(err, LookupError::NotFound { .. }), "{err}");
    }

    #[test]
    fn test_is_stale_miss_classification() {
        assert!(LookupError::NotFound {
            name: "x".into(),
            searched: 0
        }
        .is_stale_miss());
        assert!(LookupError::NotFoundInVault {
            name: "x".into(),
            vault: "v".into(),
            searched: 0
        }
        .is_stale_miss());
        assert!(LookupError::VaultNotFound("v".into()).is_stale_miss());
        assert!(!LookupError::VaultAmbiguous("v".into()).is_stale_miss());
    }

    #[test]
    fn test_decrypt_vault_counts_missing_org_key_skips() {
        let (personal_key, _, _) = make_key();
        let iv = [7u8; 16];
        let org_id = "org-missing-key".to_string();

        let enc_name = encrypt_type2(&[9u8; 32], &[9u8; 32], &iv, b"ORPHANED");
        let cipher = SyncCipher {
            id: "cipher-orphan".to_string(),
            cipher_type: CIPHER_TYPE_LOGIN,
            organization_id: Some(org_id.clone()),
            name: enc_name,
            notes: None,
            login: None,
            card: None,
            fields: vec![],
        };

        let sync = SyncResponse {
            profile: SyncProfile {
                id: "u1".into(),
                email: "u@example.com".into(),
                key: String::new(),
                private_key: String::new(),
                organizations: vec![org(&org_id, "Orphaned Org")],
            },
            ciphers: vec![cipher],
        };

        let (cache, skips) = decrypt_vault(&sync, &personal_key);
        assert_eq!(skips.no_org_key, 1);
        assert_eq!(skips.decrypt_failed, 0);
        assert_eq!(skips.total(), 1);
        assert!(cache.items.is_empty());
        // The org still resolves by name even though its items were dropped.
        assert!(cache.orgs_by_name.contains_key("orphaned org"));
    }

    #[test]
    fn test_extract_secret_password_priority() {
        let item = DecryptedItem {
            id: "1".into(),
            cipher_type: 1,
            organization_id: None,
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
            organization_id: None,
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
            organization_id: None,
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
