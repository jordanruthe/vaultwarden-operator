//! Bitwarden-compatible encryption and decryption.
#![allow(dead_code)]
//!
//! Faithfully ports the Go crypto.go from the Vaultwarden-API project so that
//! vault sessions created by either implementation are interoperable.

use aes::Aes256;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use cbc::cipher::{BlockDecryptMut, KeyIvInit};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;
use sha1::Sha1;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use thiserror::Error;

type Aes256CbcDec = cbc::Decryptor<Aes256>;
type HmacSha256 = Hmac<Sha256>;

/// Bitwarden encryption type constants.
pub const ENC_TYPE_AES_CBC256_B64: u8 = 0;
pub const ENC_TYPE_AES_CBC256_HMAC_SHA256_B64: u8 = 2;
pub const ENC_TYPE_RSA2048_OAEP_SHA256_B64: u8 = 3;
pub const ENC_TYPE_RSA2048_OAEP_SHA1_B64: u8 = 4;

/// KDF type constants.
pub const KDF_PBKDF2: u32 = 0;
pub const KDF_ARGON2ID: u32 = 1;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("empty cipher string")]
    Empty,
    #[error("invalid cipher string format: {0}")]
    Format(String),
    #[error("unsupported encryption type: {0}")]
    UnsupportedType(u8),
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid IV length: expected 16, got {0}")]
    InvalidIv(usize),
    #[error("invalid ciphertext length: {0}")]
    InvalidCiphertext(usize),
    #[error("MAC key required for type 2 decryption")]
    MacKeyMissing,
    #[error("MAC verification failed")]
    MacMismatch,
    #[error("PKCS7 unpad error: {0}")]
    Pkcs7(String),
    #[error("not an RSA cipher type: {0}")]
    NotRsa(u8),
    #[error("RSA decrypt error: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("PKCS8 parse error: {0}")]
    Pkcs8(String),
    #[error("private key is not RSA")]
    NotRsaKey,
    #[error("unexpected org key length: expected 64, got {0}")]
    OrgKeyLength(usize),
    #[error("unexpected symmetric key length: expected 64, got {0}")]
    SymKeyLength(usize),
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("HKDF expand error")]
    Hkdf,
    #[error("empty encrypted key")]
    EmptyKey,
}

/// AES-256 symmetric key: 32-byte enc key + 32-byte MAC key.
#[derive(Clone, Debug, Default)]
pub struct SymmetricKey {
    pub enc_key: Vec<u8>,
    pub mac_key: Vec<u8>,
}

/// A parsed Bitwarden cipher string.
///
/// AES format:  `<type>.<iv_b64>|<ct_b64>|<mac_b64>`  (type 2)
///              `<type>.<iv_b64>|<ct_b64>`             (type 0)
/// RSA format:  `<type>.<ct_b64>`                      (types 3, 4)
#[derive(Debug)]
pub struct CipherString {
    pub enc_type: u8,
    pub iv: Vec<u8>,
    pub ct: Vec<u8>,
    pub mac: Vec<u8>,
}

impl CipherString {
    /// Parse a Bitwarden cipher string.
    pub fn parse(s: &str) -> Result<Self, CryptoError> {
        if s.is_empty() {
            return Err(CryptoError::Empty);
        }

        let (type_str, rest) = s
            .split_once('.')
            .ok_or_else(|| CryptoError::Format("missing type separator".into()))?;

        let enc_type: u8 = type_str
            .parse()
            .map_err(|_| CryptoError::Format(format!("invalid type: {type_str}")))?;

        match enc_type {
            ENC_TYPE_AES_CBC256_B64 => {
                // Format: iv|ct
                let parts: Vec<&str> = rest.splitn(3, '|').collect();
                if parts.len() != 2 {
                    return Err(CryptoError::Format(format!(
                        "AesCbc256_B64 expects 2 parts, got {}",
                        parts.len()
                    )));
                }
                Ok(CipherString {
                    enc_type,
                    iv: BASE64.decode(parts[0])?,
                    ct: BASE64.decode(parts[1])?,
                    mac: vec![],
                })
            }
            ENC_TYPE_AES_CBC256_HMAC_SHA256_B64 => {
                // Format: iv|ct|mac
                let parts: Vec<&str> = rest.splitn(4, '|').collect();
                if parts.len() != 3 {
                    return Err(CryptoError::Format(format!(
                        "AesCbc256_HmacSha256_B64 expects 3 parts, got {}",
                        parts.len()
                    )));
                }
                Ok(CipherString {
                    enc_type,
                    iv: BASE64.decode(parts[0])?,
                    ct: BASE64.decode(parts[1])?,
                    mac: BASE64.decode(parts[2])?,
                })
            }
            ENC_TYPE_RSA2048_OAEP_SHA256_B64 | ENC_TYPE_RSA2048_OAEP_SHA1_B64 => {
                // Format: ct only — rejoin any stray pipes (shouldn't occur but matches Go)
                let raw = rest.replace('|', "");
                Ok(CipherString {
                    enc_type,
                    iv: vec![],
                    ct: BASE64.decode(&raw)?,
                    mac: vec![],
                })
            }
            t => Err(CryptoError::UnsupportedType(t)),
        }
    }

    /// Decrypt using a symmetric key (AES-CBC). Verifies HMAC when present (type 2).
    pub fn decrypt(&self, key: &SymmetricKey) -> Result<Vec<u8>, CryptoError> {
        if self.iv.len() != 16 {
            return Err(CryptoError::InvalidIv(self.iv.len()));
        }
        if self.ct.is_empty() || !self.ct.len().is_multiple_of(16) {
            return Err(CryptoError::InvalidCiphertext(self.ct.len()));
        }

        // Verify HMAC for type 2.
        if self.enc_type == ENC_TYPE_AES_CBC256_HMAC_SHA256_B64 {
            if key.mac_key.is_empty() {
                return Err(CryptoError::MacKeyMissing);
            }
            let mut mac =
                HmacSha256::new_from_slice(&key.mac_key).expect("HMAC accepts any key size");
            mac.update(&self.iv);
            mac.update(&self.ct);
            let expected = mac.finalize().into_bytes();
            if expected.ct_eq(&self.mac[..]).unwrap_u8() != 1 {
                return Err(CryptoError::MacMismatch);
            }
        }

        // AES-256-CBC decrypt.
        let enc_key: &[u8; 32] = key
            .enc_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::Format("enc_key must be 32 bytes".into()))?;
        let iv: &[u8; 16] = self
            .iv
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidIv(self.iv.len()))?;

        let mut buf = self.ct.clone();
        Aes256CbcDec::new(enc_key.into(), iv.into())
            .decrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut buf)
            .map_err(|e| CryptoError::Format(format!("AES-CBC decrypt: {e}")))?;

        pkcs7_unpad(&buf, 16)
    }

    /// Decrypt to a UTF-8 string.
    pub fn decrypt_to_string(&self, key: &SymmetricKey) -> Result<String, CryptoError> {
        let bytes = self.decrypt(key)?;
        String::from_utf8(bytes).map_err(|e| CryptoError::Format(format!("UTF-8 decode: {e}")))
    }

    /// Decrypt using an RSA private key (OAEP). Supports types 3 (SHA-256) and 4 (SHA-1).
    pub fn decrypt_rsa(&self, private_key: &RsaPrivateKey) -> Result<Vec<u8>, CryptoError> {
        use rsa::Oaep;
        match self.enc_type {
            ENC_TYPE_RSA2048_OAEP_SHA256_B64 => {
                let padding = Oaep::new::<Sha256>();
                private_key
                    .decrypt(padding, &self.ct)
                    .map_err(CryptoError::Rsa)
            }
            ENC_TYPE_RSA2048_OAEP_SHA1_B64 => {
                let padding = Oaep::new::<Sha1>();
                private_key
                    .decrypt(padding, &self.ct)
                    .map_err(CryptoError::Rsa)
            }
            t => Err(CryptoError::NotRsa(t)),
        }
    }
}

/// Parse and decrypt a Bitwarden cipher string in one call.
/// Returns an empty string for empty input (matches Go `DecryptStr`).
pub fn decrypt_str(s: &str, key: &SymmetricKey) -> Result<String, CryptoError> {
    if s.is_empty() {
        return Ok(String::new());
    }
    CipherString::parse(s)?.decrypt_to_string(key)
}

/// Derive the Bitwarden master key from password + email using the server-specified KDF.
///
/// - PBKDF2: PBKDF2-HMAC-SHA256; salt = lowercase-trimmed email.
/// - Argon2id: memory in MiB from server → converted to KiB; defaults 64 MiB / parallelism 4.
pub fn make_master_key(
    password: &str,
    email: &str,
    kdf_type: u32,
    iterations: u32,
    memory_mib: Option<u32>,
    parallelism: Option<u32>,
) -> Result<Vec<u8>, CryptoError> {
    let salt = email.trim().to_lowercase();

    match kdf_type {
        KDF_PBKDF2 => {
            if iterations < 1 {
                return Err(CryptoError::Kdf(format!(
                    "PBKDF2 iterations must be >= 1, got {iterations}"
                )));
            }
            use pbkdf2::pbkdf2_hmac;
            let mut key = vec![0u8; 32];
            pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, &mut key);
            Ok(key)
        }
        KDF_ARGON2ID => {
            let mem_kib = memory_mib.unwrap_or(64) * 1024; // MiB → KiB
            let par = parallelism.unwrap_or(4);
            use argon2::{Algorithm, Argon2, Params, Version};
            let params = Params::new(mem_kib, iterations, par, Some(32))
                .map_err(|e| CryptoError::Kdf(format!("argon2 params: {e}")))?;
            let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = vec![0u8; 32];
            argon2
                .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
                .map_err(|e| CryptoError::Kdf(format!("argon2 hash: {e}")))?;
            Ok(key)
        }
        t => Err(CryptoError::Kdf(format!("unsupported KDF type: {t}"))),
    }
}

/// Hash a password for Bitwarden authentication.
///
/// `hash = Base64(PBKDF2-HMAC-SHA256(masterKey, password, 1 iter, 32 bytes))`
pub fn hash_password(password: &str, master_key: &[u8]) -> String {
    use pbkdf2::pbkdf2_hmac;
    let mut hash = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(master_key, password.as_bytes(), 1, &mut hash);
    BASE64.encode(hash)
}

/// Expand a 32-byte master key into a 64-byte stretched key using HKDF-Expand-SHA256.
///
/// Returns `(enc_key[32], mac_key[32])` packed into a `SymmetricKey`.
pub fn stretch_key(master_key: &[u8]) -> Result<SymmetricKey, CryptoError> {
    let hk = Hkdf::<Sha256>::from_prk(master_key).map_err(|_| CryptoError::Hkdf)?;

    let mut enc_key = vec![0u8; 32];
    hk.expand(b"enc", &mut enc_key)
        .map_err(|_| CryptoError::Hkdf)?;

    let mut mac_key = vec![0u8; 32];
    hk.expand(b"mac", &mut mac_key)
        .map_err(|_| CryptoError::Hkdf)?;

    Ok(SymmetricKey { enc_key, mac_key })
}

/// Decrypt the user's encrypted symmetric key from the login response.
///
/// Tries HKDF-stretched master key first; falls back to legacy (master key used directly).
/// The decrypted result must be 64 bytes: `enc_key[0..32]` + `mac_key[32..64]`.
pub fn decrypt_symmetric_key(
    encrypted_key: &str,
    master_key: &[u8],
) -> Result<SymmetricKey, CryptoError> {
    if encrypted_key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }

    let cs = CipherString::parse(encrypted_key)?;

    // Try modern HKDF-stretched key first.
    let stretched = stretch_key(master_key)?;
    let decrypted = match cs.decrypt(&stretched) {
        Ok(d) => d,
        Err(_) => {
            // Legacy fallback: master key used directly as enc key (no MAC).
            let legacy = SymmetricKey {
                enc_key: master_key.to_vec(),
                mac_key: vec![],
            };
            cs.decrypt(&legacy).map_err(|_| {
                CryptoError::Format("decrypt symmetric key (tried stretched + legacy)".into())
            })?
        }
    };

    if decrypted.len() != 64 {
        return Err(CryptoError::SymKeyLength(decrypted.len()));
    }

    Ok(SymmetricKey {
        enc_key: decrypted[..32].to_vec(),
        mac_key: decrypted[32..].to_vec(),
    })
}

/// Decrypt the user's AES-encrypted RSA private key from the sync response.
///
/// The private key is AES-CBC encrypted with the user's symmetric key.
/// When decrypted it is a PKCS8 DER-encoded RSA private key.
pub fn decrypt_private_key(
    encrypted_private_key: &str,
    sym_key: &SymmetricKey,
) -> Result<RsaPrivateKey, CryptoError> {
    if encrypted_private_key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }

    let cs = CipherString::parse(encrypted_private_key)?;
    let der_bytes = cs.decrypt(sym_key)?;

    RsaPrivateKey::from_pkcs8_der(&der_bytes).map_err(|e| CryptoError::Pkcs8(e.to_string()))
}

/// Decrypt an organisation's symmetric key using the user's RSA private key.
///
/// The org key is RSA-OAEP encrypted. When decrypted it is 64 bytes:
/// `enc_key[0..32]` + `mac_key[32..64]`.
pub fn decrypt_org_key(
    encrypted_org_key: &str,
    private_key: &RsaPrivateKey,
) -> Result<SymmetricKey, CryptoError> {
    if encrypted_org_key.is_empty() {
        return Err(CryptoError::EmptyKey);
    }

    let cs = CipherString::parse(encrypted_org_key)?;
    let decrypted = cs.decrypt_rsa(private_key)?;

    if decrypted.len() != 64 {
        return Err(CryptoError::OrgKeyLength(decrypted.len()));
    }

    Ok(SymmetricKey {
        enc_key: decrypted[..32].to_vec(),
        mac_key: decrypted[32..].to_vec(),
    })
}

/// Remove PKCS#7 padding from a block-aligned buffer.
fn pkcs7_unpad(data: &[u8], block_size: usize) -> Result<Vec<u8>, CryptoError> {
    if data.is_empty() {
        return Err(CryptoError::Pkcs7("empty data".into()));
    }
    if !data.len().is_multiple_of(block_size) {
        return Err(CryptoError::Pkcs7("data not block-aligned".into()));
    }

    let pad_len = *data.last().unwrap() as usize;
    if pad_len == 0 || pad_len > block_size {
        return Err(CryptoError::Pkcs7(format!(
            "invalid padding length: {pad_len}"
        )));
    }

    let pad_start = data.len() - pad_len;
    if !data[pad_start..].iter().all(|&b| b as usize == pad_len) {
        return Err(CryptoError::Pkcs7("invalid PKCS7 padding bytes".into()));
    }

    Ok(data[..pad_start].to_vec())
}

// ---------------------------------------------------------------------------
// Tests — ported from crypto_test.go
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use aes::Aes256;
    use cbc::cipher::{BlockEncryptMut, KeyIvInit};
    use hmac::{Hmac, Mac};
    use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
    use sha2::Sha256;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;
    type HmacSha256 = Hmac<Sha256>;

    fn make_type2_cipherstring(
        enc_key: &[u8; 32],
        mac_key: &[u8; 32],
        iv: &[u8; 16],
        plaintext: &[u8],
    ) -> String {
        // PKCS7 pad
        let pad_len = 16 - (plaintext.len() % 16);
        let mut padded = plaintext.to_vec();
        padded.extend(std::iter::repeat_n(pad_len as u8, pad_len));

        // AES-256-CBC encrypt
        let mut ct = padded.clone();
        Aes256CbcEnc::new(enc_key.into(), iv.into())
            .encrypt_padded_mut::<cbc::cipher::block_padding::NoPadding>(&mut ct, padded.len())
            .unwrap();

        // HMAC-SHA256
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

    #[test]
    fn test_parse_cipher_string_type2() {
        let iv = [0u8; 16];
        let ct = [0u8; 32];
        let mac = [0u8; 32];
        let s = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode(ct),
            BASE64.encode(mac)
        );
        let cs = CipherString::parse(&s).unwrap();
        assert_eq!(cs.enc_type, 2);
        assert_eq!(cs.iv.len(), 16);
        assert_eq!(cs.ct.len(), 32);
        assert_eq!(cs.mac.len(), 32);
    }

    #[test]
    fn test_parse_cipher_string_type0() {
        let iv = [0u8; 16];
        let ct = [0u8; 32];
        let s = format!("0.{}|{}", BASE64.encode(iv), BASE64.encode(ct));
        let cs = CipherString::parse(&s).unwrap();
        assert_eq!(cs.enc_type, 0);
        assert!(cs.mac.is_empty());
    }

    #[test]
    fn test_parse_cipher_string_invalid() {
        assert!(CipherString::parse("").is_err());
        assert!(CipherString::parse("abcdef").is_err());
        assert!(CipherString::parse("x.abc|def|ghi").is_err());
        // type 2 missing mac
        assert!(CipherString::parse(&format!(
            "2.{}|{}",
            BASE64.encode([0u8; 16]),
            BASE64.encode([0u8; 32])
        ))
        .is_err());
        // unsupported type
        assert!(CipherString::parse(&format!(
            "5.{}|{}|{}",
            BASE64.encode([0u8; 16]),
            BASE64.encode([0u8; 32]),
            BASE64.encode([0u8; 32])
        ))
        .is_err());
    }

    #[test]
    fn test_pkcs7_unpad_1byte() {
        let input: Vec<u8> = vec![
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
            0x4F, 0x01,
        ];
        let result = pkcs7_unpad(&input, 16).unwrap();
        assert_eq!(result.len(), 15);
    }

    #[test]
    fn test_pkcs7_unpad_full_block() {
        let input = vec![0x10u8; 16];
        let result = pkcs7_unpad(&input, 16).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_pkcs7_unpad_empty() {
        assert!(pkcs7_unpad(&[], 16).is_err());
    }

    #[test]
    fn test_pkcs7_unpad_zero_padding_byte() {
        let mut input: Vec<u8> = vec![
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E,
            0x4F, 0x00,
        ];
        input[15] = 0x00;
        assert!(pkcs7_unpad(&input, 16).is_err());
    }

    #[test]
    fn test_decrypt_type2_round_trip() {
        let enc_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mac_key: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
        let iv: [u8; 16] = std::array::from_fn(|i| (i + 100) as u8);
        let key = SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };

        let s = make_type2_cipherstring(&enc_key, &mac_key, &iv, b"Hello, Vaultwarden!");
        let cs = CipherString::parse(&s).unwrap();
        let result = cs.decrypt_to_string(&key).unwrap();
        assert_eq!(result, "Hello, Vaultwarden!");
    }

    #[test]
    fn test_decrypt_mac_verification_fails() {
        let enc_key = [0u8; 32];
        let mac_key = [0u8; 32];
        let iv = [0u8; 16];
        let wrong_mac = [0xFFu8; 32];

        let s = format!(
            "2.{}|{}|{}",
            BASE64.encode(iv),
            BASE64.encode([0u8; 16]),
            BASE64.encode(wrong_mac)
        );
        let cs = CipherString::parse(&s).unwrap();
        let key = SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };
        let err = cs.decrypt(&key).unwrap_err();
        assert!(
            matches!(err, CryptoError::MacMismatch),
            "expected MacMismatch, got {err}"
        );
    }

    #[test]
    fn test_make_master_key_pbkdf2() {
        use pbkdf2::pbkdf2_hmac;
        let key = make_master_key(
            "password123",
            "user@example.com",
            KDF_PBKDF2,
            600000,
            None,
            None,
        )
        .unwrap();
        assert_eq!(key.len(), 32);

        let mut expected = vec![0u8; 32];
        pbkdf2_hmac::<Sha256>(b"password123", b"user@example.com", 600000, &mut expected);
        assert_eq!(key, expected);
    }

    #[test]
    fn test_make_master_key_argon2id() {
        let key = make_master_key(
            "password123",
            "user@example.com",
            KDF_ARGON2ID,
            3,
            Some(64),
            Some(4),
        )
        .unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_hash_password() {
        let master_key: Vec<u8> = (0..32).collect();
        let hash = hash_password("password123", &master_key);
        assert!(!hash.is_empty());
        // Must be valid base64.
        BASE64.decode(&hash).unwrap();
    }

    #[test]
    fn test_stretch_key() {
        let master_key: Vec<u8> = (0..32).collect();
        let sk = stretch_key(&master_key).unwrap();
        assert_eq!(sk.enc_key.len(), 32);
        assert_eq!(sk.mac_key.len(), 32);
        assert_ne!(sk.enc_key, sk.mac_key);
    }

    #[test]
    fn test_decrypt_str_empty() {
        let key = SymmetricKey::default();
        let result = decrypt_str("", &key).unwrap();
        assert_eq!(result, "");
    }

    #[test]
    fn test_parse_cipher_string_type3_rsa_sha256() {
        let ct = [0u8; 256]; // RSA-2048 ciphertext
        let s = format!("3.{}", BASE64.encode(ct));
        let cs = CipherString::parse(&s).unwrap();
        assert_eq!(cs.enc_type, ENC_TYPE_RSA2048_OAEP_SHA256_B64);
        assert_eq!(cs.ct.len(), 256);
        assert!(cs.iv.is_empty());
        assert!(cs.mac.is_empty());
    }

    #[test]
    fn test_parse_cipher_string_type4_rsa_sha1() {
        let ct = [0u8; 256];
        let s = format!("4.{}", BASE64.encode(ct));
        let cs = CipherString::parse(&s).unwrap();
        assert_eq!(cs.enc_type, ENC_TYPE_RSA2048_OAEP_SHA1_B64);
        assert_eq!(cs.ct.len(), 256);
    }

    #[test]
    fn test_decrypt_rsa_oaep_sha1_round_trip() {
        use rsa::{Oaep, RsaPublicKey};
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let org_key_plain: Vec<u8> = (0..64u8).collect();
        let padding = Oaep::new::<Sha1>();
        let ciphertext = public_key
            .encrypt(&mut rng, padding, &org_key_plain)
            .unwrap();

        let s = format!("4.{}", BASE64.encode(&ciphertext));
        let cs = CipherString::parse(&s).unwrap();
        let decrypted = cs.decrypt_rsa(&private_key).unwrap();
        assert_eq!(decrypted.len(), 64);
        assert_eq!(decrypted, org_key_plain);
    }

    #[test]
    fn test_decrypt_rsa_oaep_sha256_round_trip() {
        use rsa::{Oaep, RsaPublicKey};
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        let plaintext = b"Hello RSA-OAEP-SHA256!";
        let padding = Oaep::new::<Sha256>();
        let ciphertext = public_key.encrypt(&mut rng, padding, plaintext).unwrap();

        let s = format!("3.{}", BASE64.encode(&ciphertext));
        let cs = CipherString::parse(&s).unwrap();
        let decrypted = cs.decrypt_rsa(&private_key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_rsa_wrong_type() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let cs = CipherString {
            enc_type: ENC_TYPE_AES_CBC256_HMAC_SHA256_B64,
            iv: vec![],
            ct: b"test".to_vec(),
            mac: vec![],
        };
        assert!(matches!(
            cs.decrypt_rsa(&private_key),
            Err(CryptoError::NotRsa(2))
        ));
    }

    #[test]
    fn test_decrypt_private_key_round_trip() {
        use rsa::traits::PublicKeyParts;
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let der_bytes = private_key.to_pkcs8_der().unwrap();

        let enc_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mac_key: [u8; 32] = std::array::from_fn(|i| (i + 32) as u8);
        let iv: [u8; 16] = std::array::from_fn(|i| (i + 100) as u8);
        let sym_key = SymmetricKey {
            enc_key: enc_key.to_vec(),
            mac_key: mac_key.to_vec(),
        };

        let s = make_type2_cipherstring(&enc_key, &mac_key, &iv, der_bytes.as_bytes());
        let decrypted_key = decrypt_private_key(&s, &sym_key).unwrap();
        assert_eq!(decrypted_key.n(), private_key.n());
    }

    #[test]
    fn test_decrypt_private_key_empty() {
        let key = SymmetricKey::default();
        assert!(matches!(
            decrypt_private_key("", &key),
            Err(CryptoError::EmptyKey)
        ));
    }

    #[test]
    fn test_decrypt_org_key_round_trip() {
        use rsa::{Oaep, RsaPublicKey};
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        // 64-byte org key: enc[0..32] + mac[32..64]
        let mut org_key_plain = vec![0u8; 64];
        for i in 0..32usize {
            org_key_plain[i] = i as u8;
            org_key_plain[32 + i] = (i + 64) as u8;
        }

        let padding = Oaep::new::<Sha1>();
        let ciphertext = public_key
            .encrypt(&mut rng, padding, &org_key_plain)
            .unwrap();
        let s = format!("4.{}", BASE64.encode(&ciphertext));

        let org_key = decrypt_org_key(&s, &private_key).unwrap();
        for i in 0..32usize {
            assert_eq!(org_key.enc_key[i], i as u8);
            assert_eq!(org_key.mac_key[i], (i + 64) as u8);
        }
    }

    #[test]
    fn test_decrypt_org_key_empty() {
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        assert!(matches!(
            decrypt_org_key("", &private_key),
            Err(CryptoError::EmptyKey)
        ));
    }

    #[test]
    fn test_decrypt_org_key_wrong_length() {
        use rsa::{Oaep, RsaPublicKey};
        let mut rng = rand::thread_rng();
        let private_key = RsaPrivateKey::new(&mut rng, 2048).unwrap();
        let public_key = RsaPublicKey::from(&private_key);

        // Only 32 bytes (should be 64).
        let short = vec![0u8; 32];
        let padding = Oaep::new::<Sha1>();
        let ct = public_key.encrypt(&mut rng, padding, &short).unwrap();
        let s = format!("4.{}", BASE64.encode(&ct));

        assert!(matches!(
            decrypt_org_key(&s, &private_key),
            Err(CryptoError::OrgKeyLength(32))
        ));
    }
}
