//! Vaultwarden authentication: prelogin, password/API-key grants, and token refresh.

use reqwest::Client as HttpClient;
use serde::Deserialize;
use thiserror::Error;
use tracing::{debug, info};

use super::crypto::{
    decrypt_symmetric_key, hash_password, make_master_key, CryptoError, SymmetricKey,
};

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
    #[error("server returned {status}: {body}")]
    Server { status: u16, body: String },
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("no refresh token available")]
    NoRefreshToken,
    #[error("profile key is empty")]
    EmptyProfileKey,
}

/// KDF parameters returned by `/identity/accounts/prelogin`.
#[derive(Debug, Deserialize)]
pub struct PreloginResponse {
    pub kdf: u32,
    #[serde(rename = "kdfIterations")]
    pub kdf_iterations: u32,
    #[serde(rename = "kdfMemory")]
    pub kdf_memory: Option<u32>,
    #[serde(rename = "kdfParallelism")]
    pub kdf_parallelism: Option<u32>,
}

/// Token response from `/identity/connect/token`.
#[derive(Debug, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub refresh_token: String,
    /// Encrypted user symmetric key (absent for API-key / client_credentials grant).
    #[serde(rename = "Key", default)]
    pub key: String,
}

/// Minimal sync response used to fetch the profile key when `TokenResponse.key` is absent.
#[derive(Debug, Deserialize)]
pub struct ProfileKeyResponse {
    pub profile: ProfileKeyProfile,
}

#[derive(Debug, Deserialize)]
pub struct ProfileKeyProfile {
    pub key: String,
}

/// Perform the prelogin request and return KDF parameters.
pub async fn prelogin(
    http: &HttpClient,
    base_url: &str,
    email: &str,
) -> Result<PreloginResponse, AuthError> {
    let url = format!("{base_url}/identity/accounts/prelogin");
    let body = serde_json::json!({ "email": email });

    let resp = http.post(&url).json(&body).send().await?;
    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::Server { status, body });
    }

    Ok(resp.json::<PreloginResponse>().await?)
}

/// Full authentication flow.
///
/// 1. Prelogin → KDF params.
/// 2. Derive master key.
/// 3. Login (password or API-key grant).
/// 4. If the token response has no `Key`, fetch from `/api/sync`.
/// 5. Decrypt the symmetric key.
///
/// Returns `(access_token, refresh_token, token_expiry_secs, symmetric_key)`.
pub async fn authenticate(
    http: &HttpClient,
    base_url: &str,
    email: &str,
    password: &str,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    device_id: &str,
) -> Result<(String, String, u64, SymmetricKey), AuthError> {
    // Step 1: KDF params.
    let pre = prelogin(http, base_url, email).await?;
    info!(
        kdf_type = pre.kdf,
        iterations = pre.kdf_iterations,
        "prelogin OK"
    );

    // Step 2: Master key.
    let master_key = make_master_key(
        password,
        email,
        pre.kdf,
        pre.kdf_iterations,
        pre.kdf_memory,
        pre.kdf_parallelism,
    )?;

    // Step 3: Login.
    let token_resp = if let (Some(id), Some(secret)) = (client_id, client_secret) {
        info!("using API-key (client_credentials) grant");
        login_with_api_key(http, base_url, id, secret, device_id).await?
    } else {
        let hashed = hash_password(password, &master_key);
        login_with_password(http, base_url, email, &hashed, device_id).await?
    };

    // Step 4: Encrypted symmetric key.
    let enc_key = if token_resp.key.is_empty() {
        info!("fetching profile key from /api/sync (API-key grant)");
        fetch_profile_key(http, base_url, &token_resp.access_token).await?
    } else {
        token_resp.key.clone()
    };

    // Step 5: Decrypt symmetric key.
    let sym_key = decrypt_symmetric_key(&enc_key, &master_key)?;
    info!("authentication successful");

    Ok((
        token_resp.access_token,
        token_resp.refresh_token,
        token_resp.expires_in,
        sym_key,
    ))
}

/// Refresh the access token using the stored refresh token.
///
/// Returns `(new_access_token, new_refresh_token_if_rotated, expires_in_secs)`.
pub async fn refresh_token(
    http: &HttpClient,
    base_url: &str,
    refresh_tok: &str,
) -> Result<(String, Option<String>, u64), AuthError> {
    if refresh_tok.is_empty() {
        return Err(AuthError::NoRefreshToken);
    }

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_tok),
        ("client_id", "web"),
    ];

    let resp = http
        .post(format!("{base_url}/identity/connect/token"))
        .form(&params)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::Server { status, body });
    }

    let tok: TokenResponse = resp.json().await?;
    debug!("token refreshed successfully");
    let new_rt = if tok.refresh_token.is_empty() {
        None
    } else {
        Some(tok.refresh_token)
    };
    Ok((tok.access_token, new_rt, tok.expires_in))
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn login_with_password(
    http: &HttpClient,
    base_url: &str,
    email: &str,
    hashed_password: &str,
    device_id: &str,
) -> Result<TokenResponse, AuthError> {
    let params = [
        ("grant_type", "password"),
        ("username", email),
        ("password", hashed_password),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "14"),
        ("deviceIdentifier", device_id),
        ("deviceName", "vaultwarden-operator"),
    ];
    do_token_request(http, base_url, &params).await
}

async fn login_with_api_key(
    http: &HttpClient,
    base_url: &str,
    client_id: &str,
    client_secret: &str,
    device_id: &str,
) -> Result<TokenResponse, AuthError> {
    let params = [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "api"),
        ("deviceType", "14"),
        ("deviceIdentifier", device_id),
        ("deviceName", "vaultwarden-operator"),
    ];
    do_token_request(http, base_url, &params).await
}

async fn do_token_request(
    http: &HttpClient,
    base_url: &str,
    params: &[(&str, &str)],
) -> Result<TokenResponse, AuthError> {
    let resp = http
        .post(format!("{base_url}/identity/connect/token"))
        .form(params)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::Server { status, body });
    }

    Ok(resp.json::<TokenResponse>().await?)
}

async fn fetch_profile_key(
    http: &HttpClient,
    base_url: &str,
    access_token: &str,
) -> Result<String, AuthError> {
    let resp = http
        .get(format!("{base_url}/api/sync"))
        .bearer_auth(access_token)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        return Err(AuthError::Server { status, body });
    }

    let r: ProfileKeyResponse = resp.json().await?;
    if r.profile.key.is_empty() {
        return Err(AuthError::EmptyProfileKey);
    }
    Ok(r.profile.key)
}
