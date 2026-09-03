//! Vaultwarden client: authentication, cached vault sync, and secret lookup.
//!
//! `VaultClient` is the central shared state. It holds the authenticated session
//! (tokens, symmetric key) and a cache of decrypted vault items. It exposes
//! `fetch_secrets` to the controller and runs background tasks for:
//! - `start_token_refresh` — proactively refreshes the access token before expiry.
//! - `start_vault_cache_refresh` — periodically re-syncs the whole vault.

pub mod auth;
pub mod crypto;
pub mod sync;

use std::{sync::Arc, time::Duration};

use reqwest::Client as HttpClient;
use thiserror::Error;
use tokio::sync::RwLock;
use tokio::time::{self, Instant};
use tracing::{debug, info, warn};
use uuid::Uuid;

use auth::{authenticate, refresh_token, AuthError};
use crypto::SymmetricKey;
use sync::{decrypt_vault, extract_secret, fetch_sync, lookup_item, LookupError, SyncError};

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("auth error: {0}")]
    Auth(#[from] AuthError),
    #[error("sync error: {0}")]
    Sync(#[from] SyncError),
    #[error("{0}")]
    Lookup(#[from] LookupError),
    #[error("vault not yet initialized")]
    NotInitialized,
}

/// One vault lookup: an item name plus an optional vault (organization) scope.
#[derive(Debug, Clone)]
pub struct SecretRequest {
    pub name: String,
    /// Organization name to scope the search to; `None` = whole account.
    pub vault: Option<String>,
}

/// Shared session state protected by a readers-writer lock.
struct Session {
    access_token: String,
    refresh_token: String,
    /// Absolute instant when the access token expires.
    token_expires_at: Instant,
    sym_key: SymmetricKey,
    /// The decrypted vault cache. `None` until the first successful sync.
    vault: Option<sync::VaultCache>,
    /// When the vault cache was last successfully refreshed (by either the
    /// background timer or an on-demand refresh-on-miss).
    last_refresh_at: Instant,
}

/// The shared Vaultwarden client.
///
/// Clone cheaply — the inner state is `Arc`-wrapped.
#[derive(Clone)]
pub struct VaultClient {
    inner: Arc<RwLock<Session>>,
    http: HttpClient,
    base_url: String,
    email: String,
    password: String,
    client_id: Option<String>,
    client_secret: Option<String>,
    device_id: String,
    /// Serializes on-demand refreshes triggered by cache misses, so a batch of
    /// reconciles failing at once collapses into a single re-sync.
    refresh_lock: Arc<tokio::sync::Mutex<()>>,
    /// Minimum time between on-demand refreshes (see `refresh_lock`). The
    /// background timer in `start_vault_cache_refresh` is unaffected by this.
    min_refresh_interval: Duration,
}

impl VaultClient {
    /// Create and authenticate a new `VaultClient`.
    ///
    /// Runs the full auth flow immediately; returns an error if auth fails.
    pub async fn new(
        base_url: impl Into<String>,
        email: impl Into<String>,
        password: impl Into<String>,
        client_id: Option<String>,
        client_secret: Option<String>,
        min_refresh_interval: Duration,
    ) -> Result<Self, VaultError> {
        let http = HttpClient::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("reqwest client build");

        let base_url = base_url.into().trim_end_matches('/').to_string();
        let email = email.into();
        let password = password.into();
        let device_id = Uuid::new_v4().to_string();

        let (access_token, refresh_tok, expires_in, sym_key) = authenticate(
            &http,
            &base_url,
            &email,
            &password,
            client_id.as_deref(),
            client_secret.as_deref(),
            &device_id,
        )
        .await?;

        let token_expires_at = Instant::now() + Duration::from_secs(expires_in);

        let client = Self {
            inner: Arc::new(RwLock::new(Session {
                access_token,
                refresh_token: refresh_tok,
                token_expires_at,
                sym_key,
                vault: None,
                last_refresh_at: Instant::now(),
            })),
            http,
            base_url,
            email,
            password,
            client_id,
            client_secret,
            device_id,
            refresh_lock: Arc::new(tokio::sync::Mutex::new(())),
            min_refresh_interval,
        };

        // Perform the initial vault sync so reconciles can start immediately.
        client.refresh_vault_cache().await?;

        Ok(client)
    }

    /// Return the decrypted values for all requested lookups, index-aligned
    /// with `requests`.
    ///
    /// All-or-nothing: if any lookup fails, the entire call fails (no partial writes).
    ///
    /// On a staleness-class miss (see `LookupError::is_stale_miss`), this triggers one
    /// on-demand vault re-sync — subject to `min_refresh_interval` cooldown so a batch
    /// of CRs failing at once collapses into a single `/api/sync` call — and retries
    /// the lookups once against the refreshed cache. This is what lets a just-recreated
    /// Vaultwarden item become visible in seconds instead of waiting for the next
    /// background refresh (up to `VAULT_CACHE_REFRESH_INTERVAL`).
    pub async fn fetch_secrets(
        &self,
        requests: &[SecretRequest],
    ) -> Result<Vec<String>, VaultError> {
        match self.try_fetch_secrets(requests).await {
            Err(VaultError::Lookup(e)) if e.is_stale_miss() => {
                debug!(err = %e, "cache miss; attempting on-demand refresh");
                if self.refresh_if_due().await {
                    self.try_fetch_secrets(requests).await
                } else {
                    Err(VaultError::Lookup(e))
                }
            }
            other => other,
        }
    }

    async fn try_fetch_secrets(
        &self,
        requests: &[SecretRequest],
    ) -> Result<Vec<String>, VaultError> {
        let session = self.inner.read().await;
        let cache = session.vault.as_ref().ok_or(VaultError::NotInitialized)?;

        let mut result = Vec::with_capacity(requests.len());
        for req in requests {
            let item = lookup_item(cache, &req.name, req.vault.as_deref())?;
            result.push(extract_secret(item).to_string());
        }
        Ok(result)
    }

    /// Refresh the vault cache on demand if the cooldown since the last refresh
    /// (background or on-demand) has elapsed. Returns whether a refresh actually ran.
    ///
    /// The cooldown check is repeated under `refresh_lock` so concurrent callers
    /// collapse into at most one sync per cooldown window instead of each racing
    /// past a stale check.
    async fn refresh_if_due(&self) -> bool {
        let _guard = self.refresh_lock.lock().await;

        let since_last = self.inner.read().await.last_refresh_at.elapsed();
        if since_last < self.min_refresh_interval {
            debug!(?since_last, "on-demand refresh skipped; within cooldown");
            return false;
        }

        match self.refresh_vault_cache().await {
            Ok(()) => true,
            Err(e) => {
                warn!(err = %e, "on-demand vault refresh failed");
                false
            }
        }
    }

    /// Re-sync the entire vault and update the decrypted item cache.
    pub async fn refresh_vault_cache(&self) -> Result<(), VaultError> {
        self.ensure_valid_token().await?;

        let access_token = self.inner.read().await.access_token.clone();
        let sym_key = self.inner.read().await.sym_key.clone();

        let sync_resp = match fetch_sync(&self.http, &self.base_url, &access_token).await {
            Ok(r) => r,
            Err(SyncError::Unauthorized) => {
                // Try refresh-then-retry once.
                warn!("401 during sync; refreshing token");
                self.do_refresh_or_reauth().await?;
                let access_token = self.inner.read().await.access_token.clone();
                fetch_sync(&self.http, &self.base_url, &access_token).await?
            }
            Err(e) => return Err(e.into()),
        };

        let (cache, skips) = decrypt_vault(&sync_resp, &sym_key);
        let new_count = cache.items.len();

        let mut session = self.inner.write().await;
        let old_count = session.vault.as_ref().map(|c| c.items.len());
        if old_count != Some(new_count) {
            info!(
                ?old_count,
                new_count,
                skipped = skips.total(),
                "vault item count changed on refresh"
            );
        }
        session.vault = Some(cache);
        session.last_refresh_at = Instant::now();
        debug!(count = new_count, "vault cache refreshed");
        Ok(())
    }

    /// Spawn a background task that keeps the access token fresh.
    ///
    /// Wakes up ~60 seconds before the token expires and refreshes it.
    /// On failure, backs off 30 s then retries. Runs until `ctx` is cancelled.
    pub async fn start_token_refresh(self, mut ctx: tokio::sync::watch::Receiver<bool>) {
        loop {
            let sleep_dur = {
                let session = self.inner.read().await;
                let refresh_at = session
                    .token_expires_at
                    .checked_sub(Duration::from_secs(60))
                    .unwrap_or_else(Instant::now);
                refresh_at.saturating_duration_since(Instant::now())
            };
            debug!(sleep_secs = sleep_dur.as_secs(), "token refresh sleeping");

            tokio::select! {
                _ = time::sleep(sleep_dur) => {}
                _ = ctx.changed() => {
                    info!("background token refresh stopped");
                    return;
                }
            }

            if let Err(e) = self.ensure_valid_token().await {
                warn!(err = %e, "background token refresh failed; backing off 30s");
                tokio::select! {
                    _ = time::sleep(Duration::from_secs(30)) => {}
                    _ = ctx.changed() => { return; }
                }
            } else {
                debug!("background token refresh succeeded");
            }
        }
    }

    /// Spawn a background task that re-syncs the vault on `interval`.
    pub async fn start_vault_cache_refresh(
        self,
        interval: Duration,
        mut ctx: tokio::sync::watch::Receiver<bool>,
    ) {
        let mut ticker = time::interval(interval);
        ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    if let Err(e) = self.refresh_vault_cache().await {
                        warn!(err = %e, "background vault sync failed");
                    } else {
                        debug!("background vault sync completed");
                    }
                }
                _ = ctx.changed() => {
                    info!("background vault cache refresh stopped");
                    return;
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Token management internals
    // -----------------------------------------------------------------------

    async fn ensure_valid_token(&self) -> Result<(), VaultError> {
        let expires_at = self.inner.read().await.token_expires_at;
        if Instant::now() + Duration::from_secs(60) >= expires_at {
            debug!("token expiring soon; refreshing");
            self.do_refresh_or_reauth().await?;
        }
        Ok(())
    }

    async fn do_refresh_or_reauth(&self) -> Result<(), VaultError> {
        let current_rt = self.inner.read().await.refresh_token.clone();

        match refresh_token(&self.http, &self.base_url, &current_rt).await {
            Ok((new_at, new_rt, expires_in)) => {
                let mut session = self.inner.write().await;
                session.access_token = new_at;
                if let Some(rt) = new_rt {
                    session.refresh_token = rt;
                }
                session.token_expires_at = Instant::now() + Duration::from_secs(expires_in);
                debug!("token refreshed via refresh_token grant");
                Ok(())
            }
            Err(e) => {
                warn!(err = %e, "token refresh failed; attempting full re-auth");
                self.re_authenticate().await
            }
        }
    }

    async fn re_authenticate(&self) -> Result<(), VaultError> {
        let (access_token, refresh_tok, expires_in, sym_key) = authenticate(
            &self.http,
            &self.base_url,
            &self.email,
            &self.password,
            self.client_id.as_deref(),
            self.client_secret.as_deref(),
            &self.device_id,
        )
        .await?;

        let mut session = self.inner.write().await;
        session.access_token = access_token;
        session.refresh_token = refresh_tok;
        session.token_expires_at = Instant::now() + Duration::from_secs(expires_in);
        session.sym_key = sym_key;
        info!("re-authentication successful");
        Ok(())
    }
}

/// Walk `std::error::Error::source()` and return the full error chain as a single string.
///
/// This produces a message like `"outer: ... -> inner: ... -> root cause"` that contains
/// the reqwest source (dns error, connect error, TLS error, etc.) which Display alone hides.
fn error_chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        out.push_str(&format!(" -> {s}"));
        src = s.source();
    }
    out
}

/// Initialize a `VaultClient` with up to 3 retry attempts using quadratic backoff.
///
/// Mirrors `InitializeAPIClient` from Go's `init.go`.
pub async fn initialize_vault_client(
    base_url: &str,
    email: &str,
    password: &str,
    client_id: Option<String>,
    client_secret: Option<String>,
    min_refresh_interval: Duration,
) -> Result<VaultClient, VaultError> {
    info!("initializing Vaultwarden client...");
    let max_retries = 3usize;

    for attempt in 1..=max_retries {
        if attempt > 1 {
            let backoff = Duration::from_secs((attempt * attempt * 5) as u64);
            info!(attempt, max_retries, ?backoff, "retrying vault client init");
            time::sleep(backoff).await;
        }

        match VaultClient::new(
            base_url,
            email,
            password,
            client_id.clone(),
            client_secret.clone(),
            min_refresh_interval,
        )
        .await
        {
            Ok(client) => {
                info!("Vaultwarden client initialized successfully");
                return Ok(client);
            }
            Err(e) => {
                warn!(attempt, err = %error_chain(&e), "vault client init attempt failed");
                if attempt == max_retries {
                    return Err(e);
                }
            }
        }
    }

    unreachable!()
}
