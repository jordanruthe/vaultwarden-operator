//! Leader election via a `coordination.k8s.io/v1` Lease.
//!
//! The operator can run with >1 replica; exactly one replica ("leader") runs the
//! reconciler and vault background tasks. Others stand by, healthy, and ready to
//! take over if the leader pod is removed or its lease expires.
//!
//! # Model
//! - [`acquire`] blocks until this instance wins the lease. While waiting it
//!   handles SIGTERM gracefully so standby pods terminate cleanly on rollout.
//! - [`keep_renewing`] renews the lease on a tight loop after acquisition.
//!   When renewal fails (lease lost, API error, network partition past TTL) it
//!   **returns** — the caller should stop the controller and exit the process.
//! - `step_down()` is called before exit to release the lease immediately so a
//!   successor picks it up without waiting out the full TTL.
//!
//! # Configuration
//! | Env var             | Default                         |
//! |----------------------|--------------------------------|
//! | `LEADER_LEASE_NAME`  | `vaultwarden-operator-leader`   |
//!
//! No downward-API wiring is required: the holder identity comes from the pod's
//! system hostname (which Kubernetes sets to the pod name automatically) and the
//! namespace comes from the service account namespace file that `kube::Client`
//! already reads when running in-cluster.

use std::time::Duration;

use gethostname::gethostname;
use kube::Client;
use kube_leader_election::{LeaseLock, LeaseLockParams};
use tracing::{debug, info, warn};

/// Default name of the `coordination.k8s.io/v1` Lease object.
const DEFAULT_LEASE_NAME: &str = "vaultwarden-operator-leader";

/// How long until an unrenewed lease expires and another candidate may take over.
const LEASE_TTL: Duration = Duration::from_secs(15);

/// How often the leader renews the lease. Should be well under `LEASE_TTL`.
const RENEW_INTERVAL: Duration = Duration::from_secs(5);

/// Configuration for the leader-election Lease.
pub struct LeaderConfig {
    /// Name of the `coordination.k8s.io/v1` Lease object.
    pub lease_name: String,
    /// Namespace where the Lease lives (should be the operator's own namespace).
    pub namespace: String,
    /// Unique identity for this candidate (typically the pod name).
    pub holder_id: String,
}

impl LeaderConfig {
    /// Build from environment/system info, with sensible fallbacks.
    ///
    /// No downward API required: `holder_id` comes from the system hostname
    /// (Kubernetes sets a pod's hostname to its pod name automatically) and
    /// `namespace` comes from `kube::Client`'s default namespace, which reads
    /// the service account namespace file when running in-cluster.
    pub fn from_env(client: &Client) -> Self {
        let lease_name =
            std::env::var("LEADER_LEASE_NAME").unwrap_or_else(|_| DEFAULT_LEASE_NAME.to_string());

        // kube::Client knows the configured default namespace.
        let namespace = client.default_namespace().to_string();

        let holder_id = gethostname()
            .into_string()
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| {
                // Fallback: random UUID so two instances never clash even if the
                // hostname can't be read.
                uuid::Uuid::new_v4().to_string()
            });

        Self {
            lease_name,
            namespace,
            holder_id,
        }
    }
}

/// Block until this instance acquires the leader lease.
///
/// Loops, calling `try_acquire_or_renew` every [`RENEW_INTERVAL`], until
/// `acquired_lease == true`. While waiting, a `SIGTERM` (or `ctrl-c` locally)
/// causes a clean exit so standby pods don't linger past the pod grace period.
///
/// Returns the [`LeaseLock`] that is now held by this instance.
pub async fn acquire(client: Client, cfg: &LeaderConfig) -> LeaseLock {
    info!(
        holder = %cfg.holder_id,
        namespace = %cfg.namespace,
        lease = %cfg.lease_name,
        "attempting to acquire leadership",
    );

    let lock = LeaseLock::new(
        client,
        &cfg.namespace,
        LeaseLockParams {
            holder_id: cfg.holder_id.clone(),
            lease_name: cfg.lease_name.clone(),
            lease_ttl: LEASE_TTL,
        },
    );

    loop {
        match lock.try_acquire_or_renew().await {
            Ok(result) if result.acquired_lease => {
                info!(holder = %cfg.holder_id, "acquired leadership");
                return lock;
            }
            Ok(_) => {
                debug!(holder = %cfg.holder_id, "lease held by another; waiting");
            }
            Err(e) => {
                warn!(err = %e, "error trying to acquire lease; will retry");
            }
        }

        // Sleep before the next attempt, but exit immediately on SIGTERM so
        // the standby pod terminates cleanly within the pod's grace period.
        tokio::select! {
            _ = tokio::time::sleep(RENEW_INTERVAL) => {}
            _ = sigterm() => {
                info!("SIGTERM while waiting for leadership; exiting");
                std::process::exit(0);
            }
        }
    }
}

/// Renew the already-acquired lease on a loop.
///
/// This function returns when leadership is lost — either because:
/// - `try_acquire_or_renew` reports `acquired_lease == false` (another pod took over), or
/// - Renewal errors persist long enough that the lease TTL expires.
///
/// The caller is expected to **stop the controller and exit the process** so
/// that a fresh replica can re-contend cleanly (canonical active/passive model).
///
/// Calls `step_down()` before returning to release the lease immediately,
/// letting a successor acquire it without waiting out the full TTL.
pub async fn keep_renewing(lock: &LeaseLock, cfg: &LeaderConfig) {
    let mut consecutive_errors: u32 = 0;
    // How many consecutive errors before we give up. One TTL / renew_interval
    // gives about three chances before the lease would naturally expire.
    let error_threshold = (LEASE_TTL.as_secs() / RENEW_INTERVAL.as_secs()).max(2) as u32;

    loop {
        tokio::time::sleep(RENEW_INTERVAL).await;

        match lock.try_acquire_or_renew().await {
            Ok(result) if result.acquired_lease => {
                consecutive_errors = 0;
                debug!(holder = %cfg.holder_id, "leadership renewed");
            }
            Ok(_) => {
                warn!(holder = %cfg.holder_id, "leadership lost: another holder acquired the lease");
                break;
            }
            Err(e) => {
                consecutive_errors += 1;
                warn!(
                    err = %e,
                    consecutive_errors,
                    error_threshold,
                    "lease renewal error",
                );
                if consecutive_errors >= error_threshold {
                    warn!(
                        holder = %cfg.holder_id,
                        "giving up leadership after too many renewal failures",
                    );
                    break;
                }
            }
        }
    }

    // Best-effort step-down: set TTL to 1s and clear holder so a successor
    // acquires the lease immediately instead of waiting out the full TTL.
    if let Err(e) = lock.step_down().await {
        warn!(err = %e, "step_down failed (non-fatal); successor will wait for TTL");
    } else {
        info!(holder = %cfg.holder_id, "stepped down from leadership");
    }
}

/// Returns a future that resolves on SIGTERM (or ctrl-c in dev).
async fn sigterm() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        // Ignore errors: if we can't install the signal handler, just never
        // resolve (the process will still be killed by the OS).
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            s.recv().await;
            return;
        }
    }
    // Fallback: ctrl-c (also fires on SIGINT in non-unix builds).
    let _ = tokio::signal::ctrl_c().await;
}
