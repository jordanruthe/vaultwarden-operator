//! Vaultwarden Kubernetes operator entrypoint.
//!
//! Reads configuration from environment, then runs:
//! - Health probe server on :8081 (started early so standby replicas pass probes)
//! - Leader election via a `coordination.k8s.io/v1` Lease
//! - Once leader: Vaultwarden authentication, background token/cache refresh, and
//!   the Kubernetes controller (VaultwardenSecret reconciler)
//!
//! When leadership is lost the process exits, which causes Kubernetes to restart
//! the pod. It will re-contend for leadership as a fresh standby, avoiding
//! split-brain scenarios without needing in-process state cleanup.

mod controller;
mod crd;
mod health;
mod leader;
mod vault;

use std::{sync::Arc, time::Duration};

use futures::StreamExt;
use kube::{
    api::Api,
    runtime::{controller::Controller, predicates, reflector, watcher, Predicate, WatchStreamExt},
    Client,
};
use tracing::info;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

use controller::{error_policy, reconcile, Context};
use crd::VaultwardenSecret;
use vault::initialize_vault_client;

/// Vault cache refresh interval. Reconciles read the in-memory cache; this
/// controls how fresh that cache is (independent of per-CR `spec.syncInterval`).
const VAULT_CACHE_REFRESH_INTERVAL: Duration = Duration::from_secs(5 * 60);

fn required_env(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| {
        eprintln!("FATAL: required env var {key} is not set");
        std::process::exit(1);
    })
}

fn optional_env(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Tracing setup: respects RUST_LOG env var; defaults to info.
    tracing_subscriber::registry()
        .with(EnvFilter::from_default_env().add_directive("info".parse()?))
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!(
        version = env!("CARGO_PKG_VERSION"),
        "starting vaultwarden-operator"
    );

    // ---------------------------------------------------------------------------
    // Kubernetes client (early — needed for leader election and health probes)
    // ---------------------------------------------------------------------------
    let kube_client = Client::try_default().await?;

    // ---------------------------------------------------------------------------
    // Health probe server — started BEFORE leader election so standby replicas
    // pass liveness/readiness probes while waiting for the lease.
    // ---------------------------------------------------------------------------
    tokio::spawn(health::serve());

    // ---------------------------------------------------------------------------
    // Leader election
    //
    // Block until this replica acquires the Lease. Standby replicas loop here,
    // checking the lease every few seconds. SIGTERM while waiting causes a clean
    // exit (handled inside `leader::acquire`).
    //
    // Once `acquire` returns, this process is the active leader.
    // ---------------------------------------------------------------------------
    let leader_cfg = leader::LeaderConfig::from_env(&kube_client);
    let lease_lock = leader::acquire(kube_client.clone(), &leader_cfg).await;

    info!("running as leader; initializing vault client");

    // ---------------------------------------------------------------------------
    // Configuration from environment (only read after becoming leader so standby
    // pods don't need vault credentials or establish Vaultwarden sessions)
    // ---------------------------------------------------------------------------
    let vault_url = required_env("VAULTWARDEN_URL");
    let vault_email = required_env("VAULTWARDEN_EMAIL");
    let vault_password = required_env("VAULTWARDEN_PASSWORD");
    let client_id = optional_env("VAULTWARDEN_CLIENT_ID");
    let client_secret = optional_env("VAULTWARDEN_CLIENT_SECRET");

    // ---------------------------------------------------------------------------
    // Vault client init (fails fast → process exits if Vaultwarden is unreachable)
    // ---------------------------------------------------------------------------
    let vault_client = initialize_vault_client(
        &vault_url,
        &vault_email,
        &vault_password,
        client_id,
        client_secret,
    )
    .await?;

    info!("vault client ready; starting controller");

    // ---------------------------------------------------------------------------
    // Background tasks: token refresh + vault cache refresh
    // ---------------------------------------------------------------------------
    // Use a watch channel as a cancellation signal.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    let vc_token = vault_client.clone();
    let token_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        vc_token.start_token_refresh(token_rx).await;
    });

    let vc_cache = vault_client.clone();
    let cache_rx = shutdown_rx.clone();
    tokio::spawn(async move {
        vc_cache
            .start_vault_cache_refresh(VAULT_CACHE_REFRESH_INTERVAL, cache_rx)
            .await;
    });

    // ---------------------------------------------------------------------------
    // Lease renewal task
    //
    // Spawn a task that renews the lease on a tight loop. When leadership is
    // lost (or renewal fails too many times) `keep_renewing` returns, signalling
    // via a oneshot channel so the controller shuts down.
    // ---------------------------------------------------------------------------
    let (lease_lost_tx, lease_lost_rx) = tokio::sync::oneshot::channel::<()>();
    let lease_lock_arc = Arc::new(lease_lock);
    let lease_lock_renew = lease_lock_arc.clone();

    tokio::spawn(async move {
        leader::keep_renewing(&lease_lock_renew, &leader_cfg).await;
        // Signal: leadership lost. The controller's shutdown future will resolve.
        let _ = lease_lost_tx.send(());
    });

    // ---------------------------------------------------------------------------
    // Graceful shutdown future
    //
    // The controller stops when EITHER:
    //   - SIGTERM/SIGINT is received (normal pod termination / rollout), or
    //   - the lease is lost (lease_lost_rx fires).
    //
    // We fuse both into a single future for `graceful_shutdown_on`.
    // ---------------------------------------------------------------------------
    let shutdown_signal = async move {
        tokio::select! {
            _ = sigterm_or_ctrlc() => {
                info!("signal received; shutting down controller");
            }
            _ = async { lease_lost_rx.await.ok(); } => {
                tracing::warn!("leadership lost; shutting down controller and exiting");
            }
        }
    };

    // ---------------------------------------------------------------------------
    // Controller
    // ---------------------------------------------------------------------------
    let ctx = Arc::new(Context {
        client: kube_client.clone(),
        vault: vault_client,
    });

    let vws_api: Api<VaultwardenSecret> = Api::all(kube_client.clone());
    let secrets_api: Api<k8s_openapi::api::core::v1::Secret> = Api::all(kube_client.clone());

    // Use a combined predicate to filter the VaultwardenSecret watch stream.
    // This prevents the controller from re-reconciling on its own status writes,
    // which would otherwise cause a hot reconcile loop (status patch → watch event
    // → immediate re-reconcile → status patch → …).
    //
    // generation alone is insufficient: adding the finalizer is a metadata change that
    // does NOT bump generation. The kube finalizer() helper adds the finalizer and then
    // returns Action::await_change(), expecting the patch to trigger a fresh watch event.
    // With generation-only filtering that event is dropped, stranding the object without
    // a Secret or status until the operator restarts. Combining with finalizers lets
    // the finalizer-add event through while still filtering status-only writes (which
    // change neither generation nor finalizers).
    let (reader, writer) = reflector::store();
    let vws_stream = watcher(vws_api, watcher::Config::default())
        .default_backoff()
        .reflect(writer)
        .applied_objects()
        .predicate_filter(predicates::generation.combine(predicates::finalizers));

    Controller::for_stream(vws_stream, reader)
        .owns(secrets_api, watcher::Config::default())
        .graceful_shutdown_on(shutdown_signal)
        .run(reconcile, error_policy, ctx)
        .for_each(|result| async move {
            match result {
                Ok(obj) => tracing::debug!(?obj, "reconciled"),
                // ObjectNotFound fires when a requeue fires after the CR is already gone from
                // the store (benign race on deletion); log at debug to avoid spurious warnings.
                Err(e) if matches!(e, kube::runtime::controller::Error::ObjectNotFound(_)) => {
                    tracing::debug!(err = %e, "reconcile skipped: object no longer in store")
                }
                Err(e) => tracing::warn!(err = %e, "reconcile error"),
            }
        })
        .await;

    info!("controller stopped; shutting down background tasks");
    let _ = shutdown_tx.send(true);

    // Best-effort step-down: if leadership was lost the renewal task already
    // called step_down(); on a normal SIGTERM we call it here to let a successor
    // acquire the lease immediately.
    if let Err(e) = lease_lock_arc.step_down().await {
        tracing::warn!(err = %e, "step_down on exit failed (non-fatal)");
    }

    Ok(())
}

/// Returns a future that resolves on SIGTERM (unix) or ctrl-c.
async fn sigterm_or_ctrlc() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut s) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = s.recv() => return,
                _ = tokio::signal::ctrl_c() => return,
            }
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
