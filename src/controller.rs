//! VaultwardenSecret reconciler.
//!
//! Ports vaultwardensecret_controller.go faithfully:
//! - One owned `corev1.Secret` per CR (same name/namespace)
//! - Finalizer for clean deletion
//! - All-or-nothing vault fetch → no partial Secret writes
//! - `Ready` / `SyncFailed` status conditions
//! - Per-CR `spec.syncInterval` requeue

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use chrono::Utc;
use k8s_openapi::api::core::v1::Secret;
use kube::{
    api::{Api, Patch, PatchParams, PostParams},
    runtime::{
        controller::Action,
        finalizer::{finalizer, Event as FinalizerEvent},
    },
    Client, Resource, ResourceExt,
};
use serde_json::json;
use thiserror::Error;
use tracing::{error, info, warn};

use crate::{
    crd::{StatusCondition, VaultwardenSecret, VaultwardenSecretStatus},
    vault::{VaultClient, VaultError},
};

const FINALIZER_NAME: &str = "secrets.vaultwarden.io/finalizer";
const MANAGED_BY_LABEL: &str = "vaultwarden-operator";
const DEFAULT_SYNC_INTERVAL: Duration = Duration::from_secs(5 * 60);

const CONDITION_READY: &str = "Ready";
const CONDITION_SYNC_FAILED: &str = "SyncFailed";

#[derive(Debug, Error)]
pub enum ReconcileError {
    #[error("kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    #[error("vault error: {0}")]
    Vault(#[from] VaultError),
    #[error("finalizer error: {0}")]
    Finalizer(#[source] Box<dyn std::error::Error + Send + Sync>),
}

/// Context shared with every reconcile call.
pub struct Context {
    pub client: Client,
    pub vault: VaultClient,
}

/// Entry point called by the kube Controller.
pub async fn reconcile(
    vws: Arc<VaultwardenSecret>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let ns = vws.namespace().unwrap_or_else(|| "default".to_string());
    let api: Api<VaultwardenSecret> = Api::namespaced(ctx.client.clone(), &ns);

    finalizer(&api, FINALIZER_NAME, vws.clone(), |event| async {
        match event {
            FinalizerEvent::Apply(vws) => reconcile_apply(vws, ctx.clone()).await,
            FinalizerEvent::Cleanup(_vws) => {
                // Owner reference on the managed Secret causes cascade deletion
                // automatically; nothing to do here.
                Ok(Action::await_change())
            }
        }
    })
    .await
    .map_err(|e| ReconcileError::Finalizer(Box::new(e)))
}

/// Called when the CR exists and is not being deleted.
async fn reconcile_apply(
    vws: Arc<VaultwardenSecret>,
    ctx: Arc<Context>,
) -> Result<Action, ReconcileError> {
    let ns = vws.namespace().unwrap_or_else(|| "default".to_string());
    let name = vws.name_any();

    // Parse sync interval.
    let interval = match parse_sync_interval(&vws.spec.sync_interval) {
        Ok(d) => d,
        Err(msg) => {
            warn!(vws = %name, "invalid syncInterval: {msg}");
            set_failed_status(&vws, &ctx, &msg).await?;
            return Ok(Action::requeue(DEFAULT_SYNC_INTERVAL));
        }
    };

    // Collect vault item names.
    let names: Vec<String> = vws
        .spec
        .data
        .iter()
        .map(|item| item.vaultwarden_secret.clone())
        .collect();

    // All-or-nothing vault fetch.
    let values = match ctx.vault.fetch_secrets(&names).await {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("failed to fetch Vaultwarden secrets: {e}");
            warn!(vws = %name, "{msg}");
            set_failed_status(&vws, &ctx, &msg).await?;
            return Ok(Action::requeue(interval));
        }
    };

    // Build Secret data.
    let secret_data: BTreeMap<String, serde_json::Value> = vws
        .spec
        .data
        .iter()
        .map(|item| {
            let value = values
                .get(&item.vaultwarden_secret)
                .cloned()
                .unwrap_or_default();
            // Kubernetes Secret data values are base64-encoded; the JSON patch
            // format expects byte strings when using the `data` field.
            // We store them as plain strings in `stringData` to avoid double-encoding.
            (item.key.clone(), json!(value))
        })
        .collect();

    // CreateOrUpdate the managed Secret.
    let secrets_api: Api<Secret> = Api::namespaced(ctx.client.clone(), &ns);

    // Build owner reference.
    let owner_ref = vws.controller_owner_ref(&()).unwrap();

    let secret_body = json!({
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": name,
            "namespace": ns,
            "labels": {
                "app.kubernetes.io/managed-by": MANAGED_BY_LABEL
            },
            "ownerReferences": [owner_ref]
        },
        "type": "Opaque",
        "stringData": secret_data
    });

    match secrets_api.get_opt(&name).await? {
        None => {
            info!(vws = %name, ns = %ns, "creating managed Secret");
            secrets_api
                .create(
                    &PostParams::default(),
                    &serde_json::from_value(secret_body).expect("valid Secret JSON"),
                )
                .await?;
        }
        Some(_) => {
            info!(vws = %name, ns = %ns, "patching managed Secret");
            secrets_api
                .patch(
                    &name,
                    &PatchParams::apply("vaultwarden-operator").force(),
                    &Patch::Apply(secret_body),
                )
                .await?;
        }
    }

    // Update status: success.
    set_ready_status(&vws, &ctx).await?;
    info!(vws = %name, ?interval, "reconcile complete; requeuing");

    Ok(Action::requeue(interval))
}

/// Handle controller errors — log and requeue after the default interval.
pub fn error_policy(
    vws: Arc<VaultwardenSecret>,
    err: &ReconcileError,
    _ctx: Arc<Context>,
) -> Action {
    error!(vws = %vws.name_any(), err = %err, "reconcile error");
    Action::requeue(DEFAULT_SYNC_INTERVAL)
}

// ---------------------------------------------------------------------------
// Status helpers
// ---------------------------------------------------------------------------

async fn set_ready_status(
    vws: &VaultwardenSecret,
    ctx: &Arc<Context>,
) -> Result<(), ReconcileError> {
    let ns = vws.namespace().unwrap_or_else(|| "default".to_string());
    let name = vws.name_any();
    let generation = vws.metadata.generation.unwrap_or(0);
    let now = Utc::now().to_rfc3339();

    // Build updated conditions: set Ready=True, remove SyncFailed.
    let mut conditions: Vec<StatusCondition> = vws
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default()
        .into_iter()
        .filter(|c| c.type_ != CONDITION_SYNC_FAILED)
        .collect();

    upsert_condition(
        &mut conditions,
        StatusCondition {
            type_: CONDITION_READY.to_string(),
            status: "True".to_string(),
            observed_generation: Some(generation),
            reason: "SyncSucceeded".to_string(),
            message: "Vault secrets synced successfully".to_string(),
            last_transition_time: now.clone(),
        },
    );

    let status = VaultwardenSecretStatus {
        ready: true,
        last_sync_time: Some(now),
        last_sync_error: String::new(),
        observed_generation: Some(generation),
        conditions,
    };

    patch_status(ctx, &ns, &name, status).await
}

async fn set_failed_status(
    vws: &VaultwardenSecret,
    ctx: &Arc<Context>,
    msg: &str,
) -> Result<(), ReconcileError> {
    let ns = vws.namespace().unwrap_or_else(|| "default".to_string());
    let name = vws.name_any();
    let generation = vws.metadata.generation.unwrap_or(0);
    let now = Utc::now().to_rfc3339();

    let mut conditions: Vec<StatusCondition> = vws
        .status
        .as_ref()
        .map(|s| s.conditions.clone())
        .unwrap_or_default();

    upsert_condition(
        &mut conditions,
        StatusCondition {
            type_: CONDITION_READY.to_string(),
            status: "False".to_string(),
            observed_generation: Some(generation),
            reason: "SyncFailed".to_string(),
            message: msg.to_string(),
            last_transition_time: now.clone(),
        },
    );
    upsert_condition(
        &mut conditions,
        StatusCondition {
            type_: CONDITION_SYNC_FAILED.to_string(),
            status: "True".to_string(),
            observed_generation: Some(generation),
            reason: "SyncFailed".to_string(),
            message: msg.to_string(),
            last_transition_time: now,
        },
    );

    let status = VaultwardenSecretStatus {
        ready: false,
        last_sync_time: vws.status.as_ref().and_then(|s| s.last_sync_time.clone()),
        last_sync_error: msg.to_string(),
        observed_generation: Some(generation),
        conditions,
    };

    patch_status(ctx, &ns, &name, status).await
}

async fn patch_status(
    ctx: &Arc<Context>,
    ns: &str,
    name: &str,
    status: VaultwardenSecretStatus,
) -> Result<(), ReconcileError> {
    let api: Api<VaultwardenSecret> = Api::namespaced(ctx.client.clone(), ns);
    let patch = json!({ "status": status });
    api.patch_status(
        name,
        &PatchParams::apply("vaultwarden-operator"),
        &Patch::Merge(patch),
    )
    .await?;
    Ok(())
}

/// Insert or replace a condition in the list (keyed by `type_`).
fn upsert_condition(conditions: &mut Vec<StatusCondition>, new: StatusCondition) {
    if let Some(pos) = conditions.iter().position(|c| c.type_ == new.type_) {
        conditions[pos] = new;
    } else {
        conditions.push(new);
    }
}

// ---------------------------------------------------------------------------
// Interval parsing
// ---------------------------------------------------------------------------

/// Parse a Go-style duration string (`"5m"`, `"1h30m"`, etc.) into a `Duration`.
///
/// Empty string → default 5 minutes. Must be positive.
fn parse_sync_interval(s: &str) -> Result<Duration, String> {
    if s.is_empty() {
        return Ok(DEFAULT_SYNC_INTERVAL);
    }
    // Use a simple Go-compatible duration parser: support s, m, h units.
    let d = humantime_parse(s).map_err(|e| e.to_string())?;
    if d.is_zero() {
        return Err("syncInterval must be positive".to_string());
    }
    Ok(d)
}

/// Minimal duration parser supporting Go's common units (s, m, h).
fn humantime_parse(s: &str) -> Result<Duration, String> {
    // Try humantime first (handles "5m", "1h30m0s", etc.)
    // We use a hand-rolled parser to avoid an extra crate dependency.
    let s = s.trim();
    let mut total_secs: u64 = 0;
    let mut remaining = s;

    while !remaining.is_empty() {
        // Read number.
        let num_end = remaining
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(remaining.len());
        if num_end == 0 {
            return Err(format!("unexpected char in duration {s:?}"));
        }
        let num: u64 = remaining[..num_end]
            .parse()
            .map_err(|_| format!("invalid number in duration {s:?}"))?;
        remaining = &remaining[num_end..];

        // Read unit.
        if remaining.is_empty() {
            return Err(format!("missing unit in duration {s:?}"));
        }
        let (unit, rest) = if let Some(r) = remaining.strip_prefix("ns") {
            ("ns", r)
        } else if let Some(r) = remaining.strip_prefix("µs") {
            ("us", r)
        } else if let Some(r) = remaining.strip_prefix("us") {
            ("us", r)
        } else if let Some(r) = remaining.strip_prefix("ms") {
            ("ms", r)
        } else if let Some(r) = remaining.strip_prefix('s') {
            ("s", r)
        } else if let Some(r) = remaining.strip_prefix('m') {
            ("m", r)
        } else if let Some(r) = remaining.strip_prefix('h') {
            ("h", r)
        } else {
            return Err(format!(
                "unknown unit in duration {s:?}: {:?}",
                &remaining[..1]
            ));
        };

        let secs = match unit {
            "ns" => 0,
            "us" => 0,
            "ms" => 0,
            "s" => num,
            "m" => num * 60,
            "h" => num * 3600,
            _ => unreachable!(),
        };
        total_secs = total_secs.saturating_add(secs);
        remaining = rest;
    }

    Ok(Duration::from_secs(total_secs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sync_interval_empty() {
        assert_eq!(parse_sync_interval("").unwrap(), DEFAULT_SYNC_INTERVAL);
    }

    #[test]
    fn test_parse_sync_interval_5m() {
        assert_eq!(parse_sync_interval("5m").unwrap(), Duration::from_secs(300));
    }

    #[test]
    fn test_parse_sync_interval_1h() {
        assert_eq!(
            parse_sync_interval("1h").unwrap(),
            Duration::from_secs(3600)
        );
    }

    #[test]
    fn test_parse_sync_interval_1h30m() {
        assert_eq!(
            parse_sync_interval("1h30m").unwrap(),
            Duration::from_secs(5400)
        );
    }

    #[test]
    fn test_parse_sync_interval_30s() {
        assert_eq!(parse_sync_interval("30s").unwrap(), Duration::from_secs(30));
    }

    #[test]
    fn test_parse_sync_interval_invalid() {
        assert!(parse_sync_interval("abc").is_err());
        assert!(parse_sync_interval("5x").is_err());
    }
}
