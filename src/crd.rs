use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maps a Kubernetes Secret key to a Vaultwarden item name.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VaultwardenSecretDataItem {
    /// Key name in the resulting Kubernetes Secret.
    pub key: String,
    /// Item name to look up in Vaultwarden (case-insensitive, supports partial match).
    #[serde(rename = "vaultwardenSecret")]
    pub vaultwarden_secret: String,
}

/// VaultwardenSecret syncs secrets from Vaultwarden into a Kubernetes Secret.
///
/// Create a VaultwardenSecret to have the operator pull the listed vault items
/// and write them as a native Kubernetes Secret with the same name and namespace.
#[derive(Debug, Clone, CustomResource, Serialize, Deserialize, JsonSchema)]
#[kube(
    group = "secrets.vaultwarden.io",
    version = "v1alpha1",
    kind = "VaultwardenSecret",
    namespaced,
    shortname = "vws",
    status = "VaultwardenSecretStatus",
    printcolumn = r#"{"name":"Ready","type":"boolean","jsonPath":".status.ready"}"#,
    printcolumn = r#"{"name":"Last Sync","type":"date","jsonPath":".status.lastSyncTime"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
pub struct VaultwardenSecretSpec {
    /// How often to re-sync from Vaultwarden. Must be a valid duration string
    /// (e.g. "5m", "1h"). Defaults to "5m".
    #[serde(
        rename = "syncInterval",
        default = "default_sync_interval",
        skip_serializing_if = "String::is_empty"
    )]
    pub sync_interval: String,
    /// List of Vaultwarden items to fetch.
    pub data: Vec<VaultwardenSecretDataItem>,
}

fn default_sync_interval() -> String {
    "5m".to_string()
}

/// A standard Kubernetes status condition (mirrors `metav1.Condition`).
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct StatusCondition {
    /// Type of the condition (e.g. "Ready", "SyncFailed").
    #[serde(rename = "type")]
    pub type_: String,
    /// Status of the condition: "True", "False", or "Unknown".
    pub status: String,
    /// CamelCase reason code for the condition.
    pub reason: String,
    /// Human-readable message.
    pub message: String,
    /// Generation of the object the condition was set on.
    #[serde(rename = "observedGeneration", skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// When this condition last transitioned (RFC3339).
    #[serde(rename = "lastTransitionTime")]
    pub last_transition_time: String,
}

/// VaultwardenSecretStatus reflects the observed state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
pub struct VaultwardenSecretStatus {
    /// Whether the secret has been successfully synced.
    #[serde(default)]
    pub ready: bool,
    /// Timestamp of the last successful sync (RFC3339).
    #[serde(rename = "lastSyncTime", skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
    /// Error message from the last failed sync.
    #[serde(
        rename = "lastSyncError",
        default,
        skip_serializing_if = "String::is_empty"
    )]
    pub last_sync_error: String,
    /// Most recent generation observed by the controller.
    #[serde(rename = "observedGeneration", skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// Latest available observations of the resource state.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<StatusCondition>,
}
