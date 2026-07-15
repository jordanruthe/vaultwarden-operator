use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// Maps a Kubernetes Secret key to a Vaultwarden item name.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct VaultwardenSecretDataItem {
    /// Key name in the resulting Kubernetes Secret.
    pub key: String,
    /// Item name to look up in Vaultwarden (case-insensitive, supports partial match).
    #[serde(
        rename = "secretName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub secret_name: Option<String>,
    /// Deprecated: legacy alias for `secretName`. Ignored when `secretName` is set.
    #[serde(
        rename = "vaultwardenSecret",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub vaultwarden_secret: Option<String>,
    /// Vault (Vaultwarden organization name) to search for this item.
    /// Overrides `spec.defaultVault`. When set, the lookup fails if the item
    /// is not found within that organization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vault: Option<String>,
}

impl VaultwardenSecretDataItem {
    /// Effective item name: `secretName` preferred, `vaultwardenSecret` fallback.
    /// Empty strings are treated as unset.
    pub fn resolved_secret_name(&self) -> Option<&str> {
        self.secret_name
            .as_deref()
            .filter(|s| !s.is_empty())
            .or_else(|| self.vaultwarden_secret.as_deref().filter(|s| !s.is_empty()))
    }
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
    /// Default vault (Vaultwarden organization name) to search for all data
    /// entries; each entry may override this with its own `vault`.
    /// Unset = search the whole account (personal + all organizations).
    #[serde(
        rename = "defaultVault",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub default_vault: Option<String>,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn item(yaml: &str) -> VaultwardenSecretDataItem {
        serde_yaml::from_str(yaml).expect("valid data item yaml")
    }

    #[test]
    fn test_resolved_secret_name_secret_name_only() {
        let i = item("key: k\nsecretName: my-item");
        assert_eq!(i.resolved_secret_name(), Some("my-item"));
    }

    #[test]
    fn test_resolved_secret_name_legacy_only() {
        let i = item("key: k\nvaultwardenSecret: legacy-item");
        assert_eq!(i.resolved_secret_name(), Some("legacy-item"));
    }

    #[test]
    fn test_resolved_secret_name_prefers_secret_name() {
        let i = item("key: k\nsecretName: new\nvaultwardenSecret: old");
        assert_eq!(i.resolved_secret_name(), Some("new"));
    }

    #[test]
    fn test_resolved_secret_name_neither() {
        let i = item("key: k");
        assert_eq!(i.resolved_secret_name(), None);
    }

    #[test]
    fn test_resolved_secret_name_empty_falls_back() {
        let i = item("key: k\nsecretName: \"\"\nvaultwardenSecret: old");
        assert_eq!(i.resolved_secret_name(), Some("old"));
    }

    #[test]
    fn test_spec_default_vault_and_entry_vault() {
        let spec: VaultwardenSecretSpec = serde_yaml::from_str(
            "defaultVault: Kubernetes - Common\n\
             data:\n\
             - key: a\n  secretName: item-a\n  vault: Kubernetes - Apollo\n\
             - key: b\n  secretName: item-b\n",
        )
        .expect("valid spec yaml");
        assert_eq!(spec.default_vault.as_deref(), Some("Kubernetes - Common"));
        assert_eq!(spec.data[0].vault.as_deref(), Some("Kubernetes - Apollo"));
        assert_eq!(spec.data[1].vault, None);
    }

    #[test]
    fn test_spec_default_vault_absent() {
        let spec: VaultwardenSecretSpec =
            serde_yaml::from_str("data:\n- key: a\n  secretName: item-a\n").expect("valid spec");
        assert_eq!(spec.default_vault, None);
    }
}
