# vaultwarden-operator

A Kubernetes operator that syncs secrets from a [Vaultwarden](https://github.com/dani-garcia/vaultwarden) instance (self-hosted Bitwarden) into native Kubernetes `Secret` objects.

Written in Rust using [kube-rs](https://github.com/kube-rs/kube).

## How it works

1. The operator authenticates with Vaultwarden once at startup using a single user account (standard Bitwarden auth — **not** the admin token).
2. All Bitwarden decryption happens **client-side inside the operator** using native Rust crypto — no CLI dependency.
3. Users create `VaultwardenSecret` custom resources listing which vault items to pull and what keys to write them under.
4. The controller writes a Kubernetes `Secret` (same name/namespace as the CR) containing the decrypted values, and re-syncs on a configurable interval.

## CRD

```yaml
apiVersion: secrets.vaultwarden.io/v1alpha1
kind: VaultwardenSecret
metadata:
  name: my-app-secrets
  namespace: my-app
spec:
  syncInterval: "5m"        # optional, default 5m
  defaultVault: "Kubernetes - Common"  # optional org name to scope all lookups
  data:
    - key: DATABASE_PASSWORD   # key in the output Secret
      secretName: "Prod DB"    # vault item name (case-insensitive, partial match)
      vault: "Kubernetes Secrets"  # optional per-entry override of defaultVault
    - key: API_KEY
      secretName: "My API Key" # uses defaultVault
```

This creates a `Secret` named `my-app-secrets` in `my-app` with `DATABASE_PASSWORD` and `API_KEY` populated from vault.

> `vaultwardenSecret` is a deprecated alias for `secretName` and keeps working for existing resources; when both are set, `secretName` wins.

### Vault scoping

`defaultVault` and per-entry `vault` name a Vaultwarden **organization** (case-insensitive exact match). Per-entry `vault` overrides `defaultVault`. Behavior when a vault is set:

- Only items owned by that organization match — personal-vault items are excluded.
- If the item is not found in that organization, the sync **fails** (Ready=False, `status.lastSyncError` explains) — it never falls back to a same-named item in another vault.
- A vault name matching multiple organizations is an error; rename one to disambiguate.
- The substring (partial) match still applies within the scoped organization.

When neither `vault` nor `defaultVault` is set, the item is matched by name across the whole account (personal vault + all organizations), as before.

> **Upgrading:** apply the new CRD before or together with the operator (a `helm upgrade` does both; the `helm.sh/resource-policy: keep` annotation only prevents deletion on uninstall). An old CRD schema silently prunes `secretName`, `vault`, and `defaultVault`.

### Vault cache refresh

Reconciles never hit Vaultwarden directly — they read an in-memory cache that is
re-synced in the background. Two intervals control this, both set as environment
variables on the operator (see `vault.cacheRefreshInterval` / `vault.minRefreshInterval`
in the Helm chart's `values.yaml`):

- `VAULT_CACHE_REFRESH_INTERVAL` (default `5m`) — how often the whole vault is
  re-fetched in the background. This is independent of each CR's own `syncInterval`,
  which only controls how often the *already-cached* data is re-applied to the
  managed `Secret`.
- `VAULT_CACHE_MIN_REFRESH_INTERVAL` (default `30s`) — when a lookup misses (the item
  isn't in the cache, or names a vault the cache doesn't know about yet), the operator
  triggers one on-demand re-sync and retries before failing, so a just-created or
  just-moved item can become visible in seconds rather than waiting for the next
  background refresh. This cooldown caps how often that on-demand refresh can fire,
  so a batch of CRs failing at once collapses into a single extra `/api/sync` call.

A vault name matching multiple organizations (`VaultAmbiguous`) is a naming conflict,
not staleness, so it fails immediately without triggering a refresh.

### Secret value extraction priority

For each vault item, the operator extracts the value using this priority:
1. `login.password`
2. Custom field named `value`, `secret`, `api_key`, `apikey`, or `token`
3. `notes`
4. First non-empty custom field value

## Install via Helm

The easiest way to deploy the operator is via the Helm chart published on GitHub Pages.

```sh
helm repo add vaultwarden-operator https://jordanruthe.github.io/vaultwarden-operator
helm repo update

# Create credentials Secret first (see below), then:
helm install vaultwarden-operator vaultwarden-operator/vaultwarden-operator \
  --namespace vaultwarden-operator-system \
  --create-namespace
```

See [`charts/vaultwarden-operator/README.md`](charts/vaultwarden-operator/README.md) for the full values reference.

## Deployment (raw manifests)

### 1. Install the CRD

```sh
kubectl apply -f config/crd/vaultwardensecret.yaml
```

### 2. Create the credentials Secret

```sh
kubectl create namespace vaultwarden-operator-system

kubectl create secret generic vaultwarden-operator-credentials \
  --namespace vaultwarden-operator-system \
  --from-literal=VAULTWARDEN_URL=https://vault.example.com \
  --from-literal=VAULTWARDEN_EMAIL=operator@example.com \
  --from-literal=VAULTWARDEN_PASSWORD=supersecret
```

For API-key auth (bypasses 2FA), also add `VAULTWARDEN_CLIENT_ID` and `VAULTWARDEN_CLIENT_SECRET` to the above Secret and uncomment the corresponding env vars in `config/manager/deployment.yaml`.

### 3. Apply RBAC and Deployment

```sh
kubectl apply -f config/rbac/
kubectl apply -f config/manager/
```

### 4. Apply VaultwardenSecret resources

```sh
kubectl apply -f your-vaultwardensecret.yaml
```

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `VAULTWARDEN_URL` | ✅ | Base URL of your Vaultwarden instance |
| `VAULTWARDEN_EMAIL` | ✅ | Login email |
| `VAULTWARDEN_PASSWORD` | ✅ | Login password |
| `VAULTWARDEN_CLIENT_ID` | ❌ | API key client ID (bypasses 2FA) |
| `VAULTWARDEN_CLIENT_SECRET` | ❌ | API key client secret (bypasses 2FA) |
| `RUST_LOG` | ❌ | Log level (default: `info`) |

## Development

```sh
# Run tests (crypto unit tests are the primary correctness gate)
cargo test

# Generate the CRD YAML
cargo run --bin crdgen > config/crd/vaultwardensecret.yaml

# Run locally against a cluster (uses in-cluster or ~/.kube/config)
VAULTWARDEN_URL=... VAULTWARDEN_EMAIL=... VAULTWARDEN_PASSWORD=... cargo run

# Lint
cargo clippy --all-targets -- -D warnings
cargo fmt --check
```

## Architecture

```
src/
  main.rs          Startup: env config, vault init, spawn tasks, run controller
  crd.rs           VaultwardenSecret CRD types (kube-derive + schemars)
  controller.rs    Reconciler: finalizer, vault fetch, Secret create/patch, status
  health.rs        /healthz + /readyz HTTP server on :8081
  vault/
    mod.rs         VaultClient: shared session, cached vault, fetch_secrets()
    auth.rs        Prelogin, password/API-key grants, token refresh
    crypto.rs      Bitwarden CipherString, AES-CBC+HMAC, PBKDF2/Argon2id, HKDF, RSA
    sync.rs        /api/sync model, org-key decrypt, find_item/extract_secret
  crdgen.rs        Binary: prints CRD YAML to stdout
```

## Notes

- **Single replica** — the operator does not implement leader election. Run one replica.
- **All-or-nothing fetch** — if any vault item listed in a CR is not found, the entire sync fails and no partial Secret is written.
- **Vault cache** — the decrypted vault is refreshed in the background every 5 minutes. Reconciles read from this cache (no per-reconcile HTTP sync).
- The operator does **not** expose vault data over HTTP — the health server on `:8081` has only `/healthz` and `/readyz`.
