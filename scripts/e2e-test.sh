#!/usr/bin/env bash
# End-to-end test: builds the operator image, spins up an ephemeral kind
# cluster with a throwaway Vaultwarden, deploys the real Helm chart in HA
# (replicaCount=2), and verifies:
#   1. the happy path (reconcile produces the expected Secret) using
#      password auth (VAULTWARDEN_EMAIL/PASSWORD)
#   2. leader failover (killing the leader hands off within the lease TTL and
#      reconciliation resumes under the new leader)
#   3. API-key auth: fetches a personal API key for the test account and
#      restarts the operator with VAULTWARDEN_CLIENT_ID/CLIENT_SECRET wired
#      in (the chart's `extraEnv` mechanism), confirming it still
#      authenticates and reconciles
#   4. the RBAC-gap failure mode: if the `leases` ClusterRole rule is missing,
#      every pod passes health probes but never reconciles (silent stall) --
#      this documents the symptom to watch for if RBAC lags the image during
#      a real rollout.
#
# Nothing here touches any real/production cluster or Vaultwarden instance;
# everything is created in and torn down with a dedicated kind cluster.
#
# Usage: scripts/e2e-test.sh [--keep] [--skip-cargo] [--skip-rbac-negative] [--skip-api-key] [--fast]
#   --keep               Don't delete the kind cluster / helm release on exit (debugging).
#   --skip-cargo         Skip `cargo fmt/clippy/test` (assume already run).
#   --skip-rbac-negative Skip the negative RBAC test (step 4 above).
#   --skip-api-key       Skip the API-key auth test (step 3 above).
#   --fast               Skip the ~5min wait that verifies reconciliation resumes
#                         after failover (still verifies the lease changes hands).
#
# Requires: docker, kubectl, helm, node/npm, python3, openssl, go (to install kind).
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
E2E_DIR="$ROOT_DIR/scripts/e2e"
CLUSTER_NAME="vwo-e2e"
IMAGE_TAG="vaultwarden-operator:e2e"
TEST_EMAIL="test@example.com"
TEST_NAME="Test User"
TEST_PASSWORD="CorrectHorseBatteryStaple1!"
VW_HTTP_PORT=8380
TLS_PROXY_PORT=8443

KEEP=false
SKIP_CARGO=false
SKIP_RBAC_NEGATIVE=false
SKIP_API_KEY=false
FAST=false
for arg in "$@"; do
  case "$arg" in
    --keep) KEEP=true ;;
    --skip-cargo) SKIP_CARGO=true ;;
    --skip-rbac-negative) SKIP_RBAC_NEGATIVE=true ;;
    --skip-api-key) SKIP_API_KEY=true ;;
    --fast) FAST=true ;;
    *) echo "unknown argument: $arg" >&2; exit 1 ;;
  esac
done

WORKDIR="$(mktemp -d)"
PORT_FORWARD_PID=""
TLS_PROXY_PID=""

log()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mWARN:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31mFATAL:\033[0m %s\n' "$*" >&2; exit 1; }

cleanup() {
  local status=$?
  set +e
  [ -n "$PORT_FORWARD_PID" ] && kill "$PORT_FORWARD_PID" 2>/dev/null
  [ -n "$TLS_PROXY_PID" ] && kill "$TLS_PROXY_PID" 2>/dev/null
  if [ "$KEEP" = false ]; then
    log "Tearing down kind cluster '$CLUSTER_NAME'"
    "$KIND" delete cluster --name "$CLUSTER_NAME" >/dev/null 2>&1
  else
    warn "Leaving kind cluster '$CLUSTER_NAME' running (--keep). Delete with: kind delete cluster --name $CLUSTER_NAME"
  fi
  rm -rf "$WORKDIR"
  exit "$status"
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Step: prerequisites
# ---------------------------------------------------------------------------
step_prereqs() {
  log "Checking prerequisites"
  for bin in docker kubectl helm node npm python3 openssl; do
    command -v "$bin" >/dev/null 2>&1 || die "'$bin' is required but not found on PATH"
  done
  docker info >/dev/null 2>&1 || die "docker is not usable (daemon not running / no permission)"

  if command -v kind >/dev/null 2>&1; then
    KIND="kind"
  elif [ -x "$(go env GOPATH 2>/dev/null)/bin/kind" ]; then
    KIND="$(go env GOPATH)/bin/kind"
  else
    command -v go >/dev/null 2>&1 || die "'kind' not found and 'go' unavailable to install it"
    log "Installing kind via 'go install' (session-local, not added to shell profile)"
    go install sigs.k8s.io/kind@v0.27.0
    KIND="$(go env GOPATH)/bin/kind"
  fi

  if ! command -v bw >/dev/null 2>&1; then
    log "Installing Bitwarden CLI (bw) via npm -g"
    npm install -g @bitwarden/cli >/dev/null
  fi

  log "Installing e2e Node helper dependencies"
  (cd "$E2E_DIR" && npm install --no-audit --no-fund >/dev/null)
  (cd "$E2E_DIR" && npx --yes playwright install chromium >/dev/null)
}

# ---------------------------------------------------------------------------
# Step: offline checks (mirrors CI)
# ---------------------------------------------------------------------------
step_cargo_checks() {
  [ "$SKIP_CARGO" = true ] && { warn "Skipping cargo fmt/clippy/test (--skip-cargo)"; return; }
  log "cargo fmt --check"
  (cd "$ROOT_DIR" && cargo fmt --all --check)
  log "cargo clippy"
  (cd "$ROOT_DIR" && cargo clippy --all-targets --all-features -- -D warnings)
  log "cargo test"
  (cd "$ROOT_DIR" && cargo test --all-features)
}

# ---------------------------------------------------------------------------
# Step: ephemeral cluster + image
# ---------------------------------------------------------------------------
step_cluster_and_image() {
  log "Creating kind cluster '$CLUSTER_NAME'"
  "$KIND" create cluster --name "$CLUSTER_NAME"

  log "Building operator image ($IMAGE_TAG)"
  docker build -t "$IMAGE_TAG" "$ROOT_DIR"

  log "Loading image into kind"
  "$KIND" load docker-image "$IMAGE_TAG" --name "$CLUSTER_NAME"
}

# ---------------------------------------------------------------------------
# Step: throwaway Vaultwarden + seed a test item
# ---------------------------------------------------------------------------
step_vaultwarden() {
  log "Deploying throwaway Vaultwarden (namespace vw)"
  kubectl create namespace vw --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -n vw -f - >/dev/null <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vaultwarden
  namespace: vw
spec:
  replicas: 1
  selector:
    matchLabels: { app: vaultwarden }
  template:
    metadata:
      labels: { app: vaultwarden }
    spec:
      containers:
        - name: vaultwarden
          image: vaultwarden/server:latest
          env:
            - { name: SIGNUPS_ALLOWED, value: "true" }
            - { name: WEBSOCKET_ENABLED, value: "false" }
          ports:
            - containerPort: 80
          volumeMounts:
            - { name: data, mountPath: /data }
      volumes:
        - { name: data, emptyDir: {} }
---
apiVersion: v1
kind: Service
metadata:
  name: vaultwarden
  namespace: vw
spec:
  selector: { app: vaultwarden }
  ports:
    - { port: 80, targetPort: 80 }
EOF
  kubectl -n vw rollout status deployment/vaultwarden --timeout=120s

  log "Port-forwarding Vaultwarden locally"
  kubectl -n vw port-forward svc/vaultwarden "${VW_HTTP_PORT}:80" >"$WORKDIR/port-forward.log" 2>&1 &
  PORT_FORWARD_PID=$!
  for _ in $(seq 1 20); do
    curl -sf "http://127.0.0.1:${VW_HTTP_PORT}/" >/dev/null 2>&1 && break
    sleep 1
  done

  # The web vault signup flow refuses plain HTTP even on loopback, so front
  # the throwaway instance with a self-signed TLS proxy purely to satisfy it.
  log "Starting local TLS proxy for registration"
  openssl req -x509 -newkey rsa:2048 -keyout "$WORKDIR/key.pem" -out "$WORKDIR/cert.pem" \
    -days 1 -nodes -subj "/CN=127.0.0.1" >/dev/null 2>&1
  node "$E2E_DIR/tlsproxy.js" "$WORKDIR/cert.pem" "$WORKDIR/key.pem" "$TLS_PROXY_PORT" \
    "http://127.0.0.1:${VW_HTTP_PORT}" >"$WORKDIR/tlsproxy.log" 2>&1 &
  TLS_PROXY_PID=$!
  for _ in $(seq 1 20); do
    curl -sfk "https://127.0.0.1:${TLS_PROXY_PORT}/" >/dev/null 2>&1 && break
    sleep 1
  done

  log "Registering throwaway test account"
  node "$E2E_DIR/register.js" "https://127.0.0.1:${TLS_PROXY_PORT}" "$TEST_EMAIL" "$TEST_NAME" "$TEST_PASSWORD"

  log "Seeding a test vault item via bw CLI"
  bw logout >/dev/null 2>&1 || true
  bw config server "https://127.0.0.1:${TLS_PROXY_PORT}" >/dev/null
  # NODE_TLS_REJECT_UNAUTHORIZED=0 only trusts our own throwaway loopback
  # proxy's self-signed cert for this session; never used against a real server.
  BW_SESSION="$(NODE_TLS_REJECT_UNAUTHORIZED=0 bw login "$TEST_EMAIL" "$TEST_PASSWORD" --raw)"
  export BW_SESSION
  NODE_TLS_REJECT_UNAUTHORIZED=0 bw sync >/dev/null
  local item_json="$WORKDIR/item.json"
  cat >"$item_json" <<EOF
{"organizationId":null,"folderId":null,"type":1,"name":"test-secret","notes":null,"favorite":false,"reprompt":0,"login":{"username":"myuser","password":"s3cr3t-value-123","totp":null,"uris":[]},"fields":[],"passwordHistory":[]}
EOF
  local encoded
  encoded="$(NODE_TLS_REJECT_UNAUTHORIZED=0 bw encode <"$item_json")"
  NODE_TLS_REJECT_UNAUTHORIZED=0 bw create item "$encoded" >/dev/null
  ITEM_ID="$(NODE_TLS_REJECT_UNAUTHORIZED=0 bw list items --search test-secret | python3 -c 'import json,sys;print(json.load(sys.stdin)[0]["id"])')"
}

# ---------------------------------------------------------------------------
# Step: deploy operator via the real Helm chart (HA)
# ---------------------------------------------------------------------------
step_deploy_operator() {
  log "Installing operator via Helm chart (replicaCount=2)"
  kubectl create namespace vwo --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n vwo create secret generic vaultwarden-operator-credentials \
    --from-literal=VAULTWARDEN_URL="http://vaultwarden.vw.svc.cluster.local" \
    --from-literal=VAULTWARDEN_EMAIL="$TEST_EMAIL" \
    --from-literal=VAULTWARDEN_PASSWORD="$TEST_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  helm upgrade --install vwo "$ROOT_DIR/charts/vaultwarden-operator" \
    --namespace vwo \
    --set image.repository="${IMAGE_TAG%%:*}" \
    --set image.tag="${IMAGE_TAG##*:}" \
    --set image.pullPolicy=IfNotPresent \
    --set replicaCount=2 \
    --set networkPolicy.enabled=false \
    --wait --timeout=120s

  log "Applying test VaultwardenSecret CR"
  kubectl create namespace app-test --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl apply -n app-test -f - >/dev/null <<'EOF'
apiVersion: secrets.vaultwarden.io/v1alpha1
kind: VaultwardenSecret
metadata:
  name: test-secret
  namespace: app-test
spec:
  syncInterval: "5m"
  data:
    - key: password
      vaultwardenSecret: test-secret
EOF
}

# ---------------------------------------------------------------------------
# Step: verify happy path
# ---------------------------------------------------------------------------
step_verify_happy_path() {
  log "Verifying happy path"
  for _ in $(seq 1 20); do
    kubectl -n app-test get secret test-secret >/dev/null 2>&1 && break
    sleep 1
  done

  local holder value
  holder="$(kubectl -n vwo get lease vaultwarden-operator-leader -o jsonpath='{.spec.holderIdentity}')"
  [ -n "$holder" ] || die "no lease holder found"
  log "lease held by: $holder"

  local ready
  ready="$(kubectl -n app-test get vaultwardensecret test-secret -o jsonpath='{.status.ready}')"
  [ "$ready" = "true" ] || die "VaultwardenSecret status.ready != true (got: $ready)"

  value="$(kubectl -n app-test get secret test-secret -o jsonpath='{.data.password}' | base64 -d)"
  [ "$value" = "s3cr3t-value-123" ] || die "unexpected secret value: $value"
  log "happy path OK (secret value matches seeded vault item)"
}

# ---------------------------------------------------------------------------
# Step: failover
# ---------------------------------------------------------------------------
step_verify_failover() {
  log "Verifying failover"
  local old_holder new_holder
  old_holder="$(kubectl -n vwo get lease vaultwarden-operator-leader -o jsonpath='{.spec.holderIdentity}')"
  kubectl -n vwo delete pod "$old_holder"

  new_holder=""
  for _ in $(seq 1 30); do
    new_holder="$(kubectl -n vwo get lease vaultwarden-operator-leader -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
    [ -n "$new_holder" ] && [ "$new_holder" != "$old_holder" ] && break
    sleep 1
  done
  [ -n "$new_holder" ] && [ "$new_holder" != "$old_holder" ] || die "no new leader took over after deleting $old_holder"
  log "failover OK: leadership moved from $old_holder to $new_holder"

  if [ "$FAST" = true ]; then
    warn "Skipping post-failover reconcile propagation check (--fast); lease handoff was verified above"
    return
  fi

  log "Rotating vault item to verify reconciliation resumes under new leader (waits for the 5min cache refresh)"
  local updated
  updated="$(NODE_TLS_REJECT_UNAUTHORIZED=0 bw get item "$ITEM_ID" | python3 -c 'import json,sys; d=json.load(sys.stdin); d["login"]["password"]="rotated-value-456"; print(json.dumps(d))')"
  local encoded
  encoded="$(echo "$updated" | NODE_TLS_REJECT_UNAUTHORIZED=0 bw encode)"
  NODE_TLS_REJECT_UNAUTHORIZED=0 bw edit item "$ITEM_ID" "$encoded" >/dev/null

  local value=""
  for _ in $(seq 1 330); do
    value="$(kubectl -n app-test get secret test-secret -o jsonpath='{.data.password}' | base64 -d)"
    [ "$value" = "rotated-value-456" ] && break
    sleep 1
  done
  [ "$value" = "rotated-value-456" ] || die "secret did not pick up rotated value after failover (got: $value)"
  log "post-failover reconciliation OK"
}

# ---------------------------------------------------------------------------
# Step: API-key auth
# ---------------------------------------------------------------------------
step_verify_api_key_auth() {
  [ "$SKIP_API_KEY" = true ] && { warn "Skipping API-key auth test (--skip-api-key)"; return; }
  log "Fetching a personal API key for the test account (drives the web vault UI)"
  # `bw` has no non-interactive command for this -- same constraint as
  # register.js -- so it's scraped from the web vault's Settings > Security >
  # Keys > "View API key" flow via get-api-key.js.
  local api_key_json client_id client_secret
  api_key_json="$(node "$E2E_DIR/get-api-key.js" "https://127.0.0.1:${TLS_PROXY_PORT}" "$TEST_EMAIL" "$TEST_PASSWORD")"
  client_id="$(echo "$api_key_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientId"])')"
  client_secret="$(echo "$api_key_json" | python3 -c 'import json,sys; print(json.load(sys.stdin)["clientSecret"])')"
  [ -n "$client_id" ] && [ -n "$client_secret" ] || die "failed to obtain an API key for the test account"

  log "Adding VAULTWARDEN_CLIENT_ID/CLIENT_SECRET to the credentials Secret"
  kubectl -n vwo create secret generic vaultwarden-operator-credentials \
    --from-literal=VAULTWARDEN_URL="http://vaultwarden.vw.svc.cluster.local" \
    --from-literal=VAULTWARDEN_EMAIL="$TEST_EMAIL" \
    --from-literal=VAULTWARDEN_PASSWORD="$TEST_PASSWORD" \
    --from-literal=VAULTWARDEN_CLIENT_ID="$client_id" \
    --from-literal=VAULTWARDEN_CLIENT_SECRET="$client_secret" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  log "Restarting operator with API-key auth wired in via extraEnv (same mechanism documented in values.yaml)"
  local extra_env_json='[{"name":"VAULTWARDEN_CLIENT_ID","valueFrom":{"secretKeyRef":{"name":"vaultwarden-operator-credentials","key":"VAULTWARDEN_CLIENT_ID"}}},{"name":"VAULTWARDEN_CLIENT_SECRET","valueFrom":{"secretKeyRef":{"name":"vaultwarden-operator-credentials","key":"VAULTWARDEN_CLIENT_SECRET"}}}]'
  helm upgrade --install vwo "$ROOT_DIR/charts/vaultwarden-operator" \
    --namespace vwo \
    --set image.repository="${IMAGE_TAG%%:*}" \
    --set image.tag="${IMAGE_TAG##*:}" \
    --set image.pullPolicy=IfNotPresent \
    --set replicaCount=2 \
    --set networkPolicy.enabled=false \
    --set-json "extraEnv=$extra_env_json" \
    --wait --timeout=120s

  log "Waiting for the operator to authenticate over the API-key grant and become ready"
  local holder=""
  local vault_ready=false
  for _ in $(seq 1 30); do
    holder="$(kubectl -n vwo get lease vaultwarden-operator-leader -o jsonpath='{.spec.holderIdentity}' 2>/dev/null || true)"
    if [ -n "$holder" ] && kubectl -n vwo logs "$holder" --tail=50 2>/dev/null | grep -q "vault client ready"; then
      vault_ready=true
      break
    fi
    sleep 2
  done
  [ "$vault_ready" = true ] || die "operator did not authenticate/become ready after switching to API-key auth (holder: $holder)"
  # main.rs's initialize_vault_client() propagates auth failures via `?`, which
  # exits the process -- so a wrong client_id/secret shows up as CrashLoopBackOff,
  # not a hang. Confirm that didn't happen.
  local restarts
  restarts="$(kubectl -n vwo get pod "$holder" -o jsonpath='{.status.containerStatuses[0].restartCount}')"
  [ "$restarts" = "0" ] || die "operator pod restarted $restarts time(s) after switching to API-key auth (likely auth failure)"

  log "Confirming reconciliation still works over API-key auth"
  local value=""
  for _ in $(seq 1 30); do
    value="$(kubectl -n app-test get secret test-secret -o jsonpath='{.data.password}' 2>/dev/null | base64 -d 2>/dev/null || true)"
    [ -n "$value" ] && break
    sleep 1
  done
  [ -n "$value" ] || die "reconciliation did not produce a secret after switching to API-key auth"
  log "API-key auth OK: operator authenticated via VAULTWARDEN_CLIENT_ID/CLIENT_SECRET and reconciled"
}

# ---------------------------------------------------------------------------
# Step: negative RBAC test (silent-stall symptom)
# ---------------------------------------------------------------------------
step_verify_rbac_gap() {
  [ "$SKIP_RBAC_NEGATIVE" = true ] && { warn "Skipping RBAC-gap negative test (--skip-rbac-negative)"; return; }
  log "Verifying the RBAC-gap failure mode (leases permission missing)"

  kubectl create namespace vwo-norbac --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl -n vwo-norbac create secret generic vaultwarden-operator-credentials \
    --from-literal=VAULTWARDEN_URL="http://vaultwarden.vw.svc.cluster.local" \
    --from-literal=VAULTWARDEN_EMAIL="$TEST_EMAIL" \
    --from-literal=VAULTWARDEN_PASSWORD="$TEST_PASSWORD" \
    --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  local rendered="$WORKDIR/vwo-norbac.yaml"
  helm template vwo-norbac "$ROOT_DIR/charts/vaultwarden-operator" \
    --namespace vwo-norbac \
    --set image.repository="${IMAGE_TAG%%:*}" \
    --set image.tag="${IMAGE_TAG##*:}" \
    --set image.pullPolicy=IfNotPresent \
    --set replicaCount=1 \
    --set networkPolicy.enabled=false \
    --set installCRDs=false \
    >"$rendered"

  python3 - "$rendered" <<'PYEOF'
import re, sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
pattern = re.compile(
    r"  # Leader election Lease\n  - apiGroups:\n      - coordination\.k8s\.io\n"
    r"    resources:\n      - leases\n    verbs:\n(?:      - \w+\n)+",
    re.MULTILINE,
)
new_content, n = pattern.subn("", content)
if n != 1:
    sys.exit(f"expected to strip exactly 1 leases rule, stripped {n}")
with open(path, "w") as f:
    f.write(new_content)
PYEOF

  kubectl apply -f "$rendered" >/dev/null
  kubectl -n vwo-norbac wait --for=condition=Ready pod -l app.kubernetes.io/instance=vwo-norbac --timeout=60s

  sleep 10
  local logs
  logs="$(kubectl -n vwo-norbac logs deployment/vwo-norbac-vaultwarden-operator --tail=10)"
  echo "$logs" | grep -q "Forbidden" || die "expected Forbidden lease errors, got:
$logs"
  echo "$logs" | grep -q "running as leader" && die "operator became leader despite missing RBAC (test invalid)"
  log "RBAC-gap symptom reproduced: pod is Ready but stuck retrying (Forbidden), never reconciles"

  kubectl delete namespace vwo-norbac --wait=false >/dev/null
}

main() {
  step_prereqs
  step_cargo_checks
  step_cluster_and_image
  step_vaultwarden
  step_deploy_operator
  step_verify_happy_path
  step_verify_failover
  step_verify_api_key_auth
  step_verify_rbac_gap
  log "All e2e checks passed."
}

main
