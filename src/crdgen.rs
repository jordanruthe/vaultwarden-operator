//! Generates the CRD YAML to stdout.
//!
//! Usage: `cargo run --bin crdgen > config/crd/vaultwardensecret.yaml`

mod crd;

use crd::VaultwardenSecret;
use kube::CustomResourceExt;

fn main() {
    let crd = VaultwardenSecret::crd();
    let yaml = serde_yaml::to_string(&crd).expect("serialize CRD");
    print!("{yaml}");
}
