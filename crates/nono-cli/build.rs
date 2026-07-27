//! Build script for nono-cli
//!
//! Embeds policy and hook scripts into the binary at compile time.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Rebuild if data files change
    println!("cargo:rerun-if-changed=data/");
    println!("cargo:rerun-if-env-changed=NONO_INSTALL_SOURCE");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir);

    // === Embed policy JSON ===
    let policy_path = Path::new("data/policy.json");
    if policy_path.exists() {
        let content = fs::read_to_string(policy_path).expect("Failed to read policy.json");

        // Write to OUT_DIR for include_str! macro
        fs::write(out_path.join("policy.json"), &content)
            .expect("Failed to write policy.json to OUT_DIR");

        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/policy.json not found");
        println!("cargo:rustc-env=POLICY_JSON_EMBEDDED=0");
    }

    // === Embed network policy JSON ===
    let net_policy_path = Path::new("data/network-policy.json");
    if net_policy_path.exists() {
        let content =
            fs::read_to_string(net_policy_path).expect("Failed to read network-policy.json");
        fs::write(out_path.join("network-policy.json"), &content)
            .expect("Failed to write network-policy.json to OUT_DIR");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=1");
    } else {
        println!("cargo:warning=data/network-policy.json not found");
        println!("cargo:rustc-env=NETWORK_POLICY_JSON_EMBEDDED=0");
    }

    // === Embed profile JSON Schema ===
    let schema_path = Path::new("data/nono-profile.schema.json");
    if schema_path.exists() {
        let content = fs::read_to_string(schema_path).expect("Failed to read profile schema");
        fs::write(out_path.join("nono-profile.schema.json"), &content)
            .expect("Failed to write profile schema to OUT_DIR");
    }

    // === Embed profile authoring guide ===
    let guide_path = Path::new("data/profile-authoring-guide.md");
    if guide_path.exists() {
        let content =
            fs::read_to_string(guide_path).expect("Failed to read profile authoring guide");
        fs::write(out_path.join("profile-authoring-guide.md"), &content)
            .expect("Failed to write profile authoring guide to OUT_DIR");
    }
}
