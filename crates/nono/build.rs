//! Build script for the nono library.
//!
//! Generates Rust types from the capability manifest JSON Schema using typify.
//! The JSON Schema is the source of truth; Rust types are derived from it.
//!
//! Embeds the source revision as `NONO_BUILD_REV` for [`crate::build_info`]:
//! read from Git, or from that variable when a packager sets it; `unknown`
//! otherwise.

use std::env;
use std::fs;
use std::path::Path;

const REV_ENV: &str = "NONO_BUILD_REV";

const SHORT_REV_LEN: usize = 10;

fn main() {
    generate_capability_types();
    embed_revision();
}

fn generate_capability_types() {
    println!("cargo:rerun-if-changed=schema/capability-manifest.schema.json");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");

    let schema_str = include_str!("schema/capability-manifest.schema.json");
    let schema = serde_json::from_str::<serde_json::Value>(schema_str)
        .expect("capability-manifest.schema.json is not valid JSON");

    let mut type_space =
        typify::TypeSpace::new(typify::TypeSpaceSettings::default().with_struct_builder(true));

    type_space
        .add_root_schema(serde_json::from_value(schema).expect("schema is not valid JSON Schema"))
        .expect("failed to process capability manifest schema");

    let contents = prettyplease::unparse(
        &syn::parse2::<syn::File>(type_space.to_stream())
            .expect("failed to parse generated tokens"),
    );

    let out_path = Path::new(&out_dir).join("capability_manifest_types.rs");
    fs::write(&out_path, contents).expect("failed to write generated types");
}

fn embed_revision() {
    println!("cargo:rerun-if-env-changed={REV_ENV}");

    let rev = env::var(REV_ENV)
        .map(|value| shorten(&value))
        .unwrap_or_else(|_| discover_rev().unwrap_or_else(|| "unknown".to_string()));

    println!("cargo:rustc-env={REV_ENV}={rev}");
}

/// Truncates to the short form, keeping a `-dirty` suffix so local builds of an
/// uncommitted tree are not mistaken for the commit they started from.
fn shorten(value: &str) -> String {
    let value = value.trim();
    let (hash, dirty) = match value.strip_suffix("-dirty") {
        Some(hash) => (hash, true),
        None => (value, false),
    };
    let mut rev: String = hash.chars().take(SHORT_REV_LEN).collect();
    if dirty {
        rev.push_str("-dirty");
    }
    rev
}

fn discover_rev() -> Option<String> {
    let repo = gix::discover(".").ok()?;

    // Cargo re-runs this script only for the paths named here; without them a
    // new commit or a staged change would leave the embedded revision stale.
    let git_dir = repo.git_dir();
    for path in [
        git_dir.join("HEAD"),
        git_dir.join("packed-refs"),
        git_dir.join("index"),
        repo.common_dir().join("refs"),
    ] {
        if path.exists() {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    // Fixed width; short_id() would vary with repository size.
    let commit = repo.head_commit().ok()?;
    let mut rev = commit.id.to_hex_with_len(SHORT_REV_LEN).to_string();

    // Untracked files do not mark the tree dirty, matching `git describe
    // --dirty`.
    if matches!(repo.is_dirty(), Ok(true)) {
        rev.push_str("-dirty");
    }
    Some(rev)
}
