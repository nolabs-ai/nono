//! Build script for nono library
//!
//! Generates Rust types from the capability manifest JSON Schema using typify.
//! The JSON Schema is the source of truth; Rust types are derived from it.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    println!("cargo:rerun-if-changed=schema/capability-manifest.schema.json");

    let out_dir = env::var("OUT_DIR").expect("OUT_DIR not set");

    let schema_str = include_str!("schema/capability-manifest.schema.json");
    let schema = serde_json::from_str::<serde_json::Value>(schema_str)
        .expect("capability-manifest.schema.json is not valid JSON");

    let mut type_space = typify::TypeSpace::new(
        typify::TypeSpaceSettings::default()
            .map_typespace_settings(|settings| settings.with_struct_builder(true)),
    );

    type_space
        .add_root_schema(serde_json::from_value(schema).expect("schema is not valid JSON Schema"))
        .expect("failed to process capability manifest schema");

    let contents = prettyplease::unparse(
        &syn::parse2::<syn::File>(
            type_space
                .to_stream()
                .expect("failed to generate capability manifest types"),
        )
        .expect("failed to parse generated tokens"),
    );

    let out_path = Path::new(&out_dir).join("capability_manifest_types.rs");
    fs::write(&out_path, contents).expect("failed to write generated types");
}
