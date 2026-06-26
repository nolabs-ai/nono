//! Capability manifest types and operations
//!
//! This module provides the `CapabilityManifest` type (and related types) generated
//! from the JSON Schema at `schema/capability-manifest.schema.json` via typify.
//!
//! The JSON Schema is the source of truth. Rust types are derived from it at build
//! time — do not edit the generated types directly. To change the manifest format,
//! edit the schema and rebuild.
//!
//! # Usage
//!
//! ```
//! use nono::manifest::CapabilityManifest;
//!
//! let json = r#"{ "version": "0.1.0" }"#;
//! let manifest = CapabilityManifest::from_json(json).unwrap();
//! ```

// Include typify-generated types from build.rs.
// Suppress clippy warnings for generated code we don't control.
#[allow(
    clippy::derivable_impls,
    clippy::incompatible_msrv,
    clippy::unwrap_used
)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/capability_manifest_types.rs"));
}
pub use generated::*;

// Re-export the main type under a shorter name
pub use NonoCapabilityManifest as CapabilityManifest;

impl CapabilityManifest {
    /// Deserialize a capability manifest from a JSON string.
    pub fn from_json(json: &str) -> crate::Result<Self> {
        serde_json::from_str(json).map_err(|e| {
            crate::NonoError::ConfigParse(format!("invalid capability manifest JSON: {e}"))
        })
    }

    /// Serialize this manifest to a JSON string.
    pub fn to_json(&self) -> crate::Result<String> {
        serde_json::to_string_pretty(self).map_err(|e| {
            crate::NonoError::ConfigParse(format!("failed to serialize manifest: {e}"))
        })
    }

    /// Validate semantic constraints that the JSON Schema cannot express.
    ///
    /// Checks for:
    /// - `rollback.enabled` requires `exec_strategy: "supervised"`
    /// - `resources` (memory_bytes) require `exec_strategy: "supervised"`
    /// - URI manager credential sources require `env_var`
    /// - `url_path` inject mode requires `path_pattern`
    /// - `query_param` inject mode requires `query_param_name`
    pub fn validate(&self) -> crate::Result<()> {
        // rollback.enabled requires exec_strategy: "supervised"
        if let Some(ref rb) = self.rollback
            && rb.enabled
        {
            let exec_strategy = self
                .process
                .as_ref()
                .map_or(ExecStrategy::Monitor, |p| p.exec_strategy);
            if exec_strategy != ExecStrategy::Supervised {
                return Err(crate::NonoError::ConfigParse(
                    "rollback.enabled: true requires exec_strategy: \"supervised\" \
                     (rollback needs a parent process for snapshots)"
                        .to_string(),
                ));
            }
        }

        // Resource ceilings are enforced by the supervising parent, so they
        // require exec_strategy: "supervised". An empty `resources` object carries
        // no actual limit, so it is a no-op and does not trigger the requirement.
        if let Some(ref res) = self.resources
            && res.memory_bytes.is_some()
        {
            let exec_strategy = self
                .process
                .as_ref()
                .map_or(ExecStrategy::Monitor, |p| p.exec_strategy);
            if exec_strategy != ExecStrategy::Supervised {
                return Err(crate::NonoError::ConfigParse(
                    "resources (memory_bytes) require \
                     exec_strategy: \"supervised\" \
                     (limits are enforced by the supervising parent process)"
                        .to_string(),
                ));
            }
        }

        for cred in &self.credentials {
            // URI manager sources (op://, apple-password://, file://) need an
            // explicit env_var because uppercasing the URI produces a nonsensical
            // environment variable name. env:// is exempt: the var name is derived
            // from the URI itself.
            let source = cred.source.as_str();
            if (crate::keystore::is_op_uri(source)
                || crate::keystore::is_apple_password_uri(source)
                || crate::keystore::is_file_uri(source))
                && cred.env_var.is_none()
            {
                return Err(crate::NonoError::ConfigParse(format!(
                    "credential '{}': env_var is required when source is a URI manager \
                     reference (op://, apple-password://, or file://); \
                     set it to the SDK API key env var name (e.g., \"OPENAI_API_KEY\")",
                    cred.name.as_str()
                )));
            }

            if let Some(ref inject) = cred.inject {
                match inject.mode {
                    InjectMode::UrlPath if inject.path_pattern.is_none() => {
                        return Err(crate::NonoError::ConfigParse(format!(
                            "credential '{}': url_path inject mode requires path_pattern",
                            cred.name.as_str()
                        )));
                    }
                    InjectMode::QueryParam if inject.query_param_name.is_none() => {
                        return Err(crate::NonoError::ConfigParse(format!(
                            "credential '{}': query_param inject mode requires query_param_name",
                            cred.name.as_str()
                        )));
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod resource_tests {
    use super::*;

    #[test]
    fn resources_roundtrip_through_json() {
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 536870912 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        let res = manifest.resources.as_ref().expect("resources present");
        assert_eq!(res.memory_bytes.map(|n| n.get()), Some(536870912));
        manifest.validate().expect("valid: supervised");

        // Re-serialize and re-parse to confirm the field round-trips.
        let out = manifest.to_json().expect("serialize");
        let reparsed = CapabilityManifest::from_json(&out).expect("reparse");
        assert!(reparsed.resources.is_some());
    }

    #[test]
    fn empty_resources_is_a_noop() {
        let json = r#"{ "version": "0.1.0", "resources": {} }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        assert!(manifest.resources.is_some(), "resources object present");
        // Empty resources (no real limit) does not require supervised.
        manifest.validate().expect("empty resources is a no-op");
    }

    #[test]
    fn resources_require_supervised() {
        // Default exec_strategy is "monitor" (no process block at all).
        let json = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 1024 } }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        assert!(
            manifest.validate().is_err(),
            "memory_bytes without supervised must fail validation"
        );

        // Explicit non-supervised strategy also fails.
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "monitor" },
            "resources": { "memory_bytes": 1024 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn resources_reject_unknown_key() {
        // additionalProperties:false on Resources → deny_unknown_fields.
        let json = r#"{ "version": "0.1.0", "resources": { "memory_byte": 1024 } }"#;
        assert!(
            CapabilityManifest::from_json(json).is_err(),
            "a misspelled resource key must be a hard error, not silently dropped"
        );
    }

    // ---- Memory-only schema contract ----

    #[test]
    fn resources_rejects_removed_cpu_and_procs_keys() {
        // The memory-only contract: cpu_max_percent and max_procs were removed from
        // the Resources schema. Because Resources is additionalProperties:false
        // (generated as #[serde(deny_unknown_fields)]), a manifest still carrying
        // either must fail to PARSE — proving the removal is enforced by the schema,
        // not silently ignored at runtime.
        let with_cpu = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 1024, "cpu_max_percent": 50 }
        }"#;
        assert!(
            CapabilityManifest::from_json(with_cpu).is_err(),
            "cpu_max_percent was removed; a manifest carrying it must fail to parse"
        );

        let with_procs = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 1024, "max_procs": 10 }
        }"#;
        assert!(
            CapabilityManifest::from_json(with_procs).is_err(),
            "max_procs was removed; a manifest carrying it must fail to parse"
        );

        // Even as the sole resource key (no valid memory_bytes to anchor on).
        let cpu_only = r#"{ "version": "0.1.0", "resources": { "cpu_max_percent": 50 } }"#;
        assert!(
            CapabilityManifest::from_json(cpu_only).is_err(),
            "a removed key as the only resource must still be rejected"
        );
    }

    #[test]
    fn resources_unknown_key_alongside_valid_memory_fails_whole_manifest() {
        // A correct memory_bytes does not rescue an unknown sibling key: the whole
        // manifest must fail (additionalProperties:false / deny_unknown_fields on
        // Resources). This guards against a typo'd limit being silently dropped
        // while the rest of the manifest is accepted.
        let json = r#"{
            "version": "0.1.0",
            "process": { "exec_strategy": "supervised" },
            "resources": { "memory_bytes": 536870912, "totally_bogus": true }
        }"#;
        assert!(
            CapabilityManifest::from_json(json).is_err(),
            "unknown sibling of a valid memory_bytes must fail the whole manifest"
        );
    }

    #[test]
    fn resources_rejects_zero_and_negative_memory_via_schema_minimum() {
        // schema minimum:1 is generated as Option<NonZeroU64>, so a zero or negative
        // ceiling fails at parse time — a limit of 0 can never be mistaken for
        // "unlimited", and a negative number can never fit an unsigned ceiling.
        let zero = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 0 } }"#;
        assert!(
            CapabilityManifest::from_json(zero).is_err(),
            "memory_bytes: 0 violates minimum:1 (NonZeroU64) and must fail to parse"
        );

        let negative = r#"{ "version": "0.1.0", "resources": { "memory_bytes": -1 } }"#;
        assert!(
            CapabilityManifest::from_json(negative).is_err(),
            "negative memory_bytes cannot fit an unsigned ceiling and must fail to parse"
        );
    }

    #[test]
    fn validate_memory_unsupervised_yields_configparse_variant() {
        // memory_bytes present + default (monitor) strategy: validate() must reject
        // specifically via the public NonoError::ConfigParse variant (the same error
        // surface the CLI relies on for a clean message). The reject/accept/no-op
        // behaviour itself is covered by resources_require_supervised /
        // empty_resources_is_a_noop; this pins the variant.
        let unsupervised = r#"{ "version": "0.1.0", "resources": { "memory_bytes": 1024 } }"#;
        let manifest = CapabilityManifest::from_json(unsupervised).expect("parse");
        let err = manifest
            .validate()
            .expect_err("memory limit without supervised must be rejected");
        assert!(
            matches!(err, crate::NonoError::ConfigParse(_)),
            "expected ConfigParse, got {err:?}"
        );
    }
}
