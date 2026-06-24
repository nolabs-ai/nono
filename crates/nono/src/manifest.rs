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
    /// - `resources` (memory_bytes/cpu_max_percent/max_procs) require `exec_strategy: "supervised"`
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
        // require exec_strategy: "supervised". A bare `backend` with no actual
        // limit is a no-op and does not trigger the requirement.
        if let Some(ref res) = self.resources
            && (res.memory_bytes.is_some()
                || res.cpu_max_percent.is_some()
                || res.max_procs.is_some())
        {
            let exec_strategy = self
                .process
                .as_ref()
                .map_or(ExecStrategy::Monitor, |p| p.exec_strategy);
            if exec_strategy != ExecStrategy::Supervised {
                return Err(crate::NonoError::ConfigParse(
                    "resources (memory_bytes/cpu_max_percent/max_procs) require \
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
            "resources": { "memory_bytes": 536870912, "cpu_max_percent": 150, "max_procs": 64 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        let res = manifest.resources.as_ref().expect("resources present");
        assert_eq!(res.memory_bytes.map(|n| n.get()), Some(536870912));
        assert_eq!(res.cpu_max_percent.map(|n| n.get()), Some(150));
        assert_eq!(res.max_procs.map(|n| n.get()), Some(64));
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
            "resources": { "max_procs": 8 }
        }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        assert!(manifest.validate().is_err());

        // A cpu-only limit equally requires supervised.
        let json = r#"{ "version": "0.1.0", "resources": { "cpu_max_percent": 50 } }"#;
        let manifest = CapabilityManifest::from_json(json).expect("parse");
        assert!(
            manifest.validate().is_err(),
            "cpu_max_percent without supervised must fail validation"
        );
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
}
