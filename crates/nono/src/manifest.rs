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
    /// - URI manager credential sources require `env_var`
    /// - `url_path` inject mode requires `path_pattern`
    /// - `query_param` inject mode requires `query_param_name`
    pub fn validate(&self) -> crate::Result<()> {
        // rollback.enabled requires exec_strategy: "supervised"
        if let Some(ref rb) = self.rollback {
            if rb.enabled {
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
        }

        for cred in &self.credentials {
            // URI manager sources (op://, apple-password://, file://) need an
            // explicit env_var because uppercasing the URI produces a nonsensical
            // environment variable name.
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
