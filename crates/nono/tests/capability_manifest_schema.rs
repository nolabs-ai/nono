//! Tests for the capability manifest JSON Schema.
//!
//! Validates that the schema itself is valid JSON Schema Draft 2020-12,
//! that well-formed manifests pass validation, and that malformed manifests
//! are rejected.

const SCHEMA_STR: &str = include_str!("../schema/capability-manifest.schema.json");

/// Helper: validate a JSON string against the capability manifest schema.
fn validate_against_schema(json_str: &str) -> Result<(), String> {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_STR).expect("schema is valid JSON");
    let instance: serde_json::Value =
        serde_json::from_str(json_str).expect("instance is valid JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let errors: Vec<_> = validator.iter_errors(&instance).collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors
            .iter()
            .map(|e| format!("{} at {}", e, e.instance_path()))
            .collect::<Vec<_>>()
            .join("; "))
    }
}

#[test]
fn schema_is_valid_json() {
    let _: serde_json::Value = serde_json::from_str(SCHEMA_STR).expect("schema is valid JSON");
}

#[test]
fn schema_compiles_as_json_schema() {
    let schema: serde_json::Value = serde_json::from_str(SCHEMA_STR).expect("schema is valid JSON");
    jsonschema::validator_for(&schema).expect("schema should compile as a JSON Schema validator");
}

#[test]
fn minimal_manifest_with_version_only() {
    let json = r#"{ "version": "0.1.0" }"#;
    validate_against_schema(json).expect("version-only manifest should be valid");
}

#[test]
fn manifest_with_empty_capabilities() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": { "grants": [], "deny": [] },
        "network": {},
        "credentials": [],
        "process": {},
        "rollback": {}
    }"#;
    validate_against_schema(json).expect("manifest with empty capabilities should be valid");
}

#[test]
fn filesystem_grant_read_directory() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/workspace", "access": "read" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("read directory grant should be valid");
}

#[test]
fn filesystem_grant_readwrite_file() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp/output.log", "access": "readwrite", "type": "file" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("readwrite file grant should be valid");
}

#[test]
fn filesystem_grant_with_home_tilde() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "~/.config/my-app", "access": "read", "type": "directory" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("tilde home path should be valid");
}

#[test]
fn filesystem_deny_paths() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "deny": [
                { "path": "~/.ssh" },
                { "path": "~/.aws" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("deny paths should be valid");
}

#[test]
fn filesystem_grants_and_deny_combined() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "~", "access": "read" }
            ],
            "deny": [
                { "path": "~/.ssh" },
                { "path": "~/.gnupg" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("combined grants and deny should be valid");
}

#[test]
fn rejects_filesystem_grant_missing_path() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "access": "read" }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "grant without path should be rejected"
    );
}

#[test]
fn rejects_filesystem_grant_missing_access() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp" }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "grant without access should be rejected"
    );
}

#[test]
fn rejects_filesystem_grant_invalid_access_mode() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp", "access": "execute" }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid access mode should be rejected"
    );
}

#[test]
fn rejects_filesystem_grant_empty_path() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "", "access": "read" }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "empty path should be rejected"
    );
}

#[test]
fn rejects_filesystem_grant_invalid_type() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/tmp", "access": "read", "type": "symlink" }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid fs entry type should be rejected"
    );
}

#[test]
fn network_blocked_mode() {
    let json = r#"{
        "version": "0.1.0",
        "network": { "mode": "blocked" }
    }"#;
    validate_against_schema(json).expect("blocked network mode should be valid");
}

#[test]
fn network_proxy_with_domains() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "mode": "proxy",
            "allow_domains": ["api.github.com", ".googleapis.com"]
        }
    }"#;
    validate_against_schema(json).expect("proxy mode with domains should be valid");
}

#[test]
fn network_with_l7_endpoints() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "mode": "proxy",
            "endpoints": [
                {
                    "host": "api.github.com:443",
                    "rules": [
                        { "method": "GET", "path": "/repos/*/issues/**" },
                        { "method": "POST", "path": "/repos/*/issues/*/comments" }
                    ]
                }
            ]
        }
    }"#;
    validate_against_schema(json).expect("L7 endpoint filtering should be valid");
}

#[test]
fn network_endpoint_without_rules_allows_all() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "mode": "proxy",
            "endpoints": [
                { "host": "api.github.com:443" }
            ]
        }
    }"#;
    validate_against_schema(json).expect("endpoint without rules (allow-all) should be valid");
}

#[test]
fn network_with_ports() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "mode": "proxy",
            "ports": {
                "connect": [443, 8080],
                "bind": [3000],
                "localhost": [5432]
            }
        }
    }"#;
    validate_against_schema(json).expect("port config should be valid");
}

#[test]
fn rejects_network_invalid_mode() {
    let json = r#"{
        "version": "0.1.0",
        "network": { "mode": "allow_all" }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid network mode should be rejected"
    );
}

#[test]
fn rejects_network_endpoint_missing_host() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "endpoints": [
                { "rules": [{ "method": "GET", "path": "/" }] }
            ]
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "endpoint without host should be rejected"
    );
}

#[test]
fn rejects_network_port_out_of_range() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "ports": { "connect": [0] }
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "port 0 should be rejected"
    );
}

#[test]
fn rejects_network_port_above_max() {
    let json = r#"{
        "version": "0.1.0",
        "network": {
            "ports": { "connect": [65536] }
        }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "port 65536 should be rejected"
    );
}

#[test]
fn credential_with_header_injection() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com",
                "source": "env://GITHUB_TOKEN",
                "inject": {
                    "mode": "header",
                    "header": "Authorization",
                    "format": "Bearer {}"
                }
            }
        ]
    }"#;
    validate_against_schema(json).expect("credential with header injection should be valid");
}

#[test]
fn credential_with_file_source() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "gitlab",
                "upstream": "https://gitlab.example.com",
                "source": "file:///vault/secrets/gitlab-token",
                "inject": {
                    "mode": "header",
                    "header": "PRIVATE-TOKEN",
                    "format": "{}"
                }
            }
        ]
    }"#;
    validate_against_schema(json).expect("file:// credential source should be valid");
}

#[test]
fn credential_with_url_path_injection() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "telegram",
                "upstream": "https://api.telegram.org",
                "source": "op://vault/telegram/token",
                "inject": {
                    "mode": "url_path",
                    "path_pattern": "/bot{}/",
                    "path_replacement": "/bot{}/"
                }
            }
        ]
    }"#;
    validate_against_schema(json).expect("credential with url_path injection should be valid");
}

#[test]
fn credential_with_endpoint_rules() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com",
                "source": "env://GITHUB_TOKEN",
                "endpoint_rules": [
                    { "method": "GET", "path": "/repos/*/issues/**" },
                    { "method": "POST", "path": "/repos/*/issues/*/comments" }
                ]
            }
        ]
    }"#;
    validate_against_schema(json).expect("credential with endpoint rules should be valid");
}

#[test]
fn credential_minimal() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com",
                "source": "github_token"
            }
        ]
    }"#;
    validate_against_schema(json).expect("minimal credential (bare keystore name) should be valid");
}

#[test]
fn rejects_credential_missing_name() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "upstream": "https://api.github.com",
                "source": "env://GITHUB_TOKEN"
            }
        ]
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "credential without name should be rejected"
    );
}

#[test]
fn rejects_credential_missing_upstream() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "source": "env://GITHUB_TOKEN"
            }
        ]
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "credential without upstream should be rejected"
    );
}

#[test]
fn rejects_credential_missing_source() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com"
            }
        ]
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "credential without source should be rejected"
    );
}

#[test]
fn rejects_credential_invalid_inject_mode() {
    let json = r#"{
        "version": "0.1.0",
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com",
                "source": "env://GITHUB_TOKEN",
                "inject": { "mode": "cookie" }
            }
        ]
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid inject mode should be rejected"
    );
}

#[test]
fn process_with_all_fields() {
    let json = r#"{
        "version": "0.1.0",
        "process": {
            "allowed_commands": ["git", "npm"],
            "blocked_commands": ["rm", "sudo"],
            "signal_mode": "allow_same_sandbox",
            "process_info_mode": "isolated",
            "ipc_mode": "full",
            "exec_strategy": "supervised"
        }
    }"#;
    validate_against_schema(json).expect("process with all fields should be valid");
}

#[test]
fn rejects_invalid_signal_mode() {
    let json = r#"{
        "version": "0.1.0",
        "process": { "signal_mode": "permissive" }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid signal mode should be rejected"
    );
}

#[test]
fn rejects_invalid_exec_strategy() {
    let json = r#"{
        "version": "0.1.0",
        "process": { "exec_strategy": "fork" }
    }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "invalid exec strategy should be rejected"
    );
}

#[test]
fn rollback_config() {
    let json = r#"{
        "version": "0.1.0",
        "rollback": {
            "enabled": true,
            "exclude_patterns": ["node_modules", ".git"],
            "exclude_globs": ["*.log", "*.tmp"]
        }
    }"#;
    validate_against_schema(json).expect("rollback config should be valid");
}

#[test]
fn rejects_missing_version() {
    let json = r#"{ "filesystem": { "grants": [] } }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "manifest without version should be rejected"
    );
}

#[test]
fn rejects_invalid_version_format() {
    let json = r#"{ "version": "1.0" }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "non-semver version should be rejected"
    );
}

#[test]
fn rejects_wrong_version_value() {
    let json = r#"{ "version": "2.0.0" }"#;
    assert!(
        validate_against_schema(json).is_err(),
        "unsupported version should be rejected"
    );
}

#[test]
fn full_realistic_manifest() {
    let json = r#"{
        "version": "0.1.0",
        "filesystem": {
            "grants": [
                { "path": "/workspace", "access": "readwrite" },
                { "path": "/usr/lib", "access": "read" },
                { "path": "/tmp/output.log", "access": "readwrite", "type": "file" }
            ],
            "deny": [
                { "path": "~/.ssh" },
                { "path": "~/.aws" },
                { "path": "~/.gnupg" }
            ]
        },
        "network": {
            "mode": "proxy",
            "allow_domains": [".googleapis.com"],
            "endpoints": [
                {
                    "host": "api.github.com:443",
                    "rules": [
                        { "method": "GET", "path": "/repos/*/issues/**" },
                        { "method": "POST", "path": "/repos/*/issues/*/comments" }
                    ]
                }
            ],
            "ports": {
                "localhost": [5432, 6379]
            },
            "dns": true
        },
        "credentials": [
            {
                "name": "github",
                "upstream": "https://api.github.com",
                "source": "file:///vault/secrets/github-token",
                "inject": {
                    "mode": "header",
                    "header": "Authorization",
                    "format": "Bearer {}"
                },
                "endpoint_rules": [
                    { "method": "GET", "path": "/repos/*/issues/**" },
                    { "method": "POST", "path": "/repos/*/issues/*/comments" }
                ]
            }
        ],
        "process": {
            "allowed_commands": ["git", "npm", "node"],
            "blocked_commands": ["rm", "sudo", "chmod"],
            "signal_mode": "allow_same_sandbox",
            "process_info_mode": "isolated",
            "ipc_mode": "full",
            "exec_strategy": "supervised"
        },
        "rollback": {
            "enabled": true,
            "exclude_patterns": ["node_modules", ".git"],
            "exclude_globs": ["*.log"]
        }
    }"#;
    validate_against_schema(json).expect("full realistic manifest should be valid");
}
