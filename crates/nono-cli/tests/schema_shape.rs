//! Snapshot tests for the checked-in JSON profile schema.
//!
//! These tests assert the canonical shape of
//! `crates/nono-cli/data/nono-profile.schema.json` after issue #594
//! phase 2 restructuring. Any future accidental reintroduction of the
//! legacy patch namespace or legacy security subkeys will fail here.

use serde_json::{Value, json};
use std::collections::BTreeSet;

fn load_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("nono-profile.schema.json");
    let content = std::fs::read_to_string(&path).expect("read embedded profile schema");
    serde_json::from_str(&content).expect("embedded profile schema is valid JSON")
}

fn assert_properties_at(schema: &Value, pointer: &str, label: &str, expected: &[&str]) {
    let props = schema
        .pointer(pointer)
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{pointer} is an object"));
    let actual = props.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "{label}.properties must match the Rust command-policy model"
    );
}

fn assert_schema_properties(schema: &Value, def_name: &str, expected: &[&str]) {
    assert_properties_at(
        schema,
        &format!("/$defs/{def_name}/properties"),
        def_name,
        expected,
    );
}

#[test]
fn test_schema_has_canonical_top_level_groups() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/groups").is_some(),
        "schema is missing canonical /properties/groups"
    );
}

#[test]
fn test_schema_has_canonical_top_level_commands() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/commands").is_some(),
        "schema is missing canonical /properties/commands"
    );
}

#[test]
fn test_schema_network_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "NetworkConfig",
        &[
            "block",
            "allow_http2",
            "network_profile",
            "allow_domain",
            "proxy_allow",
            "allow_proxy",
            "deny_domain",
            "credentials",
            "proxy_credentials",
            "open_port",
            "port_allow",
            "allow_port",
            "open_port_range",
            "listen_port",
            "listen_port_range",
            "connect_port",
            "no_proxy",
            "custom_credentials",
            "tls_intercept",
            "upstream_proxy",
            "external_proxy",
            "upstream_bypass",
            "external_proxy_bypass",
        ],
    );
}

#[test]
fn test_schema_top_level_profile_matches_rust_model() {
    let schema = load_schema();
    assert_properties_at(
        &schema,
        "/properties",
        "Profile",
        &[
            "$schema",
            "extends",
            "meta",
            "security",
            "groups",
            "commands",
            "filesystem",
            "network",
            "diagnostics",
            "linux",
            "env_credentials",
            "secrets",
            "environment",
            "command_policies",
            "credential_capture",
            "credential_providers",
            "credential_routes",
            "workdir",
            "hooks",
            "session_hooks",
            "rollback",
            "undo",
            "open_urls",
            "allow_launch_services",
            "allow_gpu",
            "allow_parent_of_protected",
            "interactive",
            "skipdirs",
            "packs",
            "binary",
            "command_args",
            "unsafe_macos_seatbelt_rules",
            "platform_overrides",
        ],
    );
}

#[test]
fn test_schema_validates_profile_with_platform_overrides_skipdirs_binary() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "skipdirs": ["vendor"],
        "binary": "node",
        "allow_parent_of_protected": true,
        "platform_overrides": {
            "macos": {
                "network": { "block": true }
            },
            "linux": {
                "filesystem": { "allow": ["/tmp"] }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("skipdirs/binary/allow_parent_of_protected/platform_overrides should validate");
}

#[test]
fn test_schema_validates_explicit_null_platform_overrides_inside_override() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    // platform_overrides: null deserializes to the same None as an omitted field
    // (Option<PlatformOverrides>), so PlatformOverride::deserialize accepts it —
    // the schema must not flag it as illegal nesting.
    let profile = json!({
        "platform_overrides": {
            "macos": {
                "network": { "block": true },
                "platform_overrides": null
            }
        }
    });

    validator
        .validate(&profile)
        .expect("explicit null platform_overrides inside an override block should validate");
}

#[test]
fn test_schema_rejects_nested_extends_in_platform_overrides() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "platform_overrides": {
            "macos": {
                "extends": "base"
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "nesting extends inside platform_overrides must fail schema validation, \
         matching PlatformOverride::deserialize's parse error"
    );
}

#[test]
fn test_schema_rejects_nested_platform_overrides_in_platform_overrides() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "platform_overrides": {
            "linux": {
                "platform_overrides": {
                    "macos": { "network": { "block": true } }
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "nesting platform_overrides inside platform_overrides must fail schema validation, \
         matching PlatformOverride::deserialize's parse error"
    );
}

#[test]
fn test_schema_oauth2_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "OAuth2Config",
        &[
            "token_url",
            "client_id",
            "client_secret",
            "scope",
            "client_assertion",
            "extra_params",
        ],
    );
    assert_properties_at(
        &schema,
        "/$defs/ClientAssertionConfig/oneOf/0/properties",
        "ClientAssertionConfig",
        &["type", "workload_api_socket", "audience", "svid_hint"],
    );
}

#[test]
fn test_schema_rejects_oauth2_with_null_client_assertion_and_no_credentials() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    // client_assertion: null is indistinguishable from omitted once deserialized
    // (both become None), so this must be rejected exactly like an oauth2 config
    // with no credentials at all — see validate_oauth2_auth's client_id.is_empty()
    // fallback path in crates/nono-cli/src/profile/mod.rs.
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "auth": {
                        "token_url": "https://auth.example.com/oauth/token",
                        "client_assertion": null
                    }
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "oauth2 config with client_assertion explicitly null and no client_id/client_secret \
         must fail schema validation, matching the Rust loader's rejection"
    );
}

#[test]
fn test_schema_validates_oauth2_with_client_assertion() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "auth": {
                        "token_url": "https://auth.example.com/oauth/token",
                        "client_assertion": {
                            "type": "spiffe_jwt",
                            "workload_api_socket": "/run/spire/sockets/agent.sock",
                            "audience": ["auth.example.com"]
                        }
                    }
                }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("oauth2 with client_assertion (no client_id/client_secret) should validate");
}

#[test]
fn test_schema_validates_client_id_secret_with_explicit_null_client_assertion() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    // client_assertion: null deserializes to the same None as an omitted field
    // (Option<ClientAssertionConfig>), so it must not be flagged as a conflict
    // with client_id/client_secret.
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "auth": {
                        "token_url": "https://auth.example.com/oauth/token",
                        "client_id": "abc",
                        "client_secret": "xyz",
                        "client_assertion": null
                    }
                }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("client_id/client_secret with explicitly-null client_assertion should validate");
}

#[test]
fn test_schema_rejects_oauth2_without_credentials_or_assertion() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "auth": {
                        "token_url": "https://auth.example.com/oauth/token"
                    }
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "oauth2 config with neither client_id/client_secret nor client_assertion must fail schema validation"
    );
}

#[test]
fn test_schema_rejects_oauth2_with_client_id_and_assertion() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "auth": {
                        "token_url": "https://auth.example.com/oauth/token",
                        "client_id": "abc",
                        "client_assertion": {
                            "type": "spiffe_jwt",
                            "workload_api_socket": "/run/spire/sockets/agent.sock",
                            "audience": ["auth.example.com"]
                        }
                    }
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "oauth2 config combining client_id with client_assertion must fail schema validation"
    );
}

#[test]
fn test_schema_rejects_custom_credential_with_spiffe_and_credential_key() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "credential_key": "internal_api_token",
                    "spiffe": {
                        "type": "jwt",
                        "workload_api_socket": "/run/spire/sockets/agent.sock",
                        "audience": ["internal-api"]
                    }
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "custom credential combining spiffe with credential_key must fail schema validation"
    );
}

#[test]
fn test_schema_validates_credential_key_with_explicit_null_spiffe_and_aws_auth() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    // spiffe: null / aws_auth: null deserialize to the same None as omitting the
    // field entirely, so this must NOT be flagged as a mutual-exclusion conflict
    // with credential_key.
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "credential_key": "internal_api_token",
                    "spiffe": null,
                    "aws_auth": null
                }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("credential_key with explicitly-null spiffe/aws_auth should validate");
}

#[test]
fn test_schema_validates_aws_auth_with_explicit_null_credential_key_and_auth() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    // credential_key/auth are Option<T> in Rust, so an explicit null deserializes
    // identically to an omitted field and must not be treated as a conflict.
    let profile = json!({
        "network": { "custom_credentials": { "internal-api": {
            "upstream": "https://internal.example.com",
            "credential_key": null,
            "auth": null,
            "aws_auth": { "region": "us-east-1" }
        } } }
    });

    validator
        .validate(&profile)
        .expect("aws_auth with explicitly-null credential_key/auth should validate");
}

#[test]
fn test_schema_rejects_custom_credential_with_no_auth_mechanism() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com"
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "custom credential with none of credential_key/auth/aws_auth/spiffe set \
         must fail schema validation, matching validate_custom_credential's \
         'must have either ... set' check"
    );
}

#[test]
fn test_schema_custom_credential_def_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "CustomCredentialDef",
        &[
            "upstream",
            "credential_key",
            "auth",
            "aws_auth",
            "spiffe",
            "inject_mode",
            "inject_header",
            "credential_format",
            "path_pattern",
            "path_replacement",
            "query_param_name",
            "proxy",
            "env_var",
            "endpoint_rules",
            "endpoint_policy",
            "tls_ca",
            "tls_client_cert",
            "tls_client_key",
            "rate_limit",
            "redeem_phantoms",
        ],
    );
}

#[test]
fn test_schema_validates_custom_credential_with_spiffe_and_endpoint_policy() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "network": {
            "custom_credentials": {
                "internal-api": {
                    "upstream": "https://internal.example.com",
                    "spiffe": {
                        "type": "jwt",
                        "workload_api_socket": "/run/spire/sockets/agent.sock",
                        "audience": ["internal-api"]
                    },
                    "endpoint_policy": {
                        "default": "deny",
                        "allow": [{ "method": "GET", "path": "/health" }]
                    }
                }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("custom credential with spiffe and endpoint_policy should validate");
}

#[test]
fn test_schema_has_linux_af_unix_mediation() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/linux").is_some(),
        "schema is missing canonical /properties/linux"
    );
    let props = schema
        .pointer("/$defs/LinuxConfig/properties")
        .and_then(Value::as_object)
        .expect("LinuxConfig.properties is an object");
    assert!(
        props.contains_key("af_unix_mediation"),
        "LinuxConfig.af_unix_mediation missing from canonical schema"
    );
}

#[test]
fn test_schema_groups_has_include_and_exclude() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/GroupsConfig/properties")
        .and_then(Value::as_object)
        .expect("GroupsConfig.properties is an object");
    assert!(
        props.contains_key("include"),
        "GroupsConfig.include missing"
    );
    assert!(
        props.contains_key("exclude"),
        "GroupsConfig.exclude missing"
    );
}

#[test]
fn test_schema_commands_has_allow_and_deny() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/CommandsConfig/properties")
        .and_then(Value::as_object)
        .expect("CommandsConfig.properties is an object");
    assert!(props.contains_key("allow"), "CommandsConfig.allow missing");
    assert!(props.contains_key("deny"), "CommandsConfig.deny missing");
}

#[test]
fn test_schema_command_policies_match_tool_sandbox_guide_shape() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "CommandPoliciesConfig",
        &[
            "approval_backends",
            "approval_defaults",
            "allow_writable_executables",
            "commands",
            "credentials",
            "deny_direct_exec_bypass",
            "entrypoint",
            "executable_dirs",
            "session_export_env",
        ],
    );
    assert_schema_properties(
        &schema,
        "ApprovalDefaultsConfig",
        &["backend", "timeout_secs"],
    );
    assert_schema_properties(
        &schema,
        "ApprovalBackendConfig",
        &["backends", "mode", "timeout_secs", "type", "url"],
    );
    assert_schema_properties(
        &schema,
        "CommandCredentialConfig",
        &[
            "base_url_env_var",
            "credential_format",
            "credential_key",
            "env_var",
            "format",
            "inject_header",
            "mode",
            "path",
            "source",
            "tls_ca",
            "tls_client_cert",
            "tls_client_key",
            "type",
            "upstream",
        ],
    );
    assert_schema_properties(&schema, "InterceptRuleConfig", &["action", "args", "match"]);
    assert_schema_properties(&schema, "InterceptRuleMatchConfig", &["argv", "env"]);
    assert_schema_properties(
        &schema,
        "CommandPolicyConfig",
        &[
            "allow_direct_exec_bypass",
            "allow_direct_exec_bypass_with_credentials",
            "allow_writable_executable",
            "can_use",
            "daemon_pid_source",
            "executable",
            "export_env",
            "from",
            "intercept",
            "sandbox",
        ],
    );
    assert_schema_properties(&schema, "DaemonPidSource", &["argv", "env"]);
    assert_schema_properties(
        &schema,
        "CommandEdgeConfig",
        &["invocation_policy", "sandbox"],
    );
    assert_schema_properties(
        &schema,
        "CommandSandboxConfig",
        &[
            "allow_launch_services",
            "allow_raw_file_credentials_in_chained_policy",
            "argv_prepend",
            "credentials",
            "environment",
            "fs_read",
            "fs_read_file",
            "fs_write",
            "fs_write_file",
            "network",
            "open_urls",
            "resources",
            "stdio",
            "unsafe_macos_seatbelt_rules",
            "use_credentials",
        ],
    );
    assert_schema_properties(
        &schema,
        "EndpointPolicyConfig",
        &["allow", "approve", "default", "deny"],
    );
    assert_schema_properties(
        &schema,
        "EndpointRuleConfig",
        &["backend", "method", "path", "reason", "timeout_secs"],
    );
    assert_schema_properties(
        &schema,
        "InvocationPolicyConfig",
        &["allow", "approve", "default", "deny"],
    );
    assert_schema_properties(
        &schema,
        "InvocationRuleConfig",
        &["argv", "backend", "env", "reason", "timeout_secs"],
    );
    assert_schema_properties(
        &schema,
        "ArgvMatcherConfig",
        &["contains", "exact", "prefix"],
    );
    assert_schema_properties(
        &schema,
        "InterceptArgvMatcherConfig",
        &["contains", "exact", "prefix"],
    );
    assert_schema_properties(&schema, "EnvMatcherConfig", &["equals", "one_of"]);
    assert_schema_properties(
        &schema,
        "CommandResourceConfig",
        &[
            "backend",
            "cpu_seconds",
            "fallback",
            "max_file_size_bytes",
            "max_output_bytes",
            "max_processes",
            "memory_bytes",
            "wall_time_seconds",
        ],
    );
    assert_schema_properties(&schema, "CommandStdioConfig", &["stderr", "stdout"]);
    assert_schema_properties(
        &schema,
        "CommandStdioStreamConfig",
        &["max_bytes", "on_limit"],
    );
    assert_schema_properties(
        &schema,
        "CommandNetworkConfig",
        &[
            "allow_all",
            "allow_domain",
            "tcp_bind_ports",
            "tcp_connect_ports",
        ],
    );
    assert_schema_properties(
        &schema,
        "CommandEnvironmentConfig",
        &["allow_vars", "set_vars"],
    );

    let from_variants = schema
        .pointer("/$defs/CommandPolicyConfig/properties/from/additionalProperties/oneOf")
        .and_then(Value::as_array)
        .expect("CommandPolicyConfig.from variants are listed");
    assert!(
        from_variants
            .iter()
            .any(|variant| variant.pointer("/$ref").and_then(Value::as_str)
                == Some("#/$defs/CommandEdgeConfig")),
        "CommandPolicyConfig.from must allow edge objects with sandbox and invocation_policy"
    );
}

#[test]
fn test_schema_credential_route_has_upgrades() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "CredentialRouteDef",
        &[
            "name",
            "provider",
            "env_var",
            "base_url_env_var",
            "endpoint_policy",
            "upgrades",
        ],
    );
    assert_schema_properties(&schema, "CredentialWebSocketRuleDef", &["origin", "path"]);
}

#[test]
fn test_schema_validates_credential_route_with_upgrades() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "credential_routes": [{
            "name": "codex",
            "provider": "codex",
            "upgrades": [{
                "origin": "https://api.openai.com",
                "path": "/v1/realtime"
            }]
        }]
    });

    validator
        .validate(&profile)
        .expect("credential route with upgrades should validate");
}

#[test]
fn test_schema_rejects_malformed_credential_route_upgrades() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for upgrade in [
        json!({ "origin": "http://api.openai.com", "path": "/v1/realtime" }),
        json!({ "origin": "https://api.openai.com/extra", "path": "/v1/realtime" }),
        json!({ "origin": "https://api.openai.com", "path": "v1/realtime" }),
        json!({ "origin": "https://api.openai.com", "path": "" }),
    ] {
        let profile = json!({
            "credential_routes": [{
                "name": "codex",
                "provider": "codex",
                "upgrades": [upgrade]
            }]
        });

        assert!(
            validator.validate(&profile).is_err(),
            "malformed upgrades entry should be rejected by the schema"
        );
    }
}

#[test]
fn test_schema_validates_intercept_match_rule() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "command_policies": {
            "commands": {
                "git": {
                    "sandbox": {},
                    "intercept": [{
                        "match": {
                            "argv": { "contains": ["push", "--force"] },
                            "env": {
                                "GIT_SSH_COMMAND": { "equals": "ssh -i /tmp/fake_key" }
                            }
                        },
                        "action": { "type": "approve" }
                    }]
                }
            }
        }
    });

    validator
        .validate(&profile)
        .expect("intercept match rule should validate");
}

#[test]
fn test_schema_rejects_intercept_args_and_match_together() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "command_policies": {
            "commands": {
                "git": {
                    "sandbox": {},
                    "intercept": [{
                        "args": ["push"],
                        "match": { "argv": { "prefix": ["push"] } },
                        "action": { "type": "passthrough" }
                    }]
                }
            }
        }
    });

    assert!(
        validator.validate(&profile).is_err(),
        "intercept rule cannot define both args and match"
    );
}

#[test]
fn test_schema_rejects_empty_intercept_argv_matcher() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for argv in [
        json!({ "exact": [] }),
        json!({ "prefix": [] }),
        json!({ "contains": [] }),
    ] {
        let profile = json!({
            "command_policies": {
                "commands": {
                    "git": {
                        "sandbox": {},
                        "intercept": [{
                            "match": { "argv": argv },
                            "action": { "type": "passthrough" }
                        }]
                    }
                }
            }
        });

        assert!(
            validator.validate(&profile).is_err(),
            "intercept argv matcher arrays cannot be empty"
        );
    }
}

#[test]
fn test_schema_rejects_invalid_intercept_argv_matcher_shape() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for argv in [
        json!({}),
        json!({ "exact": ["push"], "prefix": ["push"] }),
        json!({ "exact": ["push"], "contains": ["push"] }),
        json!({ "prefix": ["push"], "contains": ["push"] }),
    ] {
        let profile = json!({
            "command_policies": {
                "commands": {
                    "git": {
                        "sandbox": {},
                        "intercept": [{
                            "match": { "argv": argv },
                            "action": { "type": "passthrough" }
                        }]
                    }
                }
            }
        });

        assert!(
            validator.validate(&profile).is_err(),
            "intercept argv matcher must define exactly one matcher"
        );
    }
}

#[test]
fn test_schema_allows_empty_invocation_argv_matcher_for_compatibility() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for argv in [
        json!({ "exact": [] }),
        json!({ "prefix": [] }),
        json!({ "contains": [] }),
    ] {
        let profile = json!({
            "command_policies": {
                "commands": {
                    "git": {
                        "sandbox": {},
                        "from": {
                            "session": {
                                "sandbox": {},
                                "invocation_policy": {
                                    "approve": [{
                                        "argv": argv
                                    }]
                                }
                            }
                        }
                    }
                }
            }
        });

        validator
            .validate(&profile)
            .expect("empty invocation argv matcher remains schema-compatible");
    }
}

#[test]
fn test_schema_filesystem_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "FilesystemConfig",
        &[
            "allow",
            "read",
            "write",
            "allow_file",
            "read_file",
            "write_file",
            "unix_socket",
            "unix_socket_bind",
            "unix_socket_dir",
            "unix_socket_dir_bind",
            "unix_socket_subtree",
            "unix_socket_subtree_bind",
            "deny",
            "bypass_protection",
            "suppress_save_prompt",
            "ignore",
        ],
    );
}

#[test]
fn test_schema_does_not_advertise_legacy_policy_namespace() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/policy").is_none(),
        "schema still advertises legacy /properties/policy; it must be removed per issue #594 phase 2"
    );
    assert!(
        schema.pointer("/$defs/PolicyPatchConfig").is_none(),
        "schema still carries the legacy /$defs/PolicyPatchConfig definition; it must be removed per issue #594 phase 2"
    );
}

#[test]
fn test_schema_has_session_hooks_property_and_defs() {
    let schema = load_schema();
    assert!(
        schema.pointer("/properties/session_hooks").is_some(),
        "schema is missing canonical /properties/session_hooks"
    );

    let hooks_props = schema
        .pointer("/$defs/SessionHooks/properties")
        .and_then(Value::as_object)
        .expect("SessionHooks.properties is an object");
    assert!(
        hooks_props.contains_key("before"),
        "SessionHooks.before missing"
    );
    assert!(
        hooks_props.contains_key("after"),
        "SessionHooks.after missing"
    );

    let hook_props = schema
        .pointer("/$defs/SessionHook/properties")
        .and_then(Value::as_object)
        .expect("SessionHook.properties is an object");
    assert!(
        hook_props.contains_key("script"),
        "SessionHook.script missing"
    );
    assert!(
        hook_props.contains_key("timeout_secs"),
        "SessionHook.timeout_secs missing"
    );

    // Both objects must reject unknown fields to match the Rust struct's
    // #[serde(deny_unknown_fields)] guarantee.
    assert_eq!(
        schema.pointer("/$defs/SessionHooks/additionalProperties"),
        Some(&Value::Bool(false)),
        "SessionHooks must set additionalProperties: false"
    );
    assert_eq!(
        schema.pointer("/$defs/SessionHook/additionalProperties"),
        Some(&Value::Bool(false)),
        "SessionHook must set additionalProperties: false"
    );
}

#[test]
fn test_schema_security_has_no_legacy_groups_or_allowed_commands() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/SecurityConfig/properties")
        .and_then(Value::as_object)
        .expect("SecurityConfig.properties is an object");
    assert!(
        !props.contains_key("groups"),
        "SecurityConfig.groups still present; canonical location is top-level /properties/groups"
    );
    assert!(
        !props.contains_key("allowed_commands"),
        "SecurityConfig.allowed_commands still present; canonical location is top-level /properties/commands"
    );
}

#[test]
fn test_schema_security_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "SecurityConfig",
        &[
            "signal_mode",
            "process_info_mode",
            "ipc_mode",
            "capability_elevation",
            "approval_backends",
            "approval_defaults",
            "wsl2_proxy_policy",
        ],
    );
}

#[test]
fn test_schema_linux_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "LinuxConfig",
        &["af_unix_mediation", "sandbox_policy"],
    );
}

#[test]
fn test_schema_validates_linux_sandbox_policy() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    for policy in ["auto", "landlock", "external"] {
        let profile = json!({ "linux": { "sandbox_policy": policy } });
        validator
            .validate(&profile)
            .unwrap_or_else(|e| panic!("sandbox_policy {policy} should validate: {e}"));
    }
}

#[test]
fn test_schema_workdir_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(&schema, "WorkdirConfig", &["access"]);
}

#[test]
fn test_schema_rollback_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "RollbackConfig",
        &["exclude_patterns", "exclude_globs"],
    );
}

#[test]
fn test_schema_diagnostics_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(&schema, "DiagnosticsConfig", &["suppress_system_services"]);
}

#[test]
fn test_schema_tls_intercept_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "TlsInterceptConfig",
        &[
            "ca_lifecycle",
            "ca_validity",
            "leaf_validity",
            "ca_env_vars",
        ],
    );
}

#[test]
fn test_schema_environment_config_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "EnvironmentConfig",
        &[
            "allow_vars",
            "deny_vars",
            "case_insensitive_vars",
            "set_vars",
        ],
    );
}

#[test]
fn test_schema_profile_meta_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "ProfileMeta",
        &["name", "version", "description", "author"],
    );
}

#[test]
fn test_schema_credential_capture_entry_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "CredentialCaptureEntry",
        &[
            "command",
            "provider",
            "timeout_secs",
            "ttl_secs",
            "cache_ttl_secs",
            "cache_path_regex",
            "stdin",
            "output",
            "interaction",
        ],
    );
    assert_schema_properties(&schema, "CredentialCaptureProvider", &["command", "config"]);
    assert_schema_properties(
        &schema,
        "CredentialCaptureOutputConfig",
        &["format", "allow_headers"],
    );
    assert_schema_properties(
        &schema,
        "CredentialCaptureInteraction",
        &["allow_launch_services", "open_urls", "stdin", "stdio"],
    );
}

#[test]
fn test_schema_credential_provider_def_matches_rust_model() {
    let schema = load_schema();
    assert_schema_properties(
        &schema,
        "CredentialProviderDef",
        &[
            "type",
            "token_endpoints",
            "api_hosts",
            "inject_header",
            "credential_format",
            "credential_store",
            "helpers",
        ],
    );
    assert_schema_properties(
        &schema,
        "CredentialProviderTokenEndpoint",
        &[
            "host",
            "path",
            "response_fields",
            "request_body",
            "request_nonce_fields",
        ],
    );
    assert_schema_properties(
        &schema,
        "CredentialProviderHelpers",
        &["status", "login", "logout"],
    );
}

#[test]
fn test_schema_validates_credential_provider_inject_header_and_format() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "credential_providers": {
            "vault": {
                "type": "oauth_capture",
                "token_endpoints": [{
                    "host": "https://vault.example.com",
                    "path": "/v1/auth/token",
                    "response_fields": [{ "path": "auth.client_token" }]
                }],
                "api_hosts": ["https://vault.example.com"],
                "inject_header": "X-Vault-Token",
                "credential_format": "{}"
            }
        }
    });

    validator
        .validate(&profile)
        .expect("credential provider inject_header/credential_format should validate");
}

#[test]
fn test_schema_rejects_empty_and_nul_env_patterns() {
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");

    let empty_pattern = json!({ "environment": { "allow_vars": [""] } });
    assert!(
        validator.validate(&empty_pattern).is_err(),
        "schema should reject an empty allow_vars pattern"
    );

    let nul_pattern = json!({ "environment": { "deny_vars": ["AWS_\0TOKEN"] } });
    assert!(
        validator.validate(&nul_pattern).is_err(),
        "schema should reject a NUL byte in a deny_vars pattern"
    );

    let valid_infix = json!({ "environment": { "allow_vars": ["*_TOKEN", "AWS_*_TOKEN"] } });
    assert!(
        validator.validate(&valid_infix).is_ok(),
        "schema should accept infix/leading wildcard patterns"
    );
}

#[test]
fn test_schema_validates_profile_authoring_guide_environment_example() {
    // The exact JSON snippet from the "environment" section of
    // profile-authoring-guide.md — must stay valid as the schema evolves.
    let schema = load_schema();
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");
    let profile = json!({
        "environment": {
            "allow_vars": ["*"],
            "deny_vars": ["*TOKEN*", "*KEY*", "*SECRET*"],
            "case_insensitive_vars": true,
            "set_vars": { "RUST_LOG": "debug", "XDG_CONFIG_HOME": "$HOME/.config" }
        }
    });

    validator
        .validate(&profile)
        .expect("profile-authoring-guide.md environment example should validate");
}
