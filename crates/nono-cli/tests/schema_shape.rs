//! Snapshot tests for the checked-in JSON profile schema.
//!
//! These tests assert the canonical shape of
//! `crates/nono-cli/data/nono-profile.schema.json` after issue #594
//! phase 2 restructuring. Any future accidental reintroduction of the
//! legacy patch namespace or legacy security subkeys will fail here.

use serde_json::Value;
use std::collections::BTreeSet;

fn load_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("nono-profile.schema.json");
    let content = std::fs::read_to_string(&path).expect("read embedded profile schema");
    serde_json::from_str(&content).expect("embedded profile schema is valid JSON")
}

fn assert_schema_properties(schema: &Value, def_name: &str, expected: &[&str]) {
    let props = schema
        .pointer(&format!("/$defs/{def_name}/properties"))
        .and_then(Value::as_object)
        .unwrap_or_else(|| panic!("{def_name}.properties is an object"));
    let actual = props.keys().map(String::as_str).collect::<BTreeSet<_>>();
    let expected = expected.iter().copied().collect::<BTreeSet<_>>();
    assert_eq!(
        actual, expected,
        "{def_name}.properties must match the Rust command-policy model"
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
    assert_schema_properties(&schema, "InterceptRuleConfig", &["action", "args"]);
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
fn test_schema_filesystem_has_deny_and_bypass_protection() {
    let schema = load_schema();
    let props = schema
        .pointer("/$defs/FilesystemConfig/properties")
        .and_then(Value::as_object)
        .expect("FilesystemConfig.properties is an object");
    assert!(
        props.contains_key("deny"),
        "FilesystemConfig.deny missing from canonical schema"
    );
    assert!(
        props.contains_key("bypass_protection"),
        "FilesystemConfig.bypass_protection missing from canonical schema"
    );
    assert!(
        props.contains_key("suppress_save_prompt"),
        "FilesystemConfig.suppress_save_prompt missing from canonical schema"
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
