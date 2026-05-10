//! Snapshot tests for the checked-in JSON profile schema.
//!
//! These tests assert the canonical shape of
//! `crates/nono-cli/data/nono-profile.schema.json` after issue #594
//! phase 2 restructuring. Any future accidental reintroduction of the
//! legacy patch namespace or legacy security subkeys will fail here.

use serde_json::Value;

fn load_schema() -> Value {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("data")
        .join("nono-profile.schema.json");
    let content = std::fs::read_to_string(&path).expect("read embedded profile schema");
    serde_json::from_str(&content).expect("embedded profile schema is valid JSON")
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
