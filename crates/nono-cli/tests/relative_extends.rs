//! Integration tests for relative-path `extends` entries and CLI `--extends`
//! paths, run through the real binary under an isolated HOME/XDG tree.

use nono_test_support::{NonoTest, nono_test};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

const ERR_ABSOLUTE_PATH: &str =
    "absolute and `~/` paths are not supported in `extends`; use a relative path";
const ERR_PACK_STORE_TARGET: &str = "extend a pack by name (`org/pack`), not by path";
const ERR_NOT_JSON: &str = "path entries in `extends` must end in `.json` or `.jsonc`";

fn nono(t: &NonoTest, cwd: &Path, args: &[&str]) -> Output {
    t.hermetic_command()
        .args(args)
        .current_dir(cwd)
        .output()
        .expect("cargo builds CARGO_BIN_EXE_nono before running this test binary")
}

fn combined(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

fn assert_ok(out: &Output) -> String {
    let text = combined(out);
    assert!(out.status.success(), "expected success, got:\n{text}");
    text
}

fn assert_err_contains(out: &Output, needle: &str) {
    let text = combined(out);
    assert!(!out.status.success(), "expected failure, got:\n{text}");
    assert!(text.contains(needle), "expected {needle:?} in:\n{text}");
}

/// Canonical test root: macOS tempdirs sit behind symlinks, and resolved paths
/// in error messages are canonical.
fn root(t: &NonoTest) -> PathBuf {
    t.root().canonicalize().expect("root exists")
}

fn write(path: &Path, body: &str) {
    fs::create_dir_all(path.parent().expect("test paths have parents")).expect("mkdir");
    fs::write(path, body).expect("write");
}

/// A profile body granting read on `dir`, created so the grant is valid.
fn reads(dir: &Path, extends: Option<&str>) -> String {
    fs::create_dir_all(dir).expect("mkdir grant dir");
    let extends = extends
        .map(|e| format!(r#""extends": "{e}", "#))
        .unwrap_or_default();
    format!(
        r#"{{ {extends}"filesystem": {{ "read": ["{}"] }} }}"#,
        dir.display()
    )
}

#[test]
fn profile_path_extends_parent_relative_base() {
    let t = nono_test!("relext-parent");
    let r = root(&t);
    let base_dir = r.join("data").join("from-base");
    let child_dir = r.join("data").join("from-child");
    write(&r.join("shared/base.json"), &reads(&base_dir, None));
    write(
        &r.join("proj/.nono/agent.json"),
        &reads(&child_dir, Some("../../shared/base.json")),
    );

    let out = nono(
        &t,
        &r,
        &[
            "run",
            "--dry-run",
            "--profile",
            "./proj/.nono/agent.json",
            "--",
            "true",
        ],
    );
    let text = assert_ok(&out);
    assert!(text.contains(&base_dir.display().to_string()), "{text}");
    assert!(text.contains(&child_dir.display().to_string()), "{text}");
}

#[test]
fn path_base_bare_name_resolves_beside_the_base() {
    let t = nono_test!("relext-sibling");
    let r = root(&t);
    let common_dir = r.join("data").join("shared-common");
    let decoy_dir = r.join("data").join("decoy-common");
    write(&r.join("shared/common.json"), &reads(&common_dir, None));
    write(&r.join("shared/base.json"), r#"{ "extends": "common" }"#);
    write(&r.join("proj/common.json"), &reads(&decoy_dir, None));
    write(
        &r.join("proj/agent.json"),
        r#"{ "extends": "../shared/base.json" }"#,
    );

    let out = nono(&t, &r, &["profile", "show", "./proj/agent.json"]);
    let text = assert_ok(&out);
    assert!(text.contains(&common_dir.display().to_string()), "{text}");
    assert!(!text.contains(&decoy_dir.display().to_string()), "{text}");
}

fn show_with_extends(t: &NonoTest, extends: &str) -> Output {
    let r = root(t);
    write(
        &r.join("proj/agent.json"),
        &format!(r#"{{ "extends": "{extends}" }}"#),
    );
    nono(t, &r, &["profile", "show", "./proj/agent.json"])
}

#[test]
fn profile_extends_absolute_path_rejected() {
    let t = nono_test!("relext-abs");
    let out = show_with_extends(&t, "/abs.json");
    assert_err_contains(&out, &format!("'/abs.json': {ERR_ABSOLUTE_PATH}"));
}

#[test]
fn profile_extends_home_path_rejected() {
    let t = nono_test!("relext-home");
    let out = show_with_extends(&t, "~/x.json");
    assert_err_contains(&out, &format!("'~/x.json': {ERR_ABSOLUTE_PATH}"));
}

#[test]
fn profile_extends_missing_file_names_resolved_path() {
    let t = nono_test!("relext-missing");
    let out = show_with_extends(&t, "./nope.json");
    let resolved = root(&t).join("proj").join("./nope.json");
    assert_err_contains(
        &out,
        &format!(
            "extends './nope.json' resolves to {}, which cannot be read",
            resolved.display()
        ),
    );
}

#[test]
fn profile_extends_path_without_extension_rejected() {
    let t = nono_test!("relext-noext");
    let out = show_with_extends(&t, "./base");
    assert_err_contains(&out, &format!("'./base': {ERR_NOT_JSON}"));
}

#[test]
fn profile_extends_slash_name_without_dot_prefix_rejected() {
    let t = nono_test!("relext-badname");
    let out = show_with_extends(&t, "shared/base.json");
    assert_err_contains(&out, "invalid base profile name 'shared/base.json'");
}

#[test]
fn profile_extends_into_pack_store_rejected() {
    let t = nono_test!("relext-store");
    let r = root(&t);
    let store_file = r.join("home/.config/nono/packages/acme/pack/profile.json");
    write(&store_file, "{}");
    // proj/agent.json -> ../home/.config/... reaches the store by path.
    let out = show_with_extends(&t, "../home/.config/nono/packages/acme/pack/profile.json");
    assert_err_contains(
        &out,
        &format!("'../home/.config/nono/packages/acme/pack/profile.json': {ERR_PACK_STORE_TARGET}"),
    );
}

#[test]
fn cli_extends_resolves_against_cwd_not_profile_dir() {
    let t = nono_test!("relext-cli-cwd");
    let r = root(&t);
    let cwd_dir = r.join("data").join("cwd-base");
    let decoy_dir = r.join("data").join("decoy-base");
    write(&r.join("cwd/x.json"), &reads(&cwd_dir, None));
    write(&r.join("proj/x.json"), &reads(&decoy_dir, None));
    write(&r.join("proj/agent.json"), "{}");
    let profile = r.join("proj/agent.json");

    let out = nono(
        &t,
        &r.join("cwd"),
        &[
            "run",
            "--dry-run",
            "--profile",
            profile.to_str().expect("utf-8 path"),
            "--extends",
            "./x.json",
            "--",
            "true",
        ],
    );
    let text = assert_ok(&out);
    assert!(text.contains(&cwd_dir.display().to_string()), "{text}");
    assert!(!text.contains(&decoy_dir.display().to_string()), "{text}");
}

fn run_with_cli_extends(t: &NonoTest, extends: &str) -> Output {
    let r = root(t);
    write(&r.join("proj/agent.json"), "{}");
    let profile = r.join("proj/agent.json");
    nono(
        t,
        &r,
        &[
            "run",
            "--dry-run",
            "--profile",
            profile.to_str().expect("utf-8 path"),
            "--extends",
            extends,
            "--",
            "true",
        ],
    )
}

#[test]
fn cli_extends_missing_file_names_cwd_resolved_path() {
    let t = nono_test!("relext-cli-missing");
    let out = run_with_cli_extends(&t, "./missing.json");
    let resolved = root(&t).join("./missing.json");
    assert_err_contains(
        &out,
        &format!(
            "extends './missing.json' resolves to {}, which cannot be read",
            resolved.display()
        ),
    );
}

#[test]
fn cli_extends_non_json_rejected() {
    let t = nono_test!("relext-cli-txt");
    write(&root(&t).join("x.txt"), "{}");
    let out = run_with_cli_extends(&t, "./x.txt");
    assert_err_contains(&out, &format!("'./x.txt': {ERR_NOT_JSON}"));
}

#[test]
fn cli_extends_absolute_path_rejected() {
    let t = nono_test!("relext-cli-abs");
    let out = run_with_cli_extends(&t, "/abs.json");
    assert_err_contains(&out, &format!("'/abs.json': {ERR_ABSOLUTE_PATH}"));
}

fn init_with_extends(t: &NonoTest, extends: &str) -> (Output, PathBuf) {
    let r = root(t);
    let target = r.join("proj/.nono/new.json");
    fs::create_dir_all(target.parent().expect("has parent")).expect("mkdir");
    let out = nono(
        t,
        &r,
        &[
            "profile",
            "init",
            "new",
            "--output",
            target.to_str().expect("utf-8 path"),
            "--extends",
            extends,
        ],
    );
    (out, target)
}

#[test]
fn profile_init_writes_relative_extends_verbatim() {
    let t = nono_test!("relext-init-ok");
    write(&root(&t).join("proj/base.json"), "{}");
    let (out, target) = init_with_extends(&t, "../base.json");
    assert_ok(&out);
    let written: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&target).expect("profile written"))
            .expect("valid JSON");
    let extends = &written["extends"];
    let entries: Vec<&str> = match extends {
        serde_json::Value::String(s) => vec![s.as_str()],
        serde_json::Value::Array(a) => a.iter().filter_map(|v| v.as_str()).collect(),
        other => panic!("unexpected extends shape: {other}"),
    };
    assert_eq!(entries, vec!["../base.json"], "{written}");
}

#[test]
fn profile_init_relative_extends_missing_base_errors() {
    let t = nono_test!("relext-init-missing");
    let (out, target) = init_with_extends(&t, "../base.json");
    let resolved = root(&t).join("proj/.nono").join("../base.json");
    assert_err_contains(
        &out,
        &format!(
            "extends '../base.json' resolves to {}, which cannot be read",
            resolved.display()
        ),
    );
    assert!(!target.exists(), "no profile written on error");
}

#[test]
fn profile_init_absolute_extends_rejected() {
    let t = nono_test!("relext-init-abs");
    let (out, target) = init_with_extends(&t, "/abs.json");
    assert_err_contains(&out, &format!("'/abs.json': {ERR_ABSOLUTE_PATH}"));
    assert!(!target.exists(), "no profile written on error");
}
