# Phase 44: REVIEW polish + test hygiene drain - Pattern Map

**Mapped:** 2026-05-20
**Files analyzed:** ~21 modified (Plan 44-01: ~17; Plan 44-02: ~4 + 2 sibling repos)
**Analogs found:** 19 / 21 with exact or role-match
**Phase type:** drain (no new feature files; ~all changes are retrofits on existing files)

> **Read-first note for planner:** This is a drain phase. Every "analog" below is an in-repo file the planner should paste an excerpt from into the plan's `read_first` block so the executor mirrors the existing convention exactly. There is no "new file" with a green-field role classification except `crates/nono/src/trust/signing.rs` (the WR-09 reader is a NEW public function in an EXISTING file) and `.config/nextest.toml` (truly new — pattern source is the nextest docs, not a repo analog).

---

## File Classification

| File | Role | Data Flow | Closest Analog | Match Quality |
|------|------|-----------|----------------|---------------|
| **Plan 44-01 — REVIEW polish** | | | | |
| `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` | const-extraction site (WR-02 P37) | transform | self (lines 891,901,910,981,993,997 — repeated string literal) | self-dedup |
| `crates/nono/src/error.rs` | const-extraction site (WR-02 P37 sibling) | transform | `crates/nono/src/error.rs:425-426` already has `const LOCKED_HINT` in tests | exact (already exists in test; promote to module-level pub const) |
| `crates/nono-cli/src/cli.rs` (lines 1484-1496) | clap `#[arg(...)]` help-text edit (IN-04 P37) | config-decl | sibling flags with `env =` + help like the `--block-net` family in same file | exact (same struct, neighboring flags) |
| `crates/nono-cli/src/cli.rs` (line 1773) | clap `hide = true` site (WR-10 P37 context) | config-decl | self (the hidden flag is the verification target; no fix at this line) | n/a (read-only context for the script fix) |
| `crates/nono-cli/src/diagnostic_formatter.rs` (lines 25-41) | "set" grep-contract comment (IN-07 P37) | doc-only | self (the doc comment at line 25 already mentions the grep-contract — extend it) | self |
| `crates/nono-cli/src/pack_update_hint.rs` (lines 84-99, 183-218, 263-274, 290-304) | UX-regression fix + atomic-write retrofit + is_newer semver fix | request-response + transform | `crates/nono-cli/src/package.rs:367-379` (`write_lockfile` tmp+rename) for IN-01; same file's `refresh_in_background` (lines 183-218) for WR-05; semver crate (`Cargo.toml:71`) for WR-03 | exact (same file for refresh_in_background pattern; package.rs for atomic-write) |
| `crates/nono-cli/src/platform.rs` (lines 146-169, 583-597) | parser correctness + Ord-symmetry fix (WR-02 + WR-04 + WR-06 P43) | transform | self — unit-test mod at lines 599+ shows the existing fixture/test idiom | self (in-file `#[cfg(test)] mod tests`) |
| `crates/nono-cli/src/sandbox_prepare.rs` (lines 108-112) | callsite for sync→background swap (WR-05 P43) | request-response | self (one-line call; the fix lives in `pack_update_hint.rs`) | n/a |
| `crates/nono-cli/src/package_cmd.rs` (lines 341-346, 580-585, 629-633) | defensive empty-segment guard + iterator pass dedup (IN-03/04 P43) | transform | `crates/nono-cli/src/package.rs:367-379` for atomic-write idiom (not needed here); pattern is `if condition || parts[0].is_empty() || parts[1].is_empty()` — defensive validation | self-style |
| `crates/nono-cli/src/session_commands.rs` (lines 691-714) | move to shared module (IN-03 P37) | transform / refactor | `crates/nono-cli/src/{session_commands.rs, session_commands_windows.rs}` show the duplication; planner picks new home (likely `crates/nono-cli/src/format_util.rs` NEW or fold into existing util module) | partial (refactor target picked by planner) |
| `crates/nono-cli/src/session_commands_windows.rs` (lines 610-628) | source-side of IN-03 dedup | transform | Unix sibling (above) | exact mirror |
| `crates/nono/src/trust/signing.rs` (NEW function inside existing file) | NEW production reader for `NONO_TRUST_OIDC_ISSUER` (WR-09 P37) | request-response (env-var read → validate → return) | **same file lines 86-123**: `validate_oidc_issuer` is the exact validator the reader will dispatch into. Plus `GITHUB_ACTIONS_OIDC_ISSUER` const at line 134 is the fallback default | exact (this is the analog; reader composes existing primitives) |
| `crates/nono/src/undo/snapshot.rs` (lines 595-687) | doc-only retrofit (WR-01 P43) | doc-only | self — doc comment immediately above `fn validate_restore_target` at line 590 | self |
| `crates/nono/Cargo.toml` (line 48) | dependency comment + test pin-test target (WR-05 P37) | config-decl | the test lives elsewhere (likely in `crates/nono/src/trust/mod.rs` or a NEW unit test asserting `VerificationPolicy::default().verify_sct == true`) | partial — test site is the analog, not the Cargo.toml line |
| `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (lines 29-61, 44-51, 218, 280, 329, 334-372, 391-465, 492) | test thread-safety + XDG_CONFIG_HOME pin (WR-03/04 + IN-01/02/05 P37) | request-response (test) | **`crates/nono-cli/tests/common/test_env.rs`** (the canonical `EnvVarGuard`); `crates/nono-cli/src/test_env.rs` for the `lock_env()` primitive | exact (canonical primitive lives in `tests/common/`) |
| `crates/nono-cli/tests/resl_nix_linux.rs` (lines 37-39, 212-253) | brittle-heuristic fix + Phase-16-stub guard (WR-06 + WR-07 P37) | request-response (test) | `nix::unistd::access` for WR-06; either `require_cgroup_v2!()` macro pattern or positive/negative split for WR-07 | partial (no existing `require_cgroup_v2!()` macro — planner introduces) |
| `.github/workflows/phase-37-linux-resl.yml` (lines 135, 294) | CI hygiene — `env:` injection (WR-08); WR-09 paired with production wire-up | config-decl (CI) | sibling step blocks in same file already use `env:` for `NONO_FIXTURE_PACK_DIR` (line 290) | exact (same file, same idiom) |
| `.github/scripts/check-cli-doc-flags.sh` (lines 24, 64-67) | awk multi-line `#[arg(...)]` accumulator + `hide = true` skip (WR-01 + WR-10 P37) | transform (bash/awk) | self — the awk pipeline at lines 18-53 is the structure to modify | self |
| **Plan 44-02 — test hygiene drain** | | | | |
| `crates/nono-cli/tests/deny_overlap_run.rs` (line 111, 58) | either-or assertion + drop `#[ignore]` (REQ-TEST-HYG-01) | request-response (test) | self (lines 107-119 already show the 3 assertions; only #2 changes; #[ignore] removed) | self |
| `crates/nono-cli/tests/env_vars.rs` (line 683, 1041) | flake elimination via nextest config + verification context (REQ-TEST-HYG-02) | request-response (test) | `crates/nono-cli/tests/common/test_env.rs::EnvVarGuard::set_all` already in use at line 1047 — the test code itself does NOT change; nextest scoping is external | self (test already uses canonical guard; flake source is parallel-test env-var race) |
| `.config/nextest.toml` (NEW) | NEW nextest profile config | config-decl | NO repo analog — pattern is from nextest docs (`https://nexte.st/book/configuration.html`) | none-in-repo (planner consults nextest docs current at plan-open) |
| `bindings/c/src/lib.rs` (lines 285-291) | verification context for sibling-repo lockstep (CR-01 = REQ-TEST-HYG-03) | request-response (FFI test) | **self lines 279-293**: `broker_not_found_maps_to_err_sandbox_init` is the EXACT shape sibling repos mirror | exact (sibling tests assert equivalent across PyO3 / napi-rs) |
| `crates/nono-shell-broker/src/main.rs` (lines 535, 562) | verification context for sibling-repo lockstep (CR-02 = REQ-TEST-HYG-04) | request-response (broker argv parser test) | **self lines 530-565**: `parse_args_null_inherit_handle_returns_error` + `parse_args_invalid_handle_value_inherit_handle_returns_error` are the EXACT shape | exact |
| `../nono-py/` (NEW regression test file) | sibling-repo regression test (PyO3) | request-response (test) | nono-py's own existing test conventions (read at clone-time per D-44-D2) | partial (cross-repo discovery) |
| `../nono-ts/` (NEW regression test file) | sibling-repo regression test (napi-rs / vitest) | request-response (test) | nono-ts's own existing test conventions (read at clone-time per D-44-D2) | partial (cross-repo discovery) |

---

## Pattern Assignments

### Plan 44-01

#### `crates/nono-cli/src/exec_strategy/supervisor_linux.rs` (const-extraction, WR-02 P37)

**Analog:** self — the verbatim duplicated literal lives in 6 sites in this file and one in `error.rs`.

**Duplicated literal pattern** (current state, lines 889-902):
```rust
return Err(NonoError::UnsupportedKernelFeature {
    feature: "cgroup_v2".into(),
    hint: "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all".into(),
});
```

**Target pattern** (target `mod cgroup` after fix — place near `const KIB`/`const MIB` style):
```rust
/// LOCKED — keep in sync with `nono::error::CGROUP_V2_HINT`. The boot-flag
/// hint must remain stable for REQ-RESL-NIX-01 acceptance #5 (FFI consumers
/// grep this string from `nono_last_error()` Display output).
pub(super) const CGROUP_V2_HINT: &str =
    "cgroup v2 required; boot with systemd.unified_cgroup_hierarchy=1 or cgroup_no_v1=all";
```

Then each site becomes:
```rust
hint: CGROUP_V2_HINT.into(),
```

**Cross-check site:** `crates/nono/src/error.rs:425-426` already declares the SAME const inside `#[cfg(test)] mod unsupported_kernel_feature_tests`. Promote it to a `pub` module-level const so library + CLI can both reference it. Planner picks single-source-of-truth location (likely `nono::error::CGROUP_V2_HINT pub const`).

---

#### `crates/nono-cli/src/cli.rs:1484-1496` (IN-04 P37 — env-var hint in help)

**Analog:** the same `#[arg(...)]` block already declares `env = "NONO_NO_AUTO_PULL"` at line 1489. Pattern is to prepend the env name to the help string.

**Current** (lines 1484-1496):
```rust
/// Disable cargo-install-style auto-pull when --profile references a
/// registry pack not yet installed locally. Falls back to the legacy
/// "profile not found" error.
#[arg(
    long,
    env = "NONO_NO_AUTO_PULL",
    value_parser = clap::builder::BoolishValueParser::new(),
    num_args = 0..=1,
    default_missing_value = "true",
    default_value_t = false,
    help_heading = "PROFILE"
)]
pub no_auto_pull: bool,
```

**Target:** clap renders `[env: NONO_NO_AUTO_PULL=]` automatically when `env =` is set — IF the env-var hint is missing from rendered help, the fix is either to confirm clap's `--help` output (no source change needed) OR explicitly prepend in doc-comment text. Planner verifies via `cargo run -- run --help | grep -A2 no-auto-pull` at plan-open.

---

#### `crates/nono-cli/src/pack_update_hint.rs` (multiple — WR-03/WR-05 P43, IN-01/IN-02 P43)

**Analog A (WR-05 — drop synchronous, lines 84-105):** the same file already has `refresh_in_background` (lines 183-218) implementing the background pattern. Pattern is `delete the if-cache-existed-was-false branch and always background-refresh`.

**Target shape** (delete lines 85-99, keep else branch unconditionally):
```rust
if !stale.is_empty() {
    // Always refresh in background — first-run users see no hint
    // until the second run. Avoids up-to-5min stalls when the
    // registry is unreachable. Phase 44 WR-05 (D-44-B2).
    let shared = Arc::new(Mutex::new(state));
    refresh_in_background(stale, shared);
}
```

`refresh_synchronous` function (lines 160-181) becomes dead code — DELETE entirely per D-44-E5 (no `#[allow(dead_code)]`).

**Analog B (IN-01 — atomic state-file write, lines 263-274):** **`crates/nono-cli/src/package.rs:367-379` `write_lockfile`** — canonical atomic write.

**Source pattern** (`package.rs:367-379` verbatim):
```rust
pub fn write_lockfile(lockfile: &Lockfile) -> Result<()> {
    let path = lockfile_path()?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }

    let tmp_path = path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(lockfile)
        .map_err(|e| NonoError::ConfigParse(format!("failed to serialize lockfile: {e}")))?;
    fs::write(&tmp_path, format!("{json}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp_path, &path).map_err(NonoError::Io)?;
    Ok(())
}
```

**Target retrofit** (`pack_update_hint.rs::save_state`):
```rust
fn save_state(state: &PackHintsState) {
    let path = match state_file_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let tmp_path = path.with_extension("json.tmp");
        if std::fs::write(&tmp_path, json).is_ok() {
            let _ = std::fs::rename(&tmp_path, &path);
        }
    }
}
```

**Analog C (WR-03 — semver pre-release, lines 290-304):** the workspace already depends on the `semver` crate (`crates/nono-cli/Cargo.toml:71 semver = "1"` per the REVIEW excerpt). Pattern: replace hand-rolled parser with strip-prefix-or-build-metadata.

**Target shape** (from 43-REVIEW.md:172-188 verbatim):
```rust
fn is_newer(installed: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let core = s.split(['-', '+']).next().unwrap_or(s);
        let mut parts = core.splitn(3, '.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next()?.parse().ok()?;
        let patch: u64 = parts.next()?.parse().ok()?;
        Some((major, minor, patch))
    };
    match (parse(installed), parse(latest)) {
        (Some(i), Some(l)) => l > i,
        _ => false,  // <-- suppress hint on either-side parse failure
    }
}
```

**Analog D (IN-02 — detached JoinHandle, lines 183-218):** per D-44-B5, accept-as-documented. Add a comment at line 185:
```rust
// Detached: no graceful shutdown signal exists; if `nono` exits before
// the HTTP request and save_state complete, the network request is
// killed mid-flight and the cache may not be updated on this run.
// Acceptable: the worst case is more-aggressive registry checking on
// the next run (Phase 44 IN-02 D-44-B5 acceptance).
let _ = thread::spawn(move || {
```

---

#### `crates/nono-cli/src/platform.rs:146-169` (WR-02 + WR-06 P43 — REG_DWORD fallback + case-insensitive name match)

**Analog:** self. The function already has the `0x` prefix-strip + `u64::from_str_radix` shape; fix is two-line tweak.

**Current** (lines 146-169):
```rust
fn parse_windows_registry_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some(name) {              // <-- WR-06: case-sensitive
            continue;
        }
        let kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        if !value.is_empty() {
            if kind == "REG_DWORD" {
                if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                    if let Ok(number) = u64::from_str_radix(hex, 16) {
                        return Some(number.to_string());
                    }
                }
            }
            return Some(value);                       // <-- WR-02: returns "0xZZZ" on malformed
        }
    }
    None
}
```

**Target retrofit** (from 43-REVIEW.md:138-146 + 312-316 verbatim):
```rust
fn parse_windows_registry_value(output: &str, name: &str) -> Option<String> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let first = parts.next()?;
        if !first.eq_ignore_ascii_case(name) {         // <-- WR-06 fix
            continue;
        }
        let kind = parts.next()?;
        let value = parts.collect::<Vec<_>>().join(" ");
        if !value.is_empty() {
            if kind == "REG_DWORD" {
                if let Some(hex) = value.strip_prefix("0x").or_else(|| value.strip_prefix("0X")) {
                    return u64::from_str_radix(hex, 16).ok().map(|n| n.to_string());
                }
                // REG_DWORD without 0x prefix is malformed — bail.
                return None;                            // <-- WR-02 fix
            }
            return Some(value);
        }
    }
    None
}
```

**Regression test target:** the `#[cfg(test)] mod tests` at line 599+ in same file — add `parse_windows_registry_value_accepts_case_mismatch` + `parse_windows_registry_value_rejects_malformed_dword`.

---

#### `crates/nono-cli/src/platform.rs:583-597` (WR-04 P43 — `compare_versions` Ord antisymmetry)

**Current** (lines 583-597):
```rust
fn compare_versions(left: &str, right: &str) -> Ordering {
    let left_parts = left.split('.').collect::<Vec<_>>();
    let right_parts = right.split('.').collect::<Vec<_>>();
    for (left_part, right_part) in left_parts.iter().zip(right_parts.iter()) {
        let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
            (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
            _ if left_part == right_part => Ordering::Equal,
            _ => Ordering::Less,                          // <-- not symmetric!
        };
        if ordering != Ordering::Equal {
            return ordering;
        }
    }
    left_parts.len().cmp(&right_parts.len())
}
```

**Target retrofit** (from 43-REVIEW.md:223-233 verbatim):
```rust
let ordering = match (left_part.parse::<u64>(), right_part.parse::<u64>()) {
    (Ok(left_num), Ok(right_num)) => left_num.cmp(&right_num),
    (Err(_), Err(_)) => left_part.cmp(right_part),
    (Ok(_), Err(_)) => Ordering::Greater,
    (Err(_), Ok(_)) => Ordering::Less,
};
```

**Regression test target:** in-file `#[cfg(test)] mod tests` — add symmetry assertion:
```rust
#[test]
fn compare_versions_is_symmetric_on_non_numeric_segments() {
    assert_eq!(compare_versions("a", "b"), Ordering::Less);
    assert_eq!(compare_versions("b", "a"), Ordering::Greater);
    assert_eq!(compare_versions("1", "a"), Ordering::Greater);
    assert_eq!(compare_versions("a", "1"), Ordering::Less);
}
```

---

#### `crates/nono/src/trust/signing.rs` (NEW production reader for `NONO_TRUST_OIDC_ISSUER`, WR-09 P37, `feat(44-01)`)

**Analog (in-file):** `validate_oidc_issuer` at lines 86-123 + `GITHUB_ACTIONS_OIDC_ISSUER` const at line 134. The reader composes these existing primitives.

**Existing primitive — `validate_oidc_issuer`** (lines 86-123 — already implements URL-component-level fail-closed validation per CLAUDE.md § Common Footguns #1):
```rust
pub fn validate_oidc_issuer(iss: &str, pin: &str) -> Result<()> {
    let iss_url = url::Url::parse(iss).map_err(|e| { ... })?;
    let pin_url = url::Url::parse(pin).map_err(|e| { ... })?;
    if iss_url.scheme() != pin_url.scheme() { return Err(...); }
    if iss_url.host_str() != pin_url.host_str() { return Err(...); }
    if iss_url.port() != pin_url.port() { return Err(...); }
    Ok(())
}
```

**Existing const** (line 134):
```rust
pub const GITHUB_ACTIONS_OIDC_ISSUER: &str = "https://token.actions.githubusercontent.com";
```

**Target NEW reader (planner picks final signature; suggested shape — `feat(44-01)` per D-44-B3):**
```rust
/// Read the configured OIDC issuer pin, preferring `NONO_TRUST_OIDC_ISSUER`
/// over the canonical GitHub Actions default. Returns the pin URL to use
/// for [`validate_oidc_issuer`] callers. CLAUDE.md § Fail Secure: when the
/// env var is set but unparseable as a URL, returns the parse error — the
/// caller MUST refuse to publish/verify rather than silently falling back.
///
/// REQ-PKGS-04 acceptance #4 (Phase 37 WR-09): when the CI workflow sets
/// `NONO_TRUST_OIDC_ISSUER=https://token.actions.githubusercontent.com`,
/// this reader returns that value and downstream `validate_oidc_issuer`
/// enforces the pin against the GitHub token's `iss` claim.
pub fn configured_oidc_issuer() -> Result<String> {
    match std::env::var("NONO_TRUST_OIDC_ISSUER") {
        Ok(v) if !v.is_empty() => {
            // Eagerly validate that the env-var value is a parseable URL —
            // fail-closed before any signature operation begins.
            url::Url::parse(&v).map_err(|e| NonoError::ConfigParse(format!(
                "NONO_TRUST_OIDC_ISSUER='{v}' is not a valid URL: {e}"
            )))?;
            Ok(v)
        }
        _ => Ok(GITHUB_ACTIONS_OIDC_ISSUER.to_string()),
    }
}
```

**Existing test idiom (in-file `mod tests`, lines 979-1090):** mirror the GitLab/GitHub test pattern. Add unit tests:
- `configured_oidc_issuer_returns_env_when_set` (using `EnvVarGuard` — must `use crate::test_env::*` OR depend on lock_env if added)
- `configured_oidc_issuer_falls_back_to_github_default_when_unset`
- `configured_oidc_issuer_rejects_malformed_env_value`

**Wire-up callsite:** planner determines exactly which signature verification path consumes this. Likely `crates/nono-cli/src/trust_cmd.rs` (per line 26 doc comment: "The fork's GitHub + GitLab trust paths (`crates/nono-cli/src/trust_cmd.rs`) may call this helper"). At plan-open, grep for `validate_oidc_issuer` callsites and choose whether the reader is called there OR exposed for the CI workflow to set via env-var only. **Acceptance gate** per D-44-B3: "the env var is read; if set, asserts as the trusted OIDC issuer at signature verification time; if unset, falls back to current behavior."

---

#### `crates/nono/src/undo/snapshot.rs:595-687` (WR-01 P43 — doc-only TOCTOU note)

**Analog:** self — the existing doc comment immediately above `fn validate_restore_target` at line 590 ("Manifest validation is lexical: it proves stored paths are under tracked roots...").

**Target retrofit** (from 43-REVIEW.md:99-109 verbatim — extend the existing doc, do NOT replace it):
```rust
/// Validate the live filesystem path that restore will write through.
///
/// Manifest validation is lexical: it proves stored paths are under tracked
/// roots, but it cannot see symlinks created after the snapshot. Restore
/// runs outside the sandbox, so every existing parent component at or below
/// the tracked root must be a real directory before `create_dir_all`,
/// temp-file creation, rename, or chmod touches the path.
///
/// **Residual race window:** this check runs lexically against
/// `symlink_metadata` and is followed by `create_dir_all` / atomic
/// rename / `set_permissions` non-atomically. A local attacker with
/// write access inside the tracked tree CAN race the validation by
/// swapping a directory for a symlink between this function returning
/// `Ok(())` and the write. Full closure requires `O_NOFOLLOW` and
/// fd-relative ops; tracked as follow-up
/// `.planning/todos/pending/44-validate-restore-target-fd-relative-hardening.md`.
fn validate_restore_target(&self, path: &Path) -> Result<()> {
```

---

#### `crates/nono-cli/tests/auto_pull_e2e_linux.rs` (WR-03 + WR-04 + IN-01/02/05 P37 — test thread-safety)

**Analog:** **`crates/nono-cli/tests/common/test_env.rs`** (the canonical `EnvVarGuard` mirror for integration tests). Plus `crates/nono-cli/src/test_env.rs::lock_env()` documented at file top.

**Source pattern — `tests/common/test_env.rs` (whole file is the canonical primitive):**
```rust
//! Integration-test copy of the `EnvVarGuard` RAII primitive.
//!
//! `crates/nono-cli` is a binary-only crate; its `#[cfg(test)] mod test_env`
//! in `src/test_env.rs` is therefore NOT visible from the integration test
//! compilation unit in `tests/`.  This file mirrors the canonical abstraction
//! verbatim so integration tests can use the same Drop-restore pattern...
#![cfg(target_os = "windows")]   // <-- NB: currently gated to Windows!

pub struct EnvVarGuard {
    original: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    #[must_use]
    pub fn set_all(vars: &[(&'static str, &str)]) -> Self {
        let original = vars.iter().map(|(key, _)| (*key, std::env::var(key).ok())).collect();
        for (key, value) in vars { std::env::set_var(key, value); }
        Self { original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in self.original.iter().rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
```

**Important friction point for planner:** `tests/common/test_env.rs` is currently gated `#![cfg(target_os = "windows")]` (line 19). For `auto_pull_e2e_linux.rs` (`#![cfg(target_os = "linux")]`) to use the SAME canonical guard, the gate must be widened to `#![cfg(any(target_os = "windows", target_os = "linux"))]` OR the comment block at lines 12-17 explaining the orphan-on-Linux issue must be revisited. Per D-44-E5 (no `#[allow(dead_code)]`), the cleanest move is widening the gate at the same time as the WR-03/04 fix.

**Source pattern — `src/test_env.rs::lock_env()` (lines 1-17):**
```rust
/// Process-global lock for tests that mutate environment variables.
#[allow(dead_code)]
pub static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub fn lock_env() -> std::sync::MutexGuard<'static, ()> {
    match ENV_LOCK.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}
```

`lock_env()` is in `src/test_env.rs` (binary-only crate's `#[cfg(test)]` mod) and is NOT visible to integration tests. The planner has two options:
- (a) Add a `pub fn lock_env()` to `tests/common/test_env.rs` mirror that wraps a `static Mutex<()>` (same shape as the source-side primitive). 37-REVIEW.md:55-57's "exact suggested fix" wording is `mod common; use common::test_env::lock_env;` — meaning the planner SHOULD add the lock primitive to the common mirror.
- (b) Use only the `EnvVarGuard` Drop-restore (currently sufficient for `env_vars.rs:1047` since no other test mutates THOSE specific vars). For `auto_pull_e2e_linux.rs` the vars (`NONO_TEST_HOME`, `XDG_CONFIG_HOME`, `NONO_FIXTURE_PACK_DIR`, etc.) may collide with sibling tests — option (a) is safer.

**Target retrofit at line 29-61 (delete file-local `EnvGuard`; replace with import):**
```rust
mod common;
use common::test_env::{EnvVarGuard, lock_env};   // planner adds lock_env to common mirror

#[test]
fn auto_pull_signature_failure_aborts() {
    let _lock = lock_env();
    let tempdir = ...;
    let _env = EnvVarGuard::set_all(&[
        ("NONO_TEST_HOME", tempdir.path().to_str().unwrap()),
        ("XDG_CONFIG_HOME", tempdir.path().to_str().unwrap()),  // <-- WR-04 pin
        // ... other vars
    ]);
    // ... rest of test
}
```

**Workflow companion:** drop `--test-threads=1` from `.github/workflows/phase-37-linux-resl.yml:296` once thread-safety is wired (per 37-REVIEW.md WR-03 last paragraph).

---

#### `crates/nono-cli/tests/resl_nix_linux.rs:37-39` (WR-06 P37 — brittle writable-check)

**Current** (lines 37-39 per REVIEW excerpt):
```rust
!std::fs::Permissions::readonly(...)  // mode-bits-only heuristic
```

**Target:** use `nix::unistd::access` (workspace already depends on `nix` per STACK.md). 37-REVIEW.md WR-06 fix:
```rust
use nix::unistd::{access, AccessFlags};
let writable = access(path, AccessFlags::W_OK).is_ok();
```

Or drop the gate entirely if redundant with sibling checks (planner discretion at plan-open).

---

#### `crates/nono-cli/tests/resl_nix_linux.rs:212-253` (WR-07 P37 — Phase-16-stub guard regression)

**Target:** add `require_cgroup_v2!()` at top OR split into positive/negative control tests. No existing macro; planner introduces:
```rust
macro_rules! require_cgroup_v2 {
    () => {
        if !cgroup_v2_available() {
            eprintln!("SKIP: cgroup-v2 unavailable");
            return;
        }
    };
}
```

---

#### `.github/scripts/check-cli-doc-flags.sh:24,64-67` (WR-01 + WR-10 P37 — awk parser fixes)

**Analog:** self. The awk pipeline at lines 18-53 is the structure to modify. Pattern is "accumulate attribute across lines until closing `)]`, then evaluate, including skipping `hide = true`."

**Current parser** (lines 23-46):
```awk
/#\[arg\(/ && /long/ { attr = $0; next }   # <-- requires both on same line (BUG)

/^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:/ {
    if (attr == "") { next }
    field = $2
    sub(/:$/, "", field)
    if (match(attr, /long[[:space:]]*=[[:space:]]*"[^"]+"/)) { ... }
    else { gsub(/_/, "-", field); print field }
    attr = ""
    next
}
```

**Target retrofit shape** (planner refines syntax):
```awk
# Accumulate multi-line #[arg(...)] until closing )]
/#\[arg\(/ {
    attr = $0
    if (attr ~ /\)\]/) { in_arg = 0 } else { in_arg = 1 }
    next
}
in_arg {
    attr = attr " " $0
    if ($0 ~ /\)\]/) { in_arg = 0 }
    next
}

# Field line — evaluate accumulated attr
/^[[:space:]]*pub[[:space:]]+[a-zA-Z0-9_]+:/ {
    if (attr == "") { next }
    # WR-10: skip hidden flags
    if (attr ~ /hide[[:space:]]*=[[:space:]]*true/) { attr = ""; next }
    # ... existing field-name extraction ...
}
```

---

#### `.github/workflows/phase-37-linux-resl.yml:135` (WR-08 P37 — env: injection)

**Analog:** sibling step at lines 288-296 already uses `env:` block for `NONO_FIXTURE_PACK_DIR` + `NONO_TRUST_OIDC_ISSUER`. Mirror that pattern.

**Source pattern** (lines 288-296):
```yaml
- name: Run auto-pull e2e integration test (D-15 both clauses)
  env:
    NONO_FIXTURE_PACK_DIR: ${{ github.workspace }}/target/fixture-pack
    NONO_TRUST_OIDC_ISSUER: https://token.actions.githubusercontent.com
  run: |
    cargo test -p nono-cli --test auto_pull_e2e_linux --release -- --nocapture --test-threads=1
```

**Target retrofit at line 135:**
```yaml
- name: Run RESL-NIX integration tests under systemd user session
  env:
    WORKSPACE: ${{ github.workspace }}
  run: |
    sudo machinectl shell ${USER}@.host /usr/bin/env bash -c \
      "cd \"$WORKSPACE\" && cargo test -p nono-cli --test resl_nix_linux --test resl_nix_async_signal_safety --release -- --nocapture"
```

---

### Plan 44-02

#### `crates/nono-cli/tests/deny_overlap_run.rs` (REQ-TEST-HYG-01, lines 58 + 111)

**Analog:** self. Two changes only:

**Change 1 — drop `#[ignore]` at line 58:**
```rust
// REMOVE: #[ignore = "regression under investigation; ..."]
#[test]
fn run_allow_cwd_with_profile_deny_under_workdir_fails_closed() {
```

**Change 2 — either-or assertion at line 112-115:**
```rust
// Phase 44 D-44-C1: accept either validator pre-flight ("Landlock deny-overlap")
// OR runtime Landlock filesystem denial ("Permission denied" + "No path
// denials were observed"). Both shapes prove the security guarantee — the
// secret is not leaked (asserted at #1 + #3). The validator pre-flight bug
// is tracked separately at
// .planning/todos/pending/44-class-d-validator-preflight-investigation.md.
let validator_message = stderr.contains("Landlock deny-overlap");
let runtime_denial = stderr.contains("Permission denied")
    && stderr.contains("No path denials were observed");
assert!(
    validator_message || runtime_denial,
    "expected validator pre-flight OR runtime Landlock denial in stderr, got:\n{stderr}",
);
```

Assertions #1 (`!output.status.success()`) and #3 (`!stdout.contains("fake-test-secret")`) are unchanged.

---

#### `crates/nono-cli/tests/env_vars.rs` (REQ-TEST-HYG-02, lines 683 + 1041)

**Analog:** the test file ALREADY uses `EnvVarGuard::set_all(...)` at line 1047 — the canonical primitive is correctly applied. The flake source is parallel-test interleaving of env-var mutations BETWEEN tests despite each test's Drop-restore. Source code changes here are minimal — the fix is external (`.config/nextest.toml`).

**Optional source-side change:** add a doc-comment at the top of each affected test referencing the nextest config:
```rust
// Phase 44 REQ-TEST-HYG-02 (D-44-D3): this test is run via cargo-nextest
// under subprocess-per-test isolation (.config/nextest.toml) because the
// PATH/PATHEXT/COMSPEC/SystemRoot/windir/SystemDrive env-var redirections
// it exercises race with sibling tests under cargo-test's in-process
// parallel runner. The EnvVarGuard Drop here saves the canonical baseline
// against the SUBPROCESS init env, not the cargo-test parent process.
```

---

#### `.config/nextest.toml` (NEW — REQ-TEST-HYG-02 D-44-D3)

**Analog:** **NONE in this repo.** Pattern source is the nextest documentation current at plan-open (`https://nexte.st/book/configuration.html`).

**Target shape (planner picks `[[profile.default.overrides]]` block vs `[test-groups]` declaration — both acceptable per D-44-D3 Claude's Discretion):**

Option A — `[[profile.default.overrides]]`:
```toml
# Phase 44 REQ-TEST-HYG-02 (D-44-D3): subprocess-per-test isolation for
# the two env_vars tests that race under cargo-test's in-process parallel
# runner. Scoped to these tests only; all other tests stay parallel.
#
# Reviewers: extend this file only when a new test is empirically observed
# to race; do NOT preemptively expand the scope.

[[profile.default.overrides]]
filter = 'test(=windows_run_redirects_profile_state_vars_into_writable_allowlist) + test(=windows_run_redirects_temp_vars_into_writable_allowlist)'
threads-required = 'num-cpus'   # take all threads → effectively serialized
```

Option B — `[test-groups]`:
```toml
[test-groups]
env-var-mutating = { max-threads = 1 }

[[profile.default.overrides]]
filter = 'test(=windows_run_redirects_profile_state_vars_into_writable_allowlist) + test(=windows_run_redirects_temp_vars_into_writable_allowlist)'
test-group = 'env-var-mutating'
```

Planner picks final shape; SC#3 validates with 50 consecutive runs.

**CI wire-up:** the Windows CI job that runs `env_vars.rs` opts in with:
```yaml
- name: Run env_vars tests under nextest subprocess isolation
  run: cargo nextest run -p nono-cli --test env_vars --config-file .config/nextest.toml
```
Other workflows continue to use `cargo test` unchanged.

---

#### Sibling-repo regression tests — verification analogs

**Analog A (CR-01, REQ-TEST-HYG-03):** **`bindings/c/src/lib.rs:283-293`** verbatim. Both nono-py and nono-ts must mirror this assertion shape.

**Source pattern (verbatim, lines 279-293):**
```rust
/// Phase 41 D-09 (CR-01): BrokerNotFound maps to ErrSandboxInit (-6),
/// NOT ErrPathNotFound (-1). The broker-discovery failure is an
/// installation/runtime defect (sandbox cannot init), not a user-input
/// path-resolution failure. Locks the D-09 mapping against regression.
#[test]
fn broker_not_found_maps_to_err_sandbox_init() {
    let err = nono::NonoError::BrokerNotFound {
        path: std::path::PathBuf::from(r"C:\fake\nono-shell-broker.exe"),
    };
    let code = map_error(&err);
    assert!(
        matches!(code, types::NonoErrorCode::ErrSandboxInit),
        "BrokerNotFound must map to ErrSandboxInit; got {code:?}"
    );
}
```

**Sibling test shape (nono-py, suggested — planner reads sibling repo at clone-time per D-44-D2 to confirm idiom):**
```python
# nono-py: tests/test_broker_ffi_mapping.py
import pytest
from nono import SandboxInitError, NonoError

def test_broker_not_found_maps_to_sandbox_init_error():
    """Phase 44 REQ-TEST-HYG-03 lockstep with bindings/c/src/lib.rs:285-291.

    A missing broker binary on Windows must surface as SandboxInitError
    (not FileNotFoundError or NonoError plain). Mirrors the C FFI
    mapping `BrokerNotFound -> NonoErrorCode::ErrSandboxInit (-6)`.
    """
    # Trigger via nono.run() with NONO_TEST_BROKER_PATH=<nonexistent>
    with pytest.raises(SandboxInitError):
        # ... test setup that triggers broker discovery failure
```

**Sibling test shape (nono-ts, suggested — planner reads sibling repo at clone-time):**
```typescript
// nono-ts: test/broker-ffi-mapping.test.ts (or .vitest.ts)
import { describe, it, expect } from 'vitest';
import { SandboxInitError, run } from '@always-further/nono';

describe('Phase 44 REQ-TEST-HYG-03: broker FFI mapping lockstep', () => {
    it('broker not found maps to SandboxInitError', async () => {
        // Mirrors bindings/c/src/lib.rs:285-291
        await expect(
            run({ /* setup that triggers broker discovery failure */ })
        ).rejects.toThrow(SandboxInitError);
    });
});
```

**Analog B (CR-02, REQ-TEST-HYG-04):** **`crates/nono-shell-broker/src/main.rs:530-565`** verbatim — two paired tests (null + INVALID_HANDLE_VALUE).

**Source pattern (verbatim, lines 530-565):**
```rust
/// Phase 41 D-11 (CR-02): a null or INVALID_HANDLE_VALUE handle is REJECTED
/// at the broker argv parser. Pseudo-handle confusion at `(HANDLE)0` and
/// the `(HANDLE)-1` sentinel are blocked before any UpdateProcThreadAttribute
/// call. Locks the CR-02 fix against regression.
#[test]
fn parse_args_null_inherit_handle_returns_error() {
    let raw = argv(&["--shell", "foo", "--cwd", r"C:\", "--inherit-handle", "0x0"]);
    let Err(NonoError::SandboxInit(msg)) = parse_args(&raw) else {
        panic!("expected SandboxInit error on --inherit-handle 0x0");
    };
    assert!(
        msg.contains("null") || msg.contains("INVALID_HANDLE_VALUE"),
        "error message must indicate null-handle rejection, got: {msg}"
    );
}

#[test]
fn parse_args_invalid_handle_value_inherit_handle_returns_error() {
    let raw = argv(&["--shell", "foo", "--cwd", r"C:\", "--inherit-handle", "0xFFFFFFFFFFFFFFFF"]);
    // ... mirrors the null test shape
}
```

**Sibling tests** (nono-py + nono-ts): mirror BOTH tests in each sibling, asserting `--inherit-handle 0x0` and `--inherit-handle 0xFFFFFFFFFFFFFFFF` both raise a structured `SandboxInitError` (Python) / `SandboxInitError` (TS). Test discovery happens at clone-time per D-44-D2.

---

#### CR-03/CR-04 archive (D-44-D4 — bookkeeping commit, no code change)

**Analog:** no code analog — this is a `git mv` from `.planning/todos/pending/v24-cr-03-broker-empty-handle-list-path.md` → `.planning/todos/done/` (and CR-04 sibling). Commit body must reference Phase 41 close SHA `13cc0628` as resolution ref. Pattern matches the prior milestone-close bookkeeping commits (mood: archival, not work).

---

## Shared Patterns

### Pattern 1 — Env-var test isolation (CLAUDE.md § Environment variables in tests)

**Source:** `crates/nono-cli/src/test_env.rs` + `crates/nono-cli/tests/common/test_env.rs`
**Apply to:** Plan 44-01 (`tests/auto_pull_e2e_linux.rs` WR-03/WR-04/IN-01)

**Excerpt (canonical Drop-restore guard):**
```rust
pub struct EnvVarGuard {
    original: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    #[must_use]
    pub fn set_all(vars: &[(&'static str, &str)]) -> Self {
        let original = vars.iter().map(|(key, _)| (*key, std::env::var(key).ok())).collect();
        for (key, value) in vars { std::env::set_var(key, value); }
        Self { original }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, value) in self.original.iter().rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
```

**Critical implementation note for planner:** `tests/common/test_env.rs` is currently `#![cfg(target_os = "windows")]`. Plan 44-01 WR-03/WR-04 widens the gate to include Linux. The associated `lock_env()` primitive must be ADDED to the mirror (currently only in `src/test_env.rs` which is binary-only).

### Pattern 2 — Atomic file write (tmp + rename)

**Source:** `crates/nono-cli/src/package.rs:367-379` (`write_lockfile`)
**Apply to:** Plan 44-01 IN-01 P43 (`pack_update_hint::save_state`)

**Excerpt:**
```rust
let tmp_path = path.with_extension("json.tmp");
fs::write(&tmp_path, format!("{json}\n")).map_err(NonoError::Io)?;
fs::rename(&tmp_path, &path).map_err(NonoError::Io)?;
```

### Pattern 3 — Path component comparison (CLAUDE.md § Common Footguns #1)

**Source:** `crates/nono/src/trust/signing.rs::validate_oidc_issuer` (lines 86-123); `crates/nono-cli/src/exec_strategy/supervisor_linux.rs::detect_from_str` (lines 915-950)
**Apply to:** Plan 44-01 WR-01 P43 (snapshot.rs doc) and WR-06 P43 (case-insensitive registry name); CLAUDE.md § Path Handling
**Excerpt (component-level rejection of prefix-match attack):**
```rust
if iss_url.host_str() != pin_url.host_str() {
    return Err(NonoError::ConfigParse(format!(
        "OIDC issuer host mismatch: ... \
         Rejected prefix-match attack (CLAUDE.md § Common Footguns #1).",
    )));
}
```

### Pattern 4 — `#[cfg(test)] mod tests` in-file unit tests

**Source:** `crates/nono-cli/src/platform.rs:599+`; `crates/nono/src/trust/signing.rs:507+`; `crates/nono/src/error.rs:421+`
**Apply to:** every Plan 44-01 commit that fixes a function-level bug — add regression test to existing in-file `mod tests`. Idiom is:
```rust
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn <descriptive_name_that_locks_the_invariant>() {
        // ...
    }
}
```

`#[allow(clippy::unwrap_used)]` ONLY inside `#[cfg(test)]` modules per CONVENTIONS.

### Pattern 5 — One commit per warning class with DCO sign-off (Phase 41 D-07 / D-44-A4)

**Source:** Phase 41 commit history; CLAUDE.md § Coding Standards "Commits"
**Apply to:** Plan 44-01 commit map (~5-7 commits)

**Commit message + trailer shape:**
```
chore(44-01): test thread-safety

WR-03 + WR-04 + IN-01 (Phase 37): replace file-local EnvGuard with
canonical EnvVarGuard from tests/common/test_env.rs; pin
XDG_CONFIG_HOME alongside NONO_TEST_HOME in all 5 tests.

Closes 37-REVIEW.md WR-03, WR-04, IN-01.

Signed-off-by: <Name> <email>
```

### Pattern 6 — Cross-target clippy verification for cfg-gated Unix code (CLAUDE.md MUST + D-44-E2)

**Source:** `.planning/templates/cross-target-verify-checklist.md`
**Apply to:** every Plan 44-01 commit touching `exec_strategy/supervisor_linux.rs`, `tests/auto_pull_e2e_linux.rs`, `tests/resl_nix_linux.rs`, `bindings/c/src/lib.rs`

**Required commands (per CLAUDE.md § Coding Standards):**
```bash
cargo clippy --workspace --target x86_64-unknown-linux-gnu -- -D warnings -D clippy::unwrap_used
cargo clippy --workspace --target x86_64-apple-darwin       -- -D warnings -D clippy::unwrap_used
```

Windows-host `cargo check` is NOT a substitute. If cross-toolchain unavailable, mark verification REQ as PARTIAL per the checklist and defer to live CI.

---

## No Analog Found

Files with no in-repo analog (planner consults external docs / sibling repos):

| File | Role | Reason |
|------|------|--------|
| `.config/nextest.toml` (NEW) | nextest profile config | First nextest config in this repo. Pattern source: `https://nexte.st/book/configuration.html` current at plan-open. |
| `../nono-py/<new test file>` | sibling-repo regression test (PyO3) | Cross-repo; planner reads sibling at clone-time per D-44-D2 to discover pytest vs unittest idiom and existing test layout. |
| `../nono-ts/<new test file>` | sibling-repo regression test (napi-rs) | Cross-repo; planner reads sibling at clone-time to discover vitest vs jest idiom and napi-rs internal-test convention. |
| `crates/nono-cli/tests/common/test_env.rs` lock primitive addition | `lock_env()` mirror in common module | Currently only exists in `src/test_env.rs` (binary-only). Planner adds the static Mutex + accessor to the integration-test mirror. No prior precedent in `tests/common/` for a sync primitive. |

---

## Metadata

**Analog search scope:**
- `crates/nono/src/{trust,undo,error}.rs` — library primitives
- `crates/nono-cli/src/{pack_update_hint,package,platform,sandbox_prepare,cli,diagnostic_formatter,session_commands,session_commands_windows,test_env}.rs`
- `crates/nono-cli/src/exec_strategy/supervisor_linux.rs`
- `crates/nono-cli/tests/{auto_pull_e2e_linux,deny_overlap_run,env_vars,resl_nix_linux,common/test_env}.rs`
- `bindings/c/src/lib.rs` (lines 270-310)
- `crates/nono-shell-broker/src/main.rs` (lines 520-580)
- `.github/{workflows/phase-37-linux-resl.yml, scripts/check-cli-doc-flags.sh}`
- `.planning/phases/{37,41,43}-*/{REVIEW,CONTEXT,SUMMARY}.md`
- `CLAUDE.md` § Coding Standards + § Security Considerations

**Files scanned:** 19 source files + 5 supporting markdown files
**Pattern extraction date:** 2026-05-20
**Phase type:** drain (retrofit-on-existing-files; only `.config/nextest.toml` is a truly new file)
