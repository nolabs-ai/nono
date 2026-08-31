---
nep: 0001
title: Pre-1.0.0 tech debt, deprecation, and API-freeze cleanup
authors:
  - Aleksy Siek
status: draft
created: 2026-08-31
superseded-by:
---

# NEP-0001: Pre-1.0.0 tech debt, deprecation, and API-freeze cleanup

## Summary

Before nono reaches 1.0.0, we should remove the deprecations, dead
code, backward-compat aliases, and library/CLI boundary drift that
have built up since the project started. Once 1.0.0 ships, the public
API of `nono` becomes something we promise to keep working. We should
make sure what we're freezing is what we actually want to support, not
a pile of decisions we already know are wrong.

The guiding rule for this NEP is that 1.0.0 is a clean slate. Anything
marked deprecated, legacy, or `remove_by="indefinite"` gets removed. A
tag of "indefinite" was never really a decision, it just meant nobody
had scheduled one yet (see `crates/nono/src/trust/types.rs:48` for an
example of the marker convention). 1.0.0 is the point where that gets
resolved by removing the thing, not by deferring it again. If
something genuinely needs to stay, that has to be an explicit,
argued-for exception written into this NEP's discussion, not the
default outcome.

## Motivation

The project is currently at 0.74.0. A number of deprecations across
`nono`, `nono-cli`, and `nono-proxy` are already marked "removed in
1.0.0" in code comments and `#[deprecated(since = ...)]` attributes
(for example `crates/nono/src/diagnostic/codes.rs:72`), but they
haven't actually been removed yet. Others were never formally marked
deprecated but are clearly meant to be temporary: aliases, fields
commented "legacy," and compat shims tagged `remove_by="indefinite"`.

This NEP comes out of a full search through the three core crates we
support (`nono`, `nono-cli`, `nono-proxy`), looking for
`#[deprecated]` items, `#[allow(dead_code)]` / `#[allow(unused)]`,
stale TODO/FIXME/HACK comments, `.unwrap()` / `.expect()` outside
tests, missing `// SAFETY:` docs, policy logic that has leaked into
the library, and public API that looks unused or inconsistent.

Most of the debt is concentrated in `nono-cli`: a handful of
deprecated files with their own pre-written removal runbooks
(`deprecated_schema.rs`, `deprecated_policy.rs`,
`command_blocking_deprecation.rs`), plus the bulk of the
`remove_by="indefinite"` aliases. `nono` carries the smaller,
higher-stakes share, since its public API is what actually freezes at
1.0.0. `nono-proxy` has the least, mostly one dead deprecated function
and a legacy config compat shim. This NEP's job is mostly to schedule
and execute what's already been flagged, plus a handful of things the
audit turned up that weren't yet marked.

### Goals

- Remove every deprecation currently tagged "removed in 1.0.0" and
  every alias currently tagged `remove_by="indefinite"`. No more
  version-scheduling, no more deferral. 1.0.0 is the removal point.
- Close the one confirmed case of policy logic living in the library
  instead of the CLI: `DANGEROUS_ENV_VAR_NAMES` in
  `crates/nono/src/keystore.rs:159-179`.
- Resolve all 15 `#[allow(dead_code)]` sites in `nono-cli`.
- Remove public API in `nono` that has no known caller inside the
  workspace, so it doesn't get locked in by the freeze.
- Drop the AGENTS.md claim that `deny.access`, `deny.unlink`, and
  `symlink_pairs` are macOS-only features, since none of them exist
  anywhere in `crates/nono/src`.
- Add `#[must_use]` to the sandbox-apply functions that are currently
  missing it.

### Non-Goals

- New features or capability types. This NEP only removes and
  corrects things, it doesn't add anything.
- Rewriting `nono-proxy`'s `endpoint_rules` compat shim
  (`crates/nono-proxy/src/config.rs:804-1374`). This NEP only decides
  whether it stays or goes, not how to redo it.
- Performance work.
- Anything that turns out to need its own NEP under the existing
  rules in `neps/README.md` (for example, if this audit had turned up
  a genuinely new capability type needed, that would be split out, not
  folded in here).

## Proposal

The list below is organized by crate. Each numbered item is
independently shippable as its own piece of work referencing this
NEP. Nothing here requires bundling everything into one change.

### `nono` (core library), highest priority since this is what freezes

1. **Execute the deprecations already scheduled for removal in 1.0.0.**
   All three are marked `#[deprecated(since = ..., note = "removed in
   1.0.0")]` today:
   - `suggested_flag_for_remediation()` in
     `crates/nono/src/diagnostic/codes.rs:72`
   - `IpcDenialRecord.suggested_flag` and its three
     `#[allow(deprecated)]` call sites in
     `crates/nono/src/diagnostic/records.rs:47,66,71,186`
   - `TRUST_POLICY_VERSION` and `TrustPolicy.version` in
     `crates/nono/src/trust/types.rs:15,41-45`

2. **Move `DANGEROUS_ENV_VAR_NAMES` out of the library.** It's defined
   at `crates/nono/src/keystore.rs:159-179` and enforced at
   `crates/nono/src/keystore.rs:824-831,897-920`. This is a security
   judgment call (it lists things like `LD_PRELOAD`,
   `DYLD_INSERT_LIBRARIES`, `BASH_ENV`, `PYTHONPATH`), and AGENTS.md
   is explicit that decisions like this belong in `nono-cli`'s policy
   layer, not in the library. The default here is to move the list
   into CLI-supplied config that gets threaded through
   `CapabilitySet`, matching how everything else in this project is
   already split. Keeping it in the library is the exception, and it
   would need a real argument (something like "keystore integrity is
   a different concern from general command policy") to survive
   review.

3. **Remove public API in `nono` that has no known caller.** None of
   these are referenced anywhere else in the workspace:
   - `CapabilityRequest` in `crates/nono/src/supervisor/types.rs:21`
   - `SessionObservationInput` in
     `crates/nono/src/diagnostic/observation.rs:14`
   - `scrub_value`, `scrub_env_name`, `scrub_env_value`, `scrub_argv`,
     `scrub_header` in `crates/nono/src/scrub.rs:213,233,249,273,329`,
     which are thin wrappers around the `..._with_policy` versions and
     have no callers of their own
   Public-and-unused doesn't carry forward into a frozen 1.0.0 API by
   default. If one of these turns out to be part of a documented
   contract for some downstream consumer, that should be called out
   explicitly and kept instead.

4. **Give `UnixSocketCapState.mode` a real type.** It's a `String`
   today (`crates/nono/src/state.rs:57`) holding one of
   `"connect"`/`"connect+bind"`/`"bind-only"`. Convert it to an enum
   before this struct's serialization format becomes something we
   have to keep compatible forever.

5. **Resolve `is_directory` in `crates/nono/src/state.rs:53`.** It's
   commented "legacy" but was never formally deprecated. Same rule as
   everything else in this NEP: remove it and migrate whatever
   replaced it, rather than starting a fresh deprecation cycle that
   just pushes the same decision out further.

6. **Remove the `instruction_patterns` alias in
   `crates/nono/src/trust/types.rs:49`.** It's a
   `#[serde(alias = "instruction_patterns")]` on the `includes` field,
   tagged `remove_by="indefinite"` under issue #435. It goes back to
   the 2026-03-20 rename from `instruction_patterns` to `includes`
   (`2c1eb5cb`). This is the same cleanup as the `nono-cli` alias
   group below, it just happens to live in the library, which makes it
   a public API break that needs to be sequenced with the rest of the
   `nono` changes above rather than treated as an incidental flag
   removal.

7. **Add `#[must_use]` to the sandbox-apply functions that are
   missing it.** Affected sites: `crates/nono/src/sandbox/linux.rs`
   at lines 345, 391, 782, 790, 800, 961, 974, 980, 1362, and 1885,
   and `crates/nono/src/sandbox/macos.rs` at lines 64, 122, 145, and
   899. If a caller drops the `Result` from one of these, they may
   believe a process is sandboxed when it isn't. It should land as
   soon as possible and doesn't need to wait on the rest of this NEP.

8. **Fix the AGENTS.md mismatch on macOS-only deny features.**
   AGENTS.md documents `deny.access`, `deny.unlink`, and
   `symlink_pairs` as macOS Seatbelt-only capabilities, but none of
   them exist anywhere in `crates/nono/src`. There's no removal
   history in the codebase for them, which means they were documented
   before they were built and never followed up on. Drop the claim
   from AGENTS.md. If we later decide these capabilities are worth
   building, that's its own issue, not something to fold back in here.

### `nono-cli`

1. **Delete `crates/nono-cli/src/deprecated_schema.rs`** (824 lines).
   This is the legacy profile schema compat layer (`security` and
   `legacy_policy` fields, the `--override-deny` alias). Its own file
   header already has an 8-step removal runbook titled "DELETE THIS
   FILE when v1.0.0 deprecations are removed."

2. **Delete `crates/nono-cli/src/deprecated_policy.rs`** (78 lines).
   This is the `nono policy <sub>` alias for `nono profile <sub>`, and
   it has its own removal runbook too. Update the references in
   `crates/nono-cli/src/cli.rs:64,519-541,930` at the same time.

3. **Retire `crates/nono-cli/src/command_blocking_deprecation.rs`**
   (192 lines). This has been deprecated since v0.33.0. It's a
   startup-only gate on `commands.{allow,deny}` that is explicitly
   documented in the file as bypassable by child processes, since
   capability-based gating has already superseded it. Removing this
   also clears out the roughly 11 cascading `#[allow(deprecated)]`
   call sites in `crates/nono-cli/src/capability_ext.rs`,
   `crates/nono-cli/src/profile/mod.rs`, and
   `crates/nono-cli/src/profile_cmd.rs`.

4. **Resolve all 15 `#[allow(dead_code)]` sites in `nono-cli`.**
   AGENTS.md says this attribute shouldn't exist in the codebase.
   Sites: `crates/nono-cli/src/setup.rs:14`,
   `crates/nono-cli/src/policy.rs:21,32,34,41`,
   `crates/nono-cli/src/test_env.rs:9`,
   `crates/nono-cli/src/network_policy.rs:20,32,34,41`,
   `crates/nono-cli/src/wiring.rs:284,1498`,
   `crates/nono-cli/src/sandbox_log.rs:206,279`, and
   `crates/nono-cli/src/profile/mod.rs:41`. `policy.rs` and
   `network_policy.rs` have the exact same 4-site pattern, so they
   probably share one root cause and one fix. Either delete the dead
   code, or if it's actually load-bearing for a test that isn't
   written yet, write that test.

5. **Remove every `remove_by="indefinite"` alias outright, no
   scheduling.** The `ALIAS(...)` marker convention itself is fairly
   new: it was introduced on 2026-05-01 in PR #594 (the schema
   restructure) and used at the time to retroactively tag aliases that
   already existed. All but one of the aliases in the "indefinite"
   group is tagged `introduced="v0.0.0"`, meaning they've been present
   since the repo's very first commit on 2026-02-09. "Indefinite" here
   has only ever meant "nobody scheduled a decision," not "kept on
   purpose." There are 18 unique aliases across 31 marker occurrences
   (the count is higher because the same alias often appears once for
   the CLI flag and once for the profile field, or repeats across
   subcommands). Grouped by their tracking issue:

   - **#302**: `--allow-net` / `--block-net`
     (`crates/nono-cli/src/cli.rs:1192,1205,1818,2309`)
   - **#415**: `allow_domain`/`--allow-domain`, `credentials`,
     `open_port`/`--open-port`, `--listen-port`,
     `upstream_proxy`/`--upstream-proxy`,
     `upstream_bypass`/`--upstream-bypass`
     (`crates/nono-cli/src/cli.rs:1238,1261,1271,1289,1300,1588,1610,1621,1830,1840`
     and `crates/nono-cli/src/profile/mod.rs:1786,1804,1813,1861,1867`).
     Six legacy names that all collapse into the same net-config
     flattening work, tracked under one issue.
   - **#143**: `env_credentials`
     (`crates/nono-cli/src/policy.rs:126`,
     `crates/nono-cli/src/profile/mod.rs:2463,2634`)
   - **#124**: `rollback` (`crates/nono-cli/src/policy.rs:135`,
     `crates/nono-cli/src/config/user.rs:28`,
     `crates/nono-cli/src/profile/mod.rs:2485,2653`)
   - **#875**: `--suppress-save-prompt`/`suppress_save_prompt`
     (`crates/nono-cli/src/cli.rs:1173,1799`,
     `crates/nono-cli/src/profile/mod.rs:204`). This is the one alias
     not present since v0.0.0 (it was introduced in v0.52.0), but the
     same clean-slate rule still applies to it.
   - **#435**: `instruction_patterns` (`crates/nono/src/trust/types.rs:49`,
     see the `nono` section above). This one lives in the core
     library, not `nono-cli`, so removing it is a public API break
     that needs to be sequenced with the rest of the `nono` changes.
   - **No tracking issue at all**: `command_args`
     (`crates/nono-cli/src/profile/mod.rs:2671`, `issue="N/A"`). This
     is a process bug on its own: every alias is supposed to have a
     tracking issue under the `ALIAS(...)` convention, which
     `crates/nono-cli/tests/alias_inventory.rs` exists to check. File
     an issue for this one before or alongside removing it.

   Two more aliases are already tagged `remove_by="v1.0.0"` and should
   land in the same removal pass, since they already have a real
   version and don't need a new decision: `--bypass-protection`
   (`crates/nono-cli/src/cli.rs:1163,1789`, issue #594) and
   `--credential` (`crates/nono-cli/src/cli.rs:1340,1691`, issue
   #143).

6. **Resolve the 3 hidden subcommands in `nono-cli`.** They're marked
   `#[command(hide = true)]` at `crates/nono-cli/src/cli.rs:498,711,715`,
   including a hidden `Prune` command. The default is to remove them
   unless one is actually in active use and worth documenting as a
   real, supported 1.0-stable command. Being hidden with no
   explanation isn't a state we want to freeze into a stable CLI.

7. **Remove `crates/nono-cli/src/legacy_cleanup.rs`** (573 lines).
   This handles migration for pre-0.43 Claude Code hooks and is
   self-documented as eventually becoming a no-op once everyone has
   migrated. 1.0.0 is a reasonable sunset point rather than leaving it
   open-ended. If there's real signal that installs still depend on
   it, that's a deliberate exception worth recording here, not
   something to fall back on by default.

8. **Lower priority, not required for the freeze:** refactor the 7
   `#[allow(clippy::too_many_arguments)]` sites in
   `crates/nono-cli/src/exec_strategy.rs` and
   `crates/nono-cli/src/tool-sandbox/platform/{linux,macos}.rs` into
   parameter structs. Also worth a pass: audit the roughly 19
   `std::process::exit` call sites (for example
   `crates/nono-cli/src/main.rs:143,148,157,160`) to confirm none of
   them are swallowing a `Result` that should propagate through
   `NonoError` instead.

### `nono-proxy`

1. **Remove `CredentialStore::load()`** in
   `crates/nono-proxy/src/credential.rs:591-603`. It's been deprecated
   since 0.64.0 and marked "removed in 1.0.0," and there are no call
   sites anywhere in the workspace.

2. **Remove the `endpoint_rules` legacy compat shim** unless there's a
   concrete, currently-in-use config format that depends on it. It
   spans `crates/nono-proxy/src/config.rs:804-1374`,
   `crates/nono-proxy/src/route.rs:46`,
   `crates/nono-proxy/src/tls_intercept/handle.rs:391,703,907,2592`,
   and `crates/nono-proxy/src/tls_intercept/h2_forward.rs:279,2374-2388`.
   It's well-tested and correctly implemented, but it has "legacy" in
   its own name, and the clean-slate default is to remove it. If it
   turns out real users are still on the old config shape, that's
   grounds for a deliberate, time-boxed exception recorded here (with
   a real removal version, not "indefinite"), not a silent keep.

3. **Lower priority:** tighten the one non-test `.expect()` in
   `crates/nono-proxy/src/aws/endpoints.rs:20` (it's an infallible
   static regex init, but it still violates the letter of the
   zero-unwrap policy). Also worth considering: parameter structs for
   the 10 `#[allow(clippy::too_many_arguments)]` sites in this crate.

### Sequencing

Everything here can land as separate pieces of work in any order, but
this is the order that makes the most sense:

1. Land the `#[must_use]` fix (`nono` item 7 above) as a standalone
   correctness and security fix.
2. Execute everything already scheduled for removal with no open
   design question: the `#[deprecated(...removed in 1.0.0)]` items,
   and all the `remove_by="indefinite"` alias removals across `nono`,
   `nono-cli`, and `nono-proxy`. That's 18 unique aliases, the 3
   already-scheduled deprecations, and the 2 aliases already tagged
   `v1.0.0`.
3. Resolve the small number of genuine judgment calls this NEP raises:
   the `DANGEROUS_ENV_VAR_NAMES` library/CLI boundary question,
   whether any of the "unused" public API in `nono` actually has an
   external consumer, and whether `endpoint_rules` has real users.
   These default to removal or moving the code, and only stay as-is
   if someone makes the case for it during review.
4. Execute whatever came out of step 3, plus the `nono-cli` dead-code
   cleanup and the hidden-subcommand decision.

## Security Considerations

- **Least privilege.** Nothing in this NEP grants a sandboxed process
  any new capability. Several items actually reduce attack surface by
  removing policy logic that was either bypassable or in the wrong
  place: retiring `command_blocking_deprecation.rs`
  (`nono-cli` item 3) and moving `DANGEROUS_ENV_VAR_NAMES` out of the
  library (`nono` item 2) both fall into this category. The
  `#[must_use]` fix (`nono` item 7) directly closes a fail-secure gap:
  today, a dropped `Result` from a sandbox-apply call can silently
  leave a process unsandboxed.

- **Fail-secure behavior.** Removing `command_blocking_deprecation.rs`
  is a fail-secure improvement, not a regression. It's a feature that
  is already documented in its own source as bypassable by child
  processes, and capability-based gating has already replaced it.
  When it's removed, we should confirm nothing silently falls back to
  the weaker mechanism.

- **Path handling.** Nothing in this NEP touches path canonicalization
  or path comparison logic. None of the audit's findings were in that
  area.

- **Library/CLI boundary.** The `DANGEROUS_ENV_VAR_NAMES` item is the
  one confirmed boundary issue this NEP raises. The resolution needs
  to either put the decision fully in `nono-cli`'s policy layer, or
  come with an explicit written justification for why keystore
  integrity is a library-level concern rather than a policy one.

- **Credential and secret secrecy.** `nono-proxy`'s credential
  handling already uses `Zeroizing` for secrets, has redacting `Debug`
  impls, and doesn't log raw secret values or leak them into child
  process environments. The one item here that touches credentials,
  `CredentialStore::load()`, is dead code with zero callers, so
  removing it has no secrecy impact.

- No item in this NEP introduces new unsafe code.

## Alternatives Considered

- **Do nothing, and let 1.0.0 ship with the current deprecations still
  in place.** Rejected. Several of these are already self-documented
  in the code as "removed in 1.0.0." Shipping 1.0.0 without actually
  removing them breaks the promise those comments make, and it locks
  in a weaker security posture (like the bypassable command blocking
  in `command_blocking_deprecation.rs`) as part of what we call
  stable.

- **Do this as one giant change.** Rejected. These items span three
  crates and have very different risk profiles. Some are pure
  deletions with a removal runbook already written, others need a
  design decision first. Bundling them together would force reviewers
  to evaluate unrelated risk all at once and would make it impossible
  to roll back just one piece if something went wrong.

- **Leave the unused public API and the `remove_by="indefinite"`
  aliases in place and decide later.** Rejected, because this is
  exactly the status quo this NEP exists to end. "Indefinite" has
  meant exactly this since the marker convention was introduced on
  2026-05-01 in PR #594: a deferred decision with no owner and no
  deadline. Most of these aliases have been sitting in the codebase
  for months. "Later" has already had time to happen and it hasn't.
  1.0.0 is the deadline. The default from here is removal, and keeping
  anything requires an explicit, argued exception.

- **Keep some indefinite aliases "just in case," without anyone
  actually arguing for it.** Rejected as a default. A specific alias
  can still survive this NEP, but only if someone attaches a real
  justification (actual current usage, no reasonable migration path)
  to its own removal. It shouldn't survive just because removing it
  wasn't strictly required to ship.

## Open Questions

None. The Proposal section states a default outcome for every item in
this NEP, including the handful the audit couldn't fully resolve on
its own (the `DANGEROUS_ENV_VAR_NAMES` boundary call, the unused
public API in `nono`, and the `endpoint_rules` shim in `nono-proxy`).
Those defaults hold unless a change against this NEP attaches a
concrete, written justification for keeping something, at which point
that becomes a recorded exception rather than a reopened question.
