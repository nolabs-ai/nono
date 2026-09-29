---
nep: 0003
title: Move macOS keychain authorisation to `nono-cli`
authors:
  - Kurtis Charnock
status: draft
created: 2026-09-23
superseded-by:
---

# NEP-0003: Move macOS keychain authorisation to `nono-cli`

## Summary

Move the decision about whether a sandboxed process may reach the macOS
keychain out of the `nono` library and into `nono-cli` and make that decision
require an explicit `filesystem.bypass_protection` entry when a deny group
covers the keychain.

## Motivation

See issue #1932:

A profile that inherits `deny_keychains_macos` and adds `filesystem.allow_file:
["$HOME/Library/Keychains/login.keychain-db"]` can read the keychain, while
`nono why` reports the same path as DENIED. Enforcement and diagnostics
disagree and the deny is defeated without `filesystem.bypass_protection`.

Two mechanisms combine to produce that:

- `CapabilitySet::remove_exact_file_caps_for_paths` drops only caps with paths
  that equal a deny path. The deny is the directory `~/Library/Keychains`; the
  grant is a file inside it, so the cap survives.
- `nono-cli::policy::apply_macos_keychain_db_exception` then emits specific-op
  allows for that file as platform rules, which the library emits last and which
  therefore beat the deny group's earlier specific-op denies.

Separately, the library infers keychain authorisation from the capability set in
`has_explicit_keychain_db_access`  to decide whether to suppress the
`securityd`/`SecurityServer`/`keychaind`/`secd`/ `security.agent` mach-lookup
denies. That inference is a policy decision in the library (and it reads `$HOME`
to build its candidate paths) making an enforcement decision out of an
environment variable the library does not control and that the tool-sandbox
launcher has to forward specifically to keep that inference working.

### Goals

- A file grant for a macOS keychain DB is ineffective unless a matching
  `filesystem.bypass_protection` entry exists (#1932).
- `nono why` and `nono run` agree for keychain paths, in both directions: a
  grant blocked by a deny reports denied, and a deny lifted by a bypass reports
  allowed.
- Remove `$HOME` as an input to library profile generation.
- A mediated command cannot reach a keychain the agent running it is denied.

### Non-Goals

- No changes to the Landlock/Linux implementation..
- No change to which paths `deny_keychains_macos` covers.

## Proposal

- Delete `has_explicit_keychain_db_access`. The library emits the five keychain
  mach-lookup denies unconditionally. It is policy-free and cannot tell an
  authorised grant from a bare one. A client that has decided keychain access
  is authorised re-allows those services through a platform rule.
- Add `nono-cli::policy::EffectiveDenyPolicy`: the resolved deny paths together
  with the `bypass_protection` paths that allow them, answering whether a path
  is still effectively denied. It becomes a single function shared by `nono
  why`, sandbox preparation, and the tool-sandbox child path, so the divergence
  in #1932 cannot be reintroduced by one caller drifting from another.
- `apply_macos_keychain_db_exception` takes an `&EffectiveDenyPolicy` and
  becomes the sole authoriser. Alongside the file-op allows it already emits,
  it emits `(allow mach-lookup (global-name ...))` for the five services.
  Because the library emits `caps.platform_rules()` after those denies
  (`crates/nono/src/sandbox/macos.rs`), the CLI's allows win under
  last-matching-rule.
- The exception applies only when all of the following hold:
  1. The capability is a keychain DB file, or a directory grant covering one.
     A directory grant unlocks only the Mach services. Its file rules come from
     ordinary allow emission.
  2. Its source is user intent (`--allow-file` or a profile `filesystem`
     entry), not a group. Group-sourced caps continue to be ignored.
  3. Neither the grant's original nor its resolved form is still covered by a
     deny. Requiring both forms to clear stops a symlink pointing at a denied
     keychain from laundering the grant.

  Mach IPC cannot be split by access mode (securityd brokers the whole keychain
  over one service) so an authorised grant unlocks the services whatever mode it
  requested, while the file allows stay mode-scoped. Any failure, including a
  non-UTF-8 path or an unset `HOME`, skips the exception and leaves the denies
  standing.

  A surviving file cap still emits a plain allow earlier in the profile, but
  the deny group's later specific-op denies beat it, so withholding the
  exception is sufficient to deny file access. Therefore no change to
  `remove_exact_file_caps_for_paths` is required on macOS.

- Bypass authority is the list `apply_deny_overrides` has actually applied, not
  the profile's raw `filesystem.bypass_protection`. A bypass naming a path
  absent from the host is warned about and dropped there, so recomputing the
  list downstream would hand back authority that the running sandbox never
  honoured.
  `PreparedCaps` carries `applied_bypass_paths`; the recomputed
  `PreparedProfile::bypass_protection_paths` is removed.
- Mediated commands: the tool-sandbox child path authorises a command policy's
  keychain grant against the *agent's* `EffectiveDenyPolicy`, so a command
  policy granting `login.keychain-db` cannot reach a keychain the outer sandbox
  is denied.

  API surface: no change to the library's public API or the C ABI.
  `has_explicit_keychain_db_access` is private and absent from
  `bindings/c/include/nono.h`.

  Platforms: macOS only. No Linux/Landlock changes.

  Backward compatibility: a behavioural break for any profile that grants a
  keychain DB file while inheriting `deny_keychains_macos`. Those profiles must
  add the path to `filesystem.bypass_protection`. This includes the registry
  pack `nolabs-ai/claude`. Keychain access currently reached through the
  `claude_code_macos` or `codex_macos` groups is unaffected, since group-sourced
  caps never triggered the exception. `nono why` output also changes: a deny
  path lifted by a bypass is now reported as allowed rather than denied,
  matching what the sandbox enforces.

  Documentation: `docs/cli/internals/seatbelt.mdx` states that users can
  override the protected-path list with `--allow` or `--read`, which is no
  longer true for keychains, and `docs/cli/clients/claude.mdx` describes
  keychain access as a property of the claude profile.

### Verification

- A keychain `allow_file`/`read_file`/`write_file` grant without a matching
  bypass emits no exception, and the library's mach denies stand.
- The same grant with a matching bypass emits file allows scoped to the
  requested mode, plus the mach allows.
- A bypass that names a sibling or unrelated path does not authorise the grant;
  a bypass on a child under a broader parent deny does.
- A grant reached through a symlinked `HOME` is still measured against the
  canonical deny, in both directions.
- Group-sourced and system-sourced grants never authorise.
- A directory grant unlocks the Mach services only when its covered DB is not
  denied.
- The CLI's mach allow lands after the library's deny in the generated profile.
- A command policy's keychain grant is refused when the agent is denied, and
  scoped to the requested mode when the agent holds a bypass.
- `nono why` and `nono run` agree for a keychain path in each case above.
- The tool-sandbox launcher path and the supervisor path reach the same
  decision. `apply_macos_keychain_db_exception` still reads `HOME`, so whichever
  process evaluates it must have `HOME` set; `crates/nono-cli/src/tool-sandbox/launch.rs`
  forwards it for that reason.

## Security Considerations

- Least privilege: reduces authority. A file grant no longer implies Mach IPC
  to the keychain daemons; that now requires an additional, explicit opt-in. For
  the mediated-command path a command policy is authorised against the agent's
  deny policy, so it can only ever narrow the agent's keychain authority, never
  exceed it.
- Fail-secure behavior: the library's default becomes an unconditional deny, so
  every failure mode in the CLI's authorisation leaves the denies in place
  rather than dropping them. Bypass authority is the list actually applied at
  enforcement time, so a bypass that was warned about and dropped cannot
  reappear as authority.
- Path handling: the candidate set is still derived from `$HOME` and compared
  by equality, but only in `nono-cli`, at the point where the deny set is
  known. Comparison is over `Path`, not strings. A grant is measured in both
  its original and its resolved form, so a symlink to a denied keychain does
  not launder it, and a deny recorded against a symlink still matches a bypass
  recorded against its target. A symlinked or non-canonical `HOME` that matches
  neither form yields no exception, which is the safe direction.
- Library/CLI boundary: moves the policy decision into `nono-cli` and leaves
  the library emitting mechanism only. The library no longer reads the
  environment to decide enforcement. The remaining coupling is the ordering
  contract — the library must keep emitting platform rules after its own denies
  — which is pinned by a test in the library.
- Credential & secret secrecy: no new handling. The keychain DB contents never
  pass through nono.

## Alternatives Considered

- Add `bypass_protection` to the library — duplicates code across both crates,
  including policy in `nono`.
- Make `remove_exact_file_caps_for_paths` subtree-aware and change nothing else
  — smaller, but it leaves the mach-lookup suppression inferred in the library
  from `$HOME`, so the keychain stays reachable over Mach IPC and the
  library/CLI boundary violation is untouched.

## Open Questions

- Does the same bug class apply on Linux?.
- How is the version skew between a released CLI and the `nolabs-ai/claude`
  registry pack handled?
