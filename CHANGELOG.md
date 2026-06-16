# Changelog

## [Unreleased]

### Features

- *(cli)* `$REPO_ROOT` variable expansion in profile path fields: resolves to the git
  repository root, auto-detected via `git rev-parse --show-toplevel` with
  worktree support. Override via `--repo-root DIR` flag or `NONO_REPO_ROOT` env
  var. Left unexpanded (path silently skipped) when not in a git repo.

## [0.63.0] - 2026-06-15

### Bug Fixes

- *(proxy)* Keep connection open for reactive proxy auth on CONNECT (#1151) ([#1151](https://github.com/always-further/nono/pull/1151))

- Report the actual blocked operation instead of the readable target path in sandbox denial diagnostics (#1150) ([#1150](https://github.com/always-further/nono/pull/1150))

- *(linux)* Trap sendto/sendmsg to prevent AF_UNIX datagram bypass (#1096) ([#1096](https://github.com/always-further/nono/pull/1096))

- *(cli)* Accept truthy env values for bool flags (#1136) ([#1136](https://github.com/always-further/nono/pull/1136))

- Replace stale nono.dev schema domains with nono.sh

- *(audit)* Address ledger review and clippy

- Write cargo vendor config for copr srpms

- *(aur)* Skip ssh-keyscan banner lines in host key check


### Build

- Add copr source rpm packaging (#1075) ([#1075](https://github.com/always-further/nono/pull/1075))


### CI/CD

- Use actions/attest


### Dependencies

- *(deps)* Bump ignore from 0.4.25 to 0.4.26 (#1160) ([#1160](https://github.com/always-further/nono/pull/1160))

- *(deps)* Bump chrono from 0.4.44 to 0.4.45 (#1159) ([#1159](https://github.com/always-further/nono/pull/1159))

- *(deps)* Bump time from 0.3.47 to 0.3.49 (#1158) ([#1158](https://github.com/always-further/nono/pull/1158))

- *(deps)* Bump zeroize from 1.8.2 to 1.9.0 (#1157) ([#1157](https://github.com/always-further/nono/pull/1157))

- *(deps)* Bump typify from 0.6.2 to 0.7.0 (#1156) ([#1156](https://github.com/always-further/nono/pull/1156))

- *(deps)* Bump actions/checkout from 6.0.2 to 6.0.3

- *(deps)* Bump x509-parser from 0.16.0 to 0.18.1

- *(deps)* Bump cbindgen from 0.29.2 to 0.29.3

- *(deps)* Bump hyper from 1.9.0 to 1.10.1


### Documentation

- Document diagnostics.suppress_system_services for macOS (#1076) (#1138) ([#1138](https://github.com/always-further/nono/pull/1138))

- *(readme)* Update agent commands and enhance feature descriptions (#1145) ([#1145](https://github.com/always-further/nono/pull/1145))

- *(readme)* Refine project description and history (#1143) ([#1143](https://github.com/always-further/nono/pull/1143))

- *(readme)* Update agent package publishing link (#1142) ([#1142](https://github.com/always-further/nono/pull/1142))

- *(cli-quickstart)* Add profile usage to quickstart guide

- Add copr installation instructions


### Features

- *(cli)* Move runtime state to XDG state dirs (#1152) ([#1152](https://github.com/always-further/nono/pull/1152))

- Add $PACK_DIR support to session_hooks for store pack support (#1073) ([#1073](https://github.com/always-further/nono/pull/1073))

- *(keyring)* Add NONO_KEYRING_TIMEOUT_SECS for keychain access (#977) ([#977](https://github.com/always-further/nono/pull/977))

- *(environment)* Add set_vars for static env injection (#1134) ([#1134](https://github.com/always-further/nono/pull/1134))

- *(pack-verification)* Skip pack verification on dry runs


### Miscellaneous

- *(project)* Add new issue template for agent package requests (#1081) ([#1081](https://github.com/always-further/nono/pull/1081))


### Refactoring

- *(diagnostic)* Move diagnostic UX out of core nono crate (#1155) ([#1155](https://github.com/always-further/nono/pull/1155))

- *(pull_ui)* Remove sigstore provenance display (#1144) ([#1144](https://github.com/always-further/nono/pull/1144))

- *(profiles)* Standardize profile names with namespace

- *(audit-ledger)* Move audit ledger logic to library crate

- *(audit)* Move audit integrity logic to nono crate


### Testing

- *(wsl2)* Fix has_landlock_network V4+ detection

## [0.62.0] - 2026-06-07

### Bug Fixes

- *(proxy)* Deny-by-default when network.block is set (#1082) ([#1082](https://github.com/always-further/nono/pull/1082))


### Dependencies

- *(deps)* Bump actions/checkout from 6.0.2 to 6.0.3

- *(deps)* Bump docker/setup-qemu-action from 4.0.0 to 4.1.0

- *(deps)* Bump jsonschema from 0.46.4 to 0.46.5

- *(deps)* Bump rustls-native-certs from 0.8.3 to 0.8.4


### Features

- *(packaging)* Add automated AUR package publishing (#917) (#1083) ([#1083](https://github.com/always-further/nono/pull/1083))


### Miscellaneous

- Release v0.61.2

## [0.61.2] - 2026-06-05

### Bug Fixes

- *(proxy)* Deny-by-default when network.block is set (#1082) ([#1082](https://github.com/always-further/nono/pull/1082))


### Dependencies

- *(deps)* Bump actions/checkout from 6.0.2 to 6.0.3

- *(deps)* Bump docker/setup-qemu-action from 4.0.0 to 4.1.0

- *(deps)* Bump jsonschema from 0.46.4 to 0.46.5

- *(deps)* Bump rustls-native-certs from 0.8.3 to 0.8.4

## [0.61.1] - 2026-06-02

### Features

- *(profile)* Allow registry refs in profile extends (#1061) ([#1061](https://github.com/always-further/nono/pull/1061))

## [0.61.0] - 2026-06-02

### Features

- *(diagnostic)* Add profile option to suppress system service diagnostics (#1059) ([#1059](https://github.com/always-further/nono/pull/1059))


### Refactoring

- *(network-policy)* Do not enable credentials by default in profiles

## [0.60.0] - 2026-06-01

### Bug Fixes

- *(cli)* Accept cap file under any known temp root for why --self

- Ci

- *(proxy)* Clean up Keychain on trust failure and expand security docs

- *(proxy)* Disambiguate AsRef call on Cow<[u8]> for typed_path compat

- *(proxy)* Detect user-cancelled trust prompts via OSStatus codes

- *(cli)* Limit visible items in denial selector


### Build

- Add rpm release artifacts


### Documentation

- *(cli)* Update credential injection with bitwarden and custom keyring


### Features

- Remove libdbus dependency on linux

- *(proxy)* Align leaf cert expiry with CA and add --proxy-ca-validity flag

- *(proxy)* Add --trust-proxy-ca for macOS system trust store integration

- *(cli)* Introduce interactive denied path selector

- *(wiring)* Support jsonc in wiring directives


### Miscellaneous

- Remove PR description file

### Refactoring

- *(proxy)* Consolidate Keychain CA storage to single combined PEM entry

- *(denial-selector)* Extract visible range logic

- *(jsonc)* Centralize jsonc parsing


### Style

- *(formatting)* Make expressions more compact

## [0.59.0] - 2026-05-27

### Bug Fixes

- *(proxy)* Enforce endpoint rules before credential selection in TLS intercept

- Formatting

- Tighten up overflow checks

- Use rfind for access mode spliting; add test

- Annotate suppressed denials and style save prompt paths (#984)

- Restore jsonc-parser dep

- Use fully qualified pack name in Quick Start example

- Correct Quick Start profile reference in README


### Dependencies

- *(deps)* Bump shlex from 1.3.0 to 2.0.1


### Documentation

- Note [save skipped] annotation in suppress_save_prompt sections


### Features

- *(cli)* Allow-domain accepts URL with path for endpoint restrictions

- *(cli)* Support fine-grained method+path restrictions in allow_domain (#960)

- *(cli)* Centralize timeout constants and make user-facing timeouts configurable


### Refactoring

- *(profile)* Extract opencode profile from built-ins


### Diagnostic

- Pre-compute canonical denial paths to avoid repeated fs I/O

## [0.58.0] - 2026-05-26

### Bug Fixes

- Set accepted listener connections to blocking mode

- Include URL listener in supervisor loop keep-alive conditions

- Keep supervisor loop alive when child closes direct IPC socket

- Increase supervisor listener read timeout to 5s for URL open

- Address review comments on supervisor socket IPC

- Add read timeout on accepted listener connections

- Grant UnixSocketCapability for supervisor socket in child sandbox

- Replace fd-based IPC with named socket for URL open helpers (#959)

- *(proxy)* Preserve upstream error and sanitise 502 reason line

- *(proxy)* Return 502 with audit entry on upstream connect failure

- *(pack-update-hint)* Make state file writes atomic

- *(policy)* Address review comments on java_runtime group

- *(keystore)* Use Zeroizing<String> for Bitwarden item fields and in-place truncation

- Review fixes

- *(macos)* Emit platform rules after user write allows

- Add user docs for *.json/*.jsonc

- *(sandbox)* Use \$PWD to capture symlink CWD without --workdir

- *(sandbox)* Preserve symlink path when adding CWD capability on macOS


### CI/CD

- *(release)* Reorder artifact attestation job

- *(attestation)* Add release artifact attestation

- *(pr-summary)* Apply automatic pr and size labels

- *(pr-summary)* Add pull request summary workflow


### Dependencies

- *(deps)* Bump rcgen from 0.13.2 to 0.14.8

- *(deps)* Bump docker/build-push-action from 7.1.0 to 7.2.0

- *(deps)* Bump actions/attest-build-provenance

- *(deps)* Bump docker/login-action from 4.1.0 to 4.2.0

- *(deps)* Bump docker/setup-buildx-action from 4.0.0 to 4.1.0

- *(deps)* Bump similar from 3.1.0 to 3.1.1

- *(deps)* Bump serde_json from 1.0.149 to 1.0.150

- *(deps)* Bump landlock from 0.4.4 to 0.4.5

- *(deps)* Update sigstore crates to 0.8.0


### Documentation

- Add session_hooks to profiles-groups page

- Update profile authoring with binary path

- *(readme)* Remove terminal demo gif

- *(readme)* Refine project description and quick start


### Features

- Session lifecycle hooks (#954)

- *(policy)* Add java_runtime group and java-dev profile

- Add Bitwarden credential source (bw:// URI scheme)

- *(profile)* Allow profiles to specify a target binary

- *(profile)* Add JSONC support for profile files


### Refactoring

- *(pack-hints)* Refresh in detached process to avoid threads

- *(hook_runtime)* Gate module unix-only, drop dead non-unix branches

- Use chained if let for conditional statements


### Testing

- Lock ENV_LOCK in test_all_groups_no_deny_within_allow_overlap


### Style

- Format debug message for line length

## [0.57.0] - 2026-05-19

### Bug Fixes

- *(profile)* Fix fmt and test assertion after shadow-check refactor

- *(profile)* Handle versioned package refs in fast path

- *(profiles)* Block profile init when name shadows builtin or pack profile

- *(profiles)* Address review points on shadow-check PR


### Dependencies

- *(deps)* Bump aws-lc-rs from 1.16.3 to 1.17.0


### Features

- *(profile)* Refine profile name resolution and init validation

- *(profiles)* Expand shadowing checks to include pack profiles

## [0.56.0] - 2026-05-18

### Bug Fixes

- *(startup)* Use SIGKILL consistently and remove dead prompt infrastructure


### CI/CD

- Add standalone homebrew-bump workflow; pin to AvesAlight fork for 3xx redirect fix


### Documentation

- *(cli)* Clarify startup timeout definition of interactive


### Features

- *(cli)* Expand startup timeout interactive detection

- *(cli)* Add option to configure process startup timeout


### Refactoring

- *(cli)* Simplify startup timeout check

- *(cli-exec-strategy)* Simplify startup timeout checks

- *(cli)* Require alt-screen for startup timeout

## [0.55.0] - 2026-05-17


### Security
- Sandbox escape on Linux via D-Bus ([GHSA-27vp-2mmc-vmh3](https://github.com/always-further/nono/security/advisories/GHSA-27vp-2mmc-vmh3)) - reported by @cgwalters

GHSA-27vp-2mmc-vmh3

### Bug Fixes

- *(cli)* Unify macOS exact-path grant restore

- *(cli)* Preserve macOS future-file grants in why --self

- *(pty)* Forward bare ESC immediately in filter_client_input

- *(docker)* Pin Alpine version and add --platform to musl Dockerfiles

- *(musl)* Use as _ for TIOCSCTTY ioctl cast to support all platforms

- *(musl)* Fix libc::Ioctl type mismatches for x86_64-unknown-linux-musl target

- Code review

- *(proxy)* Honor explicit credential_format on custom inject headers

- *(profile-verification)* Strengthen profile and pack verification checks

- *(sandbox)* Correctly resolve af_unix socket paths for seccomp

- Preserve child output without trailing newline (#881)


### Dependencies

- *(deps)* Bump clap_complete from 4.6.3 to 4.6.5


### Documentation

- *(cli-security-model)* Correct typo in nono description

- *(cli)* Correct grammar in security model doc

- *(cli-security)* Add isolation scope and deployment model

- *(installation)* Add makepkg instructions and Note disclaimer

- *(installation)* Add Arch Linux (AUR) section

- *(capability)* Clarify linux signal mode behavior with landlock


### Features

- *(macos)* Treat open_port 0 as localhost:* outbound

- *(package)* Prevent artifact install path conflicts

- *(profile)* Ensure source pack is included for verification

- *(profiles)* Verify pack signer identities

- *(linux)* Implement af_unix pathname mediation

- *(sandbox)* Add explicit allowlist for pathname af_unix sockets

- *(unix-socket)* Record explicit scope for grants

- *(cli)* Add recursive unix socket directory grants

- *(landlock)* Add landlock v6 signal and abstract unix socket scoping


### Miscellaneous

- Drop changelog update for issue 943


### Refactoring

- *(package)* Base installs on package manifest

- *(supervisor)* Refine ipc denial reporting and audit timestamps


### Testing

- *(integration-tests)* Use CARGO_TARGET_DIR in runner

- *(supervisor-linux)* Add unix listener for connect capability test


### Cli

- Quiet Landlock deny-overlap diagnostics on Linux

## Unreleased

### Bug Fixes

- *(pty)* Forward bare ESC immediately instead of buffering for CSI-u detach match, fixing ESC key in TUI apps inside tmux with `extended-keys-format csi-u` (#941)

### Notes

- Socket grant state now records explicit socket scope. New subtree socket
  grants require this metadata; rolling back to older nono builds may read
  those state entries as file-scoped grants.

## [0.54.0] - 2026-05-13

### Bug Fixes

- *(pack-update-hint)* Treat unparsable installed as older in update check

- Macos lint

- Macos lint

- Macos lint

- *(snapshot)* Validate restore targets against symlinks

- *(platform)* Correctly parse windows registry dword values


### Dependencies

- *(deps)* Bump nix from 0.31.2 to 0.31.3

- *(deps)* Bump sigstore/cosign-installer from 4.1.1 to 4.1.2

- *(deps)* Bump tokio from 1.52.2 to 1.52.3


### Features

- *(pack-hints)* Document inline pack update hints

- *(pack_update_hint)* Refresh hints synchronously on first run

- *(packs)* Add pinning, outdated, and clarify publishing versioning

- *(cli)* Implement `nono update` command

- *(package)* Add package pinning and outdated commands

- Upgrade to Rust edition 2024, centralize workspace dependencies

- *(platform)* Implement robust windows platform detection

- *(profile)* Add platform-conditional profile fields


### Style

- *(cli)* Adjust line breaks and module order

- *(cli)* Improve formatting and simplify error handling

## [0.53.0] - 2026-05-11

### Bug Fixes

- Absolute match / 2 matches = deny / no match = passthrough w no creds

- Review comments

- Return full failure diagnostic

- *(sandbox)* Cache Landlock ABI detection with OnceLock


### Features

- Fix upstream TLS trust, intercept auth, and multi-route dispatch.

- *(core)* Scrub command arguments for secrets


### Refactoring

- *(scrub)* Optimize and simplify scrubbing logic

## [0.52.2] - 2026-05-11

### Bug Fixes

- *(profile-save)* Address suppression review feedback


### Features

- *(profile-save)* Suppress save-profile prompts for denied paths


### Miscellaneous

- Release v0.52.1

## [0.52.1] - 2026-05-11

### Bug Fixes

- *(profile-save)* Address suppression review feedback


### Features

- *(profile-save)* Suppress save-profile prompts for denied paths

## [0.52.1] - 2026-05-11

### Bug Fixes

- Match backend validation logic

- *(schema)* Add missing 'environment' property to profile JSON schema

- *(proxy)* Set NODE_USE_ENV_PROXY for Node 26

- *(policy)* Expand browser deny groups with missing Chromium-based browsers

- Preserve two keyboard-mode resets

- Documented concat! blocks instead of opaque byte blobs

- *(pty)* Stop clearing terminal scrollback on exit for normal-mode sessions

- Provide more accurate warning message + doc comment update

- *(cli)* Validate --allow paths and persist domain allowlist in sandbox state

- *(cli)* Make 'nono why --host' aware of proxy domain filtering

- Prevent feature unification from linking libdbus in no-keyring builds


### Documentation

- *(agents)* Relax agent disclosure and expand campaign ban

## [0.52.0] - 2026-05-10

### Bug Fixes

- *(diagnostic)* Parse escaped quotes in structured properties

- *(env)* Preserve fail-closed semantics for empty allow_vars

- *(lint)* Replace unwrap() with is_some_and() in test


### Documentation

- *(environment)* Document empty allow_vars array behavior

- Restructure navigation and fix stale terminology


### Features

- *(cli)* Deprecate 'nono learn' and improve diagnostics

- *(cli)* Enhance interactive experience and profile saving

- *(cli)* Enhance macos learn and run diagnostics

- *(env)* Add operator-controlled deny_vars to EnvironmentConfig


### Refactoring

- *(env)* Extract matches_env_var_patterns helper, fix docs wording


### Style

- Run cargo fmt

## [0.51.0] - 2026-05-09

### Bug Fixes

- *(tls_intercept)* Add authority key identifier to leaf certs


### Features

- *(proxy)* Extend ca trust to git clients

- *(proxy)* Enhance audit context for managed auth and harden tls ca dir

- *(audit)* Add structured context to network audit events

- *(proxy)* Add tls interception for l7-bearing connect routes

## [0.50.1] - 2026-05-08

### Bug Fixes

- Use native types for iotcl integers

## [0.50.0] - 2026-05-08

### Features

- *(profile)* Support env:// URI in custom_credentials credential_key


### Refactoring

- *(cli)* Optimize ps command column width calculation

- *(cli/ps)* Improve ps command display with dynamic columns

## [0.49.0] - 2026-05-07

### Bug Fixes

- *(trust)* Treat empty parent() as CWD when deriving scan_root

- *(trust)* Reject symlink-escape in multi-subject bundle subject names

- *(trust)* Reject path traversal in multi-subject bundle subject names

- *(yaml-merge)* Pin serde_yaml_ng to 0.10.0 and add reversal failure test


### Dependencies

- *(deps)* Bump tokio from 1.52.1 to 1.52.2


### Features

- *(wiring)* Add yaml_merge directive for YAML config patching


### Miscellaneous

- Add PR template requiring linked issue


### Style

- Apply rustfmt to trust_cmd and trust_scan

- Apply rustfmt

## [0.48.0] - 2026-05-07

### Bug Fixes

- *(cli)* Prevent truncate_chars panic and spurious truncation

- Demote --allow-launch-services log from warn to debug

- *(profile)* Skip self-references in sibling extends resolution


### Features

- *(cli)* Add shell completion generation via `nono completion <shell>`


### Miscellaneous

- Harden CI workflows and fix stale metadata

- Reduce nono run output verbosity


### Refactoring

- *(string-truncation)* Extract generic string truncation utility

## [0.47.1] - 2026-05-06

### Dependencies

- *(deps)* Bump jsonschema from 0.45.1 to 0.46.4

- *(deps)* Bump rustls from 0.23.39 to 0.23.40


### Documentation

- Fix stale references, deprecation wording, and built-in vs pack distinction

## [0.47.0] - 2026-05-05

### Bug Fixes

- Doc changes + relax strict cap check

- Resolve extends against sibling profiles in the same directory

- *(capability)* Platform-specific dedup key (original on macOS, resolved on Linux)

- *(ci)* Poll crates.io index instead of fixed sleep before publish

- *(profile)* Emit serde-rendered values in show/diff JSON output

- Migrate diagnostic.rs to shared try_canonicalize helper

- Canonicalize protected roots at call sites to handle raw paths

- Replace unwrap() with expect() in path tests for clippy

- Unify path canonicalization with ancestor-walk fallback


### Documentation

- *(plans)* Design and implementation plan for #594 phase 2 schema restructure


### Features

- *(profile)* #594 phase 2 - canonical JSON schema restructure (#594)


### Performance

- Eliminate redundant canonicalize syscalls per review feedback


### Policy

- Normalize nix profile paths to tilde-style and add defexpr


### Style

- Remove extra blank line in diagnostic.rs

- Run cargo fmt

## [0.46.0] - 2026-05-01

### Bug Fixes

- *(policy)* Add XDG_STATE_HOME nix profiles path to nix_runtime group

- *(policy)* Make nix_runtime group cross-platform

- *(cli)* Re-validate deny overlaps after all grants

- Update examples in setup.rs


### Features

- *(network)* Support GitLab developer domains


### Testing

- *(cli-tests)* Add workdir access to deny overlap test

- Exclude system_write_linux in post-CWD overlap regression test

## [0.45.0] - 2026-04-30

### Features

- *(packages)* Use native tls root certificates
- *(ux)* Warn on macOS when `--allow` targets a path blocked by a deny group (e.g. `deny_credentials`), suggesting `--override-deny`

## [0.44.0] - 2026-04-29

### Bug Fixes

- *(package)* Harden re-pulls against user edits

- *(wiring)* Harden install and uninstall wiring


### Features

- *(claude)* Detect and remove pre-0.43 inbuilt hook leftovers (`~/.claude/hooks/nono-hook.sh` and matching `settings.json::hooks` entry) on first
   claude pack install/resolve, with a confirmation prompt and a per-item summary
- *(profile, migration)* Move codex, claude-code to registry pack


### Miscellaneous

- *(ci)* Improve ci stability and profile test coverage


### Refactoring

- *(wiring)* Simplify string expansion

## [0.43.1] - 2026-04-29

### Bug Fixes

- *(cli)* Char-aware truncation in truncate_command

## [0.43.0] - 2026-04-28

### Bug Fixes

- *(cli)* Fail fast on --allow-connect-port on macOS

- Set system-keyring as default feature for backward compatibility


### Dependencies

- *(deps)* Bump aws-lc-rs from 1.16.2 to 1.16.3

- *(deps)* Bump hyper from 1.8.1 to 1.9.0


### Features

- *(cli)* Add --allow-connect-port for outbound TCP port allowlisting

- Make system keyring optional for headless/container builds


### Style

- Run cargo fmt

## [0.42.0] - 2026-04-25

### Bug Fixes

- *(proxy)* Stop adding allow_domain hosts to NO_PROXY without direct TCP grants


### Documentation

- Add --allow-unix-socket* flags and profile fields


### Features

- *(cli)* Add --allow-unix-socket flag family + profile schema

- *(capability)* Add UnixSocketCapability and UnixSocketMode

## [0.41.0] - 2026-04-24

### Bug Fixes

- *(cli)* Improve attach/detach scrollback and alt-screen

- *(pty-proxy)* Ensure full scrollback on reattach for normal screen

- *(cli)* Improve profile save resilience and policy suggestions

- *(signals)* Prevent signal swallowing


### Features

- *(pty-proxy)* Scroll viewport to native scrollback on detach

- *(pty)* Enhance detach notice and terminal cleanup

- *(pty)* Preserve outer terminal scrollback on attach

- *(cli)* Consolidate 'nono policy' subcommands under 'nono profile' with deprecation alias (#594)

- *(cli)* Enhance prompts and denial diagnostics

- *(cli)* Improve denial diagnostics and profile saving workflow


### Refactoring

- *(cli-startup-prompt)* Extract startup prompt functions

## [0.40.1] - 2026-04-23

### Bug Fixes

- *(policy)* Improve unlink rules; add claude read path


### Miscellaneous

- Add gitignore entries and hiring badge

## [0.40.0] - 2026-04-23

### Bug Fixes

- *(sandbox)* Downgrade unsafe seatbelt rules log from warn to info

- Add unsafe_macos_seatbelt_rules to test Profile initializers

- Address review feedback

- *(reverse-proxy)* Disallow insecure http upstreams for unspecified local addresses

- *(proxy)* Support local-only http upstreams safely

- *(proxy)* Restrict insecure http upstreams to local-only targets

- *(policy)* Update tests and claude-no-kc for allow_file move

- *(policy)* Move .claude.lock to allow_file for least-privilege access

- *(cli)* Skip non-existent profile deny overrides


### Build

- *(docker)* Harden user and create work dir


### Dependencies

- *(deps)* Update rustls-webpki

- *(deps)* Bump rustls-webpki from 0.103.12 to 0.103.13


### Documentation

- *(agents)* Update agent contribution policy and project overview

- Add documentation for agents and claude


### Features

- Add unsafe_macos_seatbelt_rules profile field

- *(reverse-proxy)* Add http upstream support

- *(audit)* Refine audit path derivation and documentation

- *(audit)* Add audit attestation for session merkle roots

- *(audit)* Record exec identity and unify audit integrity

- *(audit)* Record executable identity and improve integrity

- *(audit)* Add audit verify command for integrity checks

- *(audit)* Add tamper-evident audit log integrity

- *(rollback)* Refine snapshot exclusion and path tracking

- *(audit)* Capture pre/post merkle roots in audit trail


### Miscellaneous

- *(cli)* Make path and policy messages informational

- *(test-env)* Isolate integration tests from audit artifacts


### Refactoring

- *(docker)* Move dockerfiles and update build workflow

- *(policy)* Enforce stricter policy for overrides, rollback


### Testing

- Improve profile and edge case test accuracy

- *(profiles)* Add tests for missing codex profile


### Style

- Run cargo fmt

## [0.39.0] - 2026-04-21

### Bug Fixes

- *(dry)* Duplicated allow_domain warning-print logic

- *(tests)* Tests and format fixes

- *(network)* Keep --allow-domain in strict proxy-only mode

- *(policy)* Add entry for ~.local/share/claude/versions

- *(learn)* Validate profile name and re-prompt on invalid input

- *(oauth)* PR 517 rebase on main

- Compilation against current main after rebase

- *(proxy)* Return early after 413 in read_request_body


### Dependencies

- *(deps)* Bump clap from 4.6.0 to 4.6.1

- *(deps)* Bump tokio from 1.51.0 to 1.52.1

- *(deps)* Bump semver from 1.0.27 to 1.0.28

- *(deps)* Bump actions/cache from 5.0.4 to 5.0.5


### Features

- *(policy)* Filter profile override deny entries without grants

- *(claude)* Add no-keychain profile and expand existing access

- *(profile)* Support OAuth2 auth config in custom_credentials

- *(proxy)* Implement OAuth2 client_credentials token exchange with cache

- *(config)* Add OAuth2Config type for client_credentials flow

## [0.38.0] - 2026-04-20

### Bug Fixes

- *(trust)* Function or associated item not found in `TrustedRoot`

- *(package)* Harden package installation security

- *(hooks)* Invoke bash via env


### Documentation

- *(cli-package-publishing)* Add warning for unreleased feature

- *(cli)* Add installation instructions for nix


### Features

- *(trust)* Prefer CI_CONFIG_REF_URI for GitLab workflow identity

- *(claude-code)* Remove claude-code integration package

- *(profile)* Add support for loading profiles from registry packs

- *(profile)* Introduce packs and command_args for profiles

- *(pack)* Introduce pack types and unify package naming

- *(package)* Add install_dir artifact placement and hook unregistration

- *(cli)* Add package management commands (pull, remove, search, list)

- Implements environment variables filtering #688


### Miscellaneous

- Release v0.37.1


### Refactoring

- *(pkg)* Stream package artifact downloads

- *(package)* Simplify artifact signer validation

- *(package-cmd)* Centralize trust bundle for package verification

- *(cli)* Improve artifact path validation


### Style

- Cargo fmt

## [0.37.1] - 2026-04-17

### Bug Fixes

- *(macos)* Emit specific-op seatbelt rules for keychain DB allows

- *(sandbox)* Allow Unix domain socket connections in restricted network modes

- *(learn)* Print profile JSON as fallback when save fails


### Documentation

- Add github to credential route configuration


### Miscellaneous

- Upgrade rustls-webpki to 0.103.12 to fix RUSTSEC-2026-0098 and RUSTSEC-2026-0099

- Upgrade rustls-webpki to 0.103.12 to fix RUSTSEC-2026-0098 and RUSTSEC-2026-0099


### Style

- Apply rustfmt

## [0.37.0] - 2026-04-16

### Bug Fixes

- *(claude-code)* Enable token refresh via .claude.json symlink

- *(profiles)* Prevent infinite recursion in profile extends check

- *(sandbox)* Support claude-code profile extensions and simplify config


### Features

- *(claude-code)* Pre-create claude config lock directory


### Refactoring

- *(proxy-tls)* Remove rustls-pemfile and use pki_types for pem parsing

## [0.36.0] - 2026-04-15

### Bug Fixes

- *(proxy)* Downgrade CONNECT-to-route-upstream log from warn to debug


### Features

- Add ?decode=go-keyring query param for keyring:// URIs

- Add keyring:// URI scheme for custom-service credential lookup

## [0.35.0] - 2026-04-14

### Bug Fixes

- Chore: lint

- Chore: revert to json! obj syntax

- Chore: split predicate out again for provider specific claims

- Refactor: expose build config URI extension

- *(pty)* Improve session gone error detection when connecting

- *(cli)* Increase detached session startup timeout and order


### Features

- *(trust)* Support GitLab ID tokens for signing

- Strip proxy artifacts and fix upstream connection handling


### Miscellaneous

- Revert doc string

- Drop example workflow in comment

- Mention GitLab tokens in doc comment


### Refactoring

- Use append to merge signer fields

- Use build signer URI extension for trust

## [0.34.0] - 2026-04-13

### Bug Fixes

- *(gpu)* Grant NVIDIA procfs paths required for CUDA init under --allow-gpu

- *(gpu)* Add nvidia-uvm-tools to GPU device allowlist

- *(proxy)* Add missing proxy field in regression tests

- *(network-policy)* Activate anthropic credential in claude-code profile

- *(proxy)* Set ANTHROPIC_API_KEY phantom token for anthropic credential

- *(sandbox)* Use relative path for ~/.claude.json symlink

- *(sandbox)* Redirect ~/.claude.json to ~/.claude/ via symlink on all unix platforms


### Dependencies

- *(deps)* Bump rustls from 0.23.37 to 0.23.38

- *(deps)* Bump similar from 2.7.0 to 3.1.0

- *(deps)* Bump rand from 0.10.0 to 0.10.1

- *(deps)* Bump always-further/agent-sign from 0.0.8 to 0.0.11

- *(deps)* Bump peter-evans/repository-dispatch from 3.0.0 to 4.0.1

- *(deps)* Bump docker/build-push-action from 7.0.0 to 7.1.0

- *(deps)* Bump softprops/action-gh-release from 2.6.1 to 3.0.0

- *(deps)* Bump actions/upload-artifact from 7.0.0 to 7.0.1


### Features

- *(macos)* Auto-enable claude launch services, refine keychain access


### Refactoring

- *(policy)* Improve seatbelt path regex escaping


### Testing

- *(gpu)* Add unit + integration coverage for NVIDIA procfs grants

- *(gpu)* Extract is_nvidia_compute_device predicate and add unit tests

- *(proxy)* Add regression test for issue #624 phantom token bug


### Style

- Fix rustfmt formatting in sandbox_prepare.rs

## [0.33.0] - 2026-04-12

### Bug Fixes

- Address review feedback on downstream bump workflows

- *(fmt)* Sort imports alphabetically in command_runtime.rs

- *(shell)* Initialize proxy runtime when credentials are configured

- *(cli)* Decouple audit trail from rollback

- *(proxy)* Guard macOS keychain hint with platform check

- *(proxy)* Warn when keychain credential is not found

- *(landlock)* Widen /proc/self Landlock rule to /proc for grandchild access

- *(seccomp)* Resolve /proc/self correctly for grandchild processes

- *(cli)* Adjust ps command output column widths

- *(cli)* Align status and attach columns in ps output

- *(test)* Add --allow-cwd to GPU integration tests

- *(cli)* Compile dummy GPU function for non-macOS tests

- *(pty-proxy)* Exit early if client socket cannot be set nonblocking

- *(pty)* Correctly handle blocking state for attach streams

- *(sandbox)* Prevent interactive CWD prompt in detached mode

- Tighten GPU IOKit surface to AGXDeviceUserClient only

- *(test)* Handle non-default TMPDIR in linux nested home grant test

- *(policy)* Remove broad ~/.local allow from openclaw profile on Linux


### CI/CD

- Remove nono-registry from downstream dispatch

- Add release automation for downstream SDK repos


### Documentation

- *(readme)* Add early alpha warning and remove separator

- *(readme)* Overhaul content and visuals

- *(cli)* Clarify --allow-gpu flag behavior and profile interaction


### Features

- *(macos)* Make parent-of-protected-root relaxation opt-in via profile

- *(gpu)* Add WSL2 GPU support via /dev/dxg passthrough

- *(gpu)* Add WSL2 GPU support via /dev/dxg passthrough

- *(gpu)* Add Linux GPU access and improve macOS support

- *(profile)* Introduce separate profile preparation for preflight

- *(cli)* Introduce pre-flight CWD prompt for detached launches


### Miscellaneous

- Remove test results file


### Performance

- *(seccomp)* Skip read_tgid for direct child and use Cow for cap_check_path


### Refactoring

- *(cli-validation)* Propagate protected parent flag to cli validation

- *(command-blocking)* Improve deprecation warning messages

- *(command-blocking)* Deprecate startup-only command blocking


### Testing

- *(macos)* Address Gemini review feedback

- *(macos)* Align GPU IOKit tests with tightened surface from #635

- *(gpu)* Skip DRM tests if no render node permissions

## [Unreleased]

### Deprecations

- Deprecate startup-only command blocking surfaces in `v0.33.0`, add compatibility warnings, and document the child-process bypass.

## [0.32.0] - 2026-04-10

### Features

- Add upstream mTLS client certificate support

## [0.31.0] - 2026-04-10

### Bug Fixes

- Tighten GPU IOKit rules

- Remove allow_gpu from default profiles

- Address review feedback for --allow-gpu

- Add docs for --allow-gpu flag and improve test coverage

- *(macos)* Deny keychain Mach IPC services on modern macOS

- *(macos)* Allow atomic-write temp files for writable capabilities


### Features

- Add --allow-gpu flag for GPU access on Apple Silicon Macs

- *(trust)* Add file:// backend for trust signing keys

## [0.30.1] - 2026-04-09

### Bug Fixes

- *(cli)* Handle profile allow_file entries resolving to directories

- *(cli)* Handle profile allow_file entries resolving to directories

## [0.30.0] - 2026-04-08

### Bug Fixes

- *(macos)* Improve path resolution for non-existent files

- *(reverse-proxy)* Authenticate requests on non-credentialed routes

- *(test)* Guard EnvVarGuard::remove against unmanaged keys

- *(test)* Prevent TMPDIR pollution by not auto-deleting temp dirs used as TMPDIR

- *(test)* Add clippy disallowed_methods lint and migrate remaining unguarded env var tests

- *(test)* Unify env var locks to eliminate flaky test failures

- *(policy)* Avoid false deny for Nix store symlink targets on Linux

- Allow filesystem.read entries to be files

- *(proxy)* Address review feedback - normalize prefix in CredentialStore

- *(proxy)* Handle route prefixes with leading slashes


### Build

- *(deps)* Bump getrandom from 0.4.1 to 0.4.2

- *(deps)* Bump tokio from 1.49.0 to 1.51.0

- *(deps)* Bump sha2 from 0.10.9 to 0.11.0

- *(deps)* Bump docker/login-action from 4.0.0 to 4.1.0


### Documentation

- *(theme)* Update theme colors


### Features

- *(macos)* Expand keychain DB exception to include metadata DB

- *(macos)* Allow future file grants and update policies

- *(nix)* Improve NixOS compatibility for /nix/store paths

- *(wsl2)* ABI-aware tests and rolling kernel documentation

- *(trust)* Add `files` field for attesting arbitrary-location paths


### Miscellaneous

- *(scripts)* Add script to manage Claude authentication state


### Performance

- *(nono-proxy/route)* Cache upstream host:port for faster lookups


### Refactoring

- *(proxy)* Separate route configuration from credential configuration

- *(policy)* Consolidate resolved deny target skipping logic

## [0.29.1] - 2026-04-04

### Bug Fixes

- *(macos)* Allow DNS resolution via mDNSResponder in proxy and blocked modes (#588)

- *(profile)* Add missing $TMPDIR and state dir to opencode profile

- Ipv6 normalization logic

- *(proxy)* Disable NO_PROXY bypass on macOS (#580)

- *(policy)* Grant ~/.cache/claude readwrite in claude-code profile

## [0.29.0] - 2026-04-03

### Bug Fixes

- *(proxy)* Don't factor seatbelt for port lockdown

- *(pty_proxy)* Improve write retry test reliability with deadline-based polling

- *(pty_proxy)* Remove timeout from test recv to prevent race condition

- *(test)* Resolve race condition and cache key uniqueness


### Build

- *(deps)* Sort wait-timeout in Cargo.lock and fix credentials resolution


### Documentation

- *(cli)* Add `--detached` and `--name` flag documentation

- Document supervised session lifecycle and runtime workflows


### Features

- *(cli)* Add manifest support and improve sandbox preparation

- *(rollback)* Add configurable rollback destination support

- *(pty,session,supervisor)* Enhance PTY attach/detach and socket utilities

- *(pty_proxy)* Improve logging and error handling for attach/detach

- *(exec_strategy)* Replace startup timeout thread with interactive prompt

- *(diagnostic)* Add macOS sandbox violation logging and startup timeouts

- *(rollback)* Condition audit state creation on rollback request flags

- *(pty_proxy)* Disable keyboard enhancement modes on terminal restore

- *(pty_proxy)* Improve enhanced key detection and multi-key sequences

- *(pty_proxy)* Support enhanced CSI u key sequences in detach detection

- *(runtime)* Harden supervised child dumpability and fd passing

- *(runtime)* Land supervised sessions and diagnostics stack


### Refactoring

- *(output)* Consolidate leading break logic in print_terminal_block

## [0.28.0] - 2026-04-03

### Bug Fixes

- *(proxy)* Add tls_ca field to file:// credential test fixtures

- *(proxy)* Simplify tls_ca to tilde expansion and doc clarification

- *(proxy)* Expand and validate tls_ca paths at credential resolution


### Features

- *(policy)* Expand git config paths in credentials group

- *(credential,proxy)* Add missing tls_ca and tls_connector fields

- *(proxy)* Add custom CA certificate support for upstream TLS (closes #545)

- *(policy)* Skip system temp grants when HOME is nested under TMPDIR

- *(policy)* Split homebrew group into platform-specific variants


### Refactoring

- *(proxy)* Wrap CA file read in Zeroizing and improve error messages

- *(proxy)* Reuse policy::expand_path for tls_ca expansion

- *(capability_ext)* Extract locked test helpers for env isolation

- *(test)* Extract environment variable guard into reusable utility


### Testing

- *(cli)* Remove proptest regression file for manifest roundtrip

- *(profile,query)* Isolate environment variables and fix symlink test


### Style

- Fix rustfmt in tls_ca path expansion closure

## [0.27.0] - 2026-04-02

### Bug Fixes

- *(test)* Use real temp directories for env_nono_allow_comma_separated

- *(proxy)* Strip port suffix from allow_domain entries in proxy host filter

- Tighten manifest round-trip fidelity and wire proxy from --config

- *(test)* Use portable paths in manifest round-trip test

- Harden --config flag conflicts and error handling

- *(macos)* Align Seatbelt signal isolation with Linux Landlock behaviour

- Gate deny-overlap test to Linux only

- Harden deny-overlap validation, reject unknown profile fields, narrow user_tools scope


### Dependencies

- *(deps)* Bump tracing-subscriber from 0.3.22 to 0.3.23

- *(deps)* Bump ureq from 3.2.0 to 3.3.0


### Documentation

- Replace mention of --supervised with --capability-elevation in README

- Address review feedback on wsl2 cross-references

- Add WSL2 cross-references to feature docs and fix discoverability

- Move endpoint filtering from credential injection to networking page

- *(keystore)* Update module docs for file:// scheme and add redaction


### Features

- *(policy)* Check credentials Option with is_some_and instead of field access

- *(proxy)* Block CONNECT to credential upstreams and smart NO_PROXY

- *(sandbox)* Add allow_domain ports to Landlock ConnectTcp rules

- *(profile)* Allow child to override inherited credentials to empty

- *(schema)* Allow additionalProperties for forward-compatible evolution

- *(cli)* Add `nono policy show --format manifest` for profile-to-manifest compilation

- *(cli)* Wire up --config manifest path in prepare_sandbox

- *(cli)* Add conflicts_with to --config flag

- *(manifest)* Add typify codegen, manifest module, and CapabilitySet conversion

- *(schema)* Add capability manifest JSON Schema

- *(proxy)* Auto-detect credential format from inject_header

- *(keystore)* Preserve significant whitespace in secret files

- *(profile)* Accept file:// credential keys in custom_credentials

- *(keystore)* Wire file:// into credential dispatch and CLI mappings

- *(keystore)* Add load_from_file() for file:// credential source

- *(keystore)* Add file:// URI validation for local file credentials

- *(policy)* Split linux system groups for granular host compatibility

- Add $XDG_RUNTIME_DIR to variable expansion


### Refactoring

- Deduplicate path expansion and fs grant construction

- *(keystore)* Extract file-backed secret helpers


### Testing

- *(env_vars)* Use as_str() for contains() calls

- *(env_vars)* Replace to_str() with display().to_string()

- *(profile,trust_scan)* Add env lock guards to fix test isolation

- *(cli)* Add global env lock for parallel test isolation

- *(cli)* Add integration tests for --config manifest flag

- *(profile)* Add endpoint_rules field to credential test fixtures


### Revert

- Keep ~/.local/state in user_tools, defer to #546

## [0.26.1] - 2026-03-31

### Bug Fixes

- *(learn)* Make Enter actually skip profile save prompt (closes #431)

- *(proxy)* Use lossy UTF-8 decoding for percent-encoded paths

- *(proxy)* Percent-decode paths before endpoint rule matching


### CI/CD

- *(workflows)* Decouple image build from release workflow


### Dependencies

- *(deps)* Bump docker/setup-buildx-action from 3.12.0 to 4.0.0

- *(deps)* Bump toml from 1.0.6+spec-1.1.0 to 1.0.7+spec-1.1.0

- *(deps)* Bump docker/setup-qemu-action from 3.7.0 to 4.0.0

- *(deps)* Bump docker/build-push-action from 6.19.2 to 7.0.0

- *(deps)* Bump docker/login-action from 3.7.0 to 4.0.0

- *(deps)* Bump sigstore/cosign-installer from 3.10.1 to 4.1.1


### Miscellaneous

- Add DCO sign-off requirement to CLAUDE.md

## [0.26.0] - 2026-03-30

### Bug Fixes

- *(wsl2)* Security hardening from code review

- *(learn)* Resolve fs_usage pipe buffering and process name mismatch on macOS


### CI/CD

- *(workflows)* Extract push condition to environment variable

- *(workflows)* Extract Docker image build into reusable workflow

- *(release)* Fix workflow inputs reference syntax

- *(release)* Use inputs.tag fallback in Docker publish condition

- *(release)* Support manual tag input in workflow conditions


### Documentation

- *(wsl2)* Add WSL2 documentation and feature matrix (Track 1.5)


### Features

- *(wsl2)* Add WSL2 feature matrix to setup --check-only (Track 1.4)

- *(wsl2)* Clarify proxy network enforcement on WSL2 (Track 1.3)

- *(wsl2)* Guard seccomp notify paths for WSL2 (Track 1.2)

- *(wsl2)* Add WSL2 detection, feature matrix, and integration tests (Track 1.1)

- *(proxy)* Add L7 method+path endpoint filtering for reverse proxy routes (#465)

- *(ci)* Add Docker image build and push to release workflow (#511) ([#511](https://github.com/always-further/nono/pull/511))

- *(cli)* Add --log-file flag to redirect logs to a file (#490) ([#490](https://github.com/always-further/nono/pull/490))


### Miscellaneous

- Add .gitattributes to enforce LF line endings

## [0.25.0] - 2026-03-26

### Features

- *(undo)* Support per-root exclusion filters in snapshot manager (#506) ([#506](https://github.com/always-further/nono/pull/506))

- *(sandbox/linux)* Add seccomp proxy-only network fallback (#503) ([#503](https://github.com/always-further/nono/pull/503))

- *(trust)* Add skip_dirs support to trust scanning and rollback preflight (#498) ([#498](https://github.com/always-further/nono/pull/498))

## [0.24.0] - 2026-03-25

### Documentation

- Add documentation for add_deny_commands (#495) ([#495](https://github.com/always-further/nono/pull/495))

- Update GitHub Action badge to agent-sign (#494) ([#494](https://github.com/always-further/nono/pull/494))


### Features

- *(sandbox/linux)* Add seccomp fallback for network  (#496) ([#496](https://github.com/always-further/nono/pull/496))

## [0.23.1] - 2026-03-25

### Bug Fixes

- Block Unix socket connections via add_deny_access; add add_deny_commands (#488) ([#488](https://github.com/always-further/nono/pull/488))

- Handle relative paths in --rollback-dest pre-check (#486) ([#486](https://github.com/always-further/nono/pull/486))

## [0.23.0] - 2026-03-24

### Dependencies

- *(deps)* Bump toml from 1.0.3+spec-1.1.0 to 1.0.6+spec-1.1.0 (#479) ([#479](https://github.com/always-further/nono/pull/479))

- *(deps)* Bump which from 8.0.0 to 8.0.2 (#478) ([#478](https://github.com/always-further/nono/pull/478))

- *(deps)* Bump aws-lc-rs from 1.16.1 to 1.16.2 (#477) ([#477](https://github.com/always-further/nono/pull/477))

- *(deps)* Bump mislav/bump-homebrew-formula-action from 3.6 to 4.1 (#476) ([#476](https://github.com/always-further/nono/pull/476))

- *(deps)* Bump actions/cache from 5.0.3 to 5.0.4 (#474) ([#474](https://github.com/always-further/nono/pull/474))

- *(deps)* Bump always-further/agent-sign from 0.0.4 to 0.0.8 (#475) ([#475](https://github.com/always-further/nono/pull/475))


### Documentation

- Remove compiled PDF, keep Typst source


### Features

- *(query)* Add diagnostic details to path query results (#472) ([#472](https://github.com/always-further/nono/pull/472))

- *(cli)* Add --rollback-dest flag to override snapshot storage path

## [0.22.1] - 2026-03-23

### Build

- *(audit)* Add cargo-audit ignores for AWS-LC X.509 advisories (#449) ([#449](https://github.com/always-further/nono/pull/449))


### CI/CD

- Add change classification to skip unnecessary jobs (#456) ([#456](https://github.com/always-further/nono/pull/456))


### Documentation

- Detect system architecture in deb installation command (#455) ([#455](https://github.com/always-further/nono/pull/455))

- Fix arrow direction in OS-level enforcement diagram (#453) ([#453](https://github.com/always-further/nono/pull/453))

- *(clients)* Recommend disabling agent sandboxes when running under nono (#451) ([#451](https://github.com/always-further/nono/pull/451))

## [0.22.0] - 2026-03-21

### Dependencies

- *(deps)* Bump rustls-webpki from 0.103.9 to 0.103.10 (#443) ([#443](https://github.com/always-further/nono/pull/443))


### Features

- *(trust)* Lazy verification of scan policies (#448) ([#448](https://github.com/always-further/nono/pull/448))

## [0.21.0] - 2026-03-21

### Bug Fixes

- *(setup)* Detect Landlock via syscall probe instead of LSM file (#417) ([#417](https://github.com/always-further/nono/pull/417))

- *(cli)* Add ~/.opencode to opencode profile paths (#421) ([#421](https://github.com/always-further/nono/pull/421))


### Features

- *(policy)* Add standard I/O and fd paths to base_posix group (#441) ([#441](https://github.com/always-further/nono/pull/441))

- *(trust)* Add --user flag to sign-policy for user-level trust policy (#440) ([#440](https://github.com/always-further/nono/pull/440))

- *(trust)* Scaffold policies, enforce missing includes at startup, and simplify write protection (#435) ([#435](https://github.com/always-further/nono/pull/435))


### Doc

- Fix installation command for nono-cli package (#426) ([#426](https://github.com/always-further/nono/pull/426))

## [0.20.0] - 2026-03-18

### Features

- Support multiple base profiles in extends field (#399) ([#399](https://github.com/always-further/nono/pull/399))

- *(cli)* Standardize network flag naming and add listen_port support (#415) ([#415](https://github.com/always-further/nono/pull/415))

## [0.19.0] - 2026-03-18

### Bug Fixes

- *(deny)* Canonicalize parent directories in deny access rules (#393) ([#393](https://github.com/always-further/nono/pull/393))


### Dependencies

- *(deps)* Bump tempfile from 3.26.0 to 3.27.0 (#398) ([#398](https://github.com/always-further/nono/pull/398))

- *(deps)* Bump sigstore-sign from 0.6.3 to 0.6.4 (#397) ([#397](https://github.com/always-further/nono/pull/397))

- *(deps)* Bump clap from 4.5.60 to 4.6.0 (#396) ([#396](https://github.com/always-further/nono/pull/396))

- *(deps)* Bump actions/download-artifact from 8.0.0 to 8.0.1 (#395) ([#395](https://github.com/always-further/nono/pull/395))

- *(deps)* Bump softprops/action-gh-release from 2.5.0 to 2.6.1 (#394) ([#394](https://github.com/always-further/nono/pull/394))


### Features

- *(sandbox)* Add IpcMode capability for POSIX semaphores (macOS Seatbelt) (#412) ([#412](https://github.com/always-further/nono/pull/412))

- *(learn)* Add macOS network tracing via nettop (#403) ([#403](https://github.com/always-further/nono/pull/403))

- Add linux-arm64 (#402) ([#402](https://github.com/always-further/nono/pull/402))

## [0.18.0] - 2026-03-16

### Bug Fixes

- *(hooks)* Use resolved path in capability display (#387) ([#387](https://github.com/always-further/nono/pull/387))

- *(main)* Move cwd resolution before pre-fork sandbox setup (#370) ([#370](https://github.com/always-further/nono/pull/370))

- *(policy)* Honor excluded dangerous command groups for direct exec (#368) ([#368](https://github.com/always-further/nono/pull/368))

- *(config)* Remove hardcoded dangerous commands list (#366) ([#366](https://github.com/always-further/nono/pull/366))

- *(exec)* Prevent implicit cwd access under restrictive profiles (#363) ([#363](https://github.com/always-further/nono/pull/363))


### Documentation

- *(profiles)* Simplify group-based profile creation guide (#390) ([#390](https://github.com/always-further/nono/pull/390))

- *(profiles-groups)* Expand built-in profiles and add policy override examples (#376) ([#376](https://github.com/always-further/nono/pull/376))


### Features

- Restyle --help output with grouped sections and bold headings (#345) ([#345](https://github.com/always-further/nono/pull/345))

- *(trust)* Skip well-known heavy directories in instruction file walk (#388) ([#388](https://github.com/always-further/nono/pull/388))

- *(cli)* Add `nono profile` scaffolding and authoring tooling (#385) ([#385](https://github.com/always-further/nono/pull/385))

- *(policy)* Extract git config paths into reusable group (#383) ([#383](https://github.com/always-further/nono/pull/383))

- *(cli)* Add `nono policy` introspection subcommand (#382) ([#382](https://github.com/always-further/nono/pull/382))

- *(profile)* Add profile-level override_deny for deny group exceptions (#380) ([#380](https://github.com/always-further/nono/pull/380))

- *(macos)* Gate open shim installation behind launch services flag (#374) ([#374](https://github.com/always-further/nono/pull/374))

- *(capability)* Remove exact file caps when deny patch overrides grant (#367) ([#367](https://github.com/always-further/nono/pull/367))

- *(policy)* Deprecate security.trust_groups in favor of policy.exclude_groups (#357) ([#357](https://github.com/always-further/nono/pull/357))

- *(policy)* Use default profile groups for runtime policy resolution (#356) ([#356](https://github.com/always-further/nono/pull/356))

- *(policy)* Add extends field to embedded profiles (#355) ([#355](https://github.com/always-further/nono/pull/355))

- Add default profile with base group configuration (#352) ([#352](https://github.com/always-further/nono/pull/352))

- *(profile)* Add composable policy patch configuration (#351) ([#351](https://github.com/always-further/nono/pull/351))


### Refactoring

- *(setup)* Move banner printing to main.rs (#386) ([#386](https://github.com/always-further/nono/pull/386))

- *(supervisor)* Remove never_grant in favor of protected roots (#360) ([#360](https://github.com/always-further/nono/pull/360))

- *(policy)* Remove deprecated base_groups and trust_groups fields (#359) ([#359](https://github.com/always-further/nono/pull/359))

- *(policy)* Deprecate base_groups in favor of default profile (#358) ([#358](https://github.com/always-further/nono/pull/358))

## [0.17.1] - 2026-03-13

### Bug Fixes

- Narrow broad linux /etc and /proc reads in system_read policy (#350) ([#350](https://github.com/always-further/nono/pull/350))


### Features

- *(sandbox/linux)* Add Landlock V6 signal scoping support (#344) ([#344](https://github.com/always-further/nono/pull/344))


### Miscellaneous

- Release v0.17.0

- Release v0.17.0

## [0.17.0] - 2026-03-13

### Bug Fixes

- Narrow broad linux /etc and /proc reads in system_read policy (#350) ([#350](https://github.com/always-further/nono/pull/350))


### Features

- *(sandbox/linux)* Add Landlock V6 signal scoping support (#344) ([#344](https://github.com/always-further/nono/pull/344))


### Miscellaneous

- Release v0.17.0

## [0.17.0] - 2026-03-12

### Bug Fixes

- Add OAuth2 URL opening support via supervisor IPC (#340) ([#340](https://github.com/always-further/nono/pull/340))

- Check access mode when determining if CWD is already covered (#334) ([#334](https://github.com/always-further/nono/pull/334))


### Documentation

- Updating docs to reflect pnpm support. (#332) ([#332](https://github.com/always-further/nono/pull/332))

- Update Homebrew install references (#326) ([#326](https://github.com/always-further/nono/pull/326))


### Features

- *(cli)* Add pluggable theme system with 6 built-in palettes (#341) ([#341](https://github.com/always-further/nono/pull/341))


### Refactoring

- *(cli)* Standardize flags to verb-noun ordering (#302) ([#302](https://github.com/always-further/nono/pull/302))

## [0.16.0] - 2026-03-10

### Bug Fixes

- Add pnpm paths to policy.json (#320) ([#320](https://github.com/always-further/nono/pull/320))

- Add uv paths to python_runtime group (#313) ([#313](https://github.com/always-further/nono/pull/313))

- Allow tty ioctls on Linux v5+ (#310) ([#310](https://github.com/always-further/nono/pull/310))


### Documentation

- Fix broken links and stale examples (#283) ([#283](https://github.com/always-further/nono/pull/283))


### Features

- Inject nono sandbox instructions via Claude Code system prompt (#322) ([#322](https://github.com/always-further/nono/pull/322))

- Add `--external-proxy-bypass` for routing domains direct (#309) ([#309](https://github.com/always-further/nono/pull/309))

- Abi-aware Landlock capability system (#256, #306) (#311) ([#311](https://github.com/always-further/nono/pull/311))

- Add built-in swival profile (#312) ([#312](https://github.com/always-further/nono/pull/312))

- Add same-sandbox process mode for signal and process-info (#299) ([#299](https://github.com/always-further/nono/pull/299))


### Miscellaneous

- Migrate Homebrew distribution from tap to homebrew-core (#321) ([#321](https://github.com/always-further/nono/pull/321))

- Simplify instruction file signing with nono-attest Action (#317) ([#317](https://github.com/always-further/nono/pull/317))

## [0.15.0] - 2026-03-09

### Bug Fixes

- Allow opentui data dir in opencode profile (#296) ([#296](https://github.com/always-further/nono/pull/296))

- `nono run` default to direct exec when supervision is not needed (#295) ([#295](https://github.com/always-further/nono/pull/295))

- Add tilde expansion to profile paths and opencode binary access (#294) ([#294](https://github.com/always-further/nono/pull/294))

- Honor silent tracing output (#290) ([#290](https://github.com/always-further/nono/pull/290))

- Preserve supervised Linux open semantics (#289) ([#289](https://github.com/always-further/nono/pull/289))


### Dependencies

- *(deps)* Bump sigstore-verify from 0.6.3 to 0.6.4 (#305) ([#305](https://github.com/always-further/nono/pull/305))

- *(deps)* Bump libc from 0.2.182 to 0.2.183 (#304) ([#304](https://github.com/always-further/nono/pull/304))

- *(deps)* Bump tempfile from 3.25.0 to 3.26.0 (#303) ([#303](https://github.com/always-further/nono/pull/303))


### Documentation

- Document that gemini baseurl is ignored in opencode (#307) ([#307](https://github.com/always-further/nono/pull/307))


### Features

- Add Apple Passwords URI credential support (#229) ([#229](https://github.com/always-further/nono/pull/229))

- Add built-in Codex profile (#300) ([#300](https://github.com/always-further/nono/pull/300))

- Add Debian package support (#298) ([#298](https://github.com/always-further/nono/pull/298))

- Add capability_elevation profile field and OS-aware groups (#293) ([#293](https://github.com/always-further/nono/pull/293))

- Make claude-code profile platform-aware (#291) ([#291](https://github.com/always-further/nono/pull/291))

## [0.14.0] - 2026-03-08

### Bug Fixes

- Resolve symlinked paths in deny rule checks (#272) (#279) ([#279](https://github.com/always-further/nono/pull/279))


### Features

- Add environment variable equivalents for CLI flags (#270) (#278) ([#278](https://github.com/always-further/nono/pull/278))

## [0.12.0] - 2026-03-07

### Bug Fixes

- Resolve dirfd-relative paths in seccomp-notify handler (#262) (#277) ([#277](https://github.com/always-further/nono/pull/277))

- Show platform-correct path in user-level policy warning (#263) ([#263](https://github.com/always-further/nono/pull/263))

- Enforce macOS signal isolation via Seatbelt (#264) ([#264](https://github.com/always-further/nono/pull/264))

- *(profile)* Allow clearing inherited network profiles (#252) ([#252](https://github.com/always-further/nono/pull/252))


### Documentation

- *(readme)* Update latest release note (#253) ([#253](https://github.com/always-further/nono/pull/253))


### Features

- Add port_allow to profile JSON NetworkConfig (#254) (#276) ([#276](https://github.com/always-further/nono/pull/276))

- Context-aware diagnostic banner for sandbox failures (#275) ([#275](https://github.com/always-further/nono/pull/275))

- *(cli)* Add --net-allow override (#251) ([#251](https://github.com/always-further/nono/pull/251))

- Add macOS learn mode using fs_usage and profile save prompt (#244) ([#244](https://github.com/always-further/nono/pull/244))


### Miscellaneous

- Implement Cargo audit and update AWS-LC (#273) ([#273](https://github.com/always-further/nono/pull/273))

- Remove Monitor strategy, make Supervised the default (#267) ([#267](https://github.com/always-further/nono/pull/267))

## [0.11.0] - 2026-03-05

### Features

- Add --allow-port for bidirectional localhost IPC between sandboxes (#248) ([#248](https://github.com/always-further/nono/pull/248))

- Unify proxy network audit with session audit trail (#231) ([#231](https://github.com/always-further/nono/pull/231))


### Miscellaneous

- Add GitHub issue templates for bugs, features, and onboarding (#247) ([#247](https://github.com/always-further/nono/pull/247))

- Add GitHub issue templates for bugs, features, and onboarding

## [0.10.0] - 2026-03-04

### Bug Fixes

- Don't inject phantom token for unavailable credentials (#234) (#236) ([#236](https://github.com/always-further/nono/pull/236))

- Allow CLI flags to upgrade access mode of profile-covered paths (#232) ([#232](https://github.com/always-further/nono/pull/232))

- Landlock network false-negative and runtime ABI probe in setup (#230) ([#230](https://github.com/always-further/nono/pull/230))

- Proxy host filtering and credential resolution for sandboxed (#215) ([#215](https://github.com/always-further/nono/pull/215))

- Include character device files in policy group resolution (#218) ([#218](https://github.com/always-further/nono/pull/218))

- Pre-create claude-code config lock file on Linux (#221) ([#221](https://github.com/always-further/nono/pull/221))


### Features

- Add --override-deny CLI flag for targeted deny group exemptions (#242) ([#242](https://github.com/always-further/nono/pull/242))

- Add env:// credential scheme and GitHub token proxy support (#227) ([#227](https://github.com/always-further/nono/pull/227))

- Remove RFC1918 private network CIDR deny list from host filter (#226) ([#226](https://github.com/always-further/nono/pull/226))

- Add allowed_commands support to profile security config (#204) ([#204](https://github.com/always-further/nono/pull/204))

- Profile inheritance via `extends` field (#203) ([#203](https://github.com/always-further/nono/pull/203))

## [0.9.0] - 2026-03-03

### Bug Fixes

- Prevent --net-block bypass via proxy credential activation (#202) ([#202](https://github.com/always-further/nono/pull/202))


### Features

- Rollback preflight with auto-exclude and walk budget (#200) ([#200](https://github.com/always-further/nono/pull/200))

## [0.8.1] - 2026-03-03

### Miscellaneous

- Release v0.8.0

## [0.8.0] - 2026-03-02

### Bug Fixes

- Reject parent directory traversal in snapshot manifest validation (#201) ([#201](https://github.com/always-further/nono/pull/201))

- Writes setup profiles to the correct directory on macOS (#184) ([#184](https://github.com/always-further/nono/pull/184))

- Add AccessFs::RemoveDir to Landlock write permissions (#199) ([#199](https://github.com/always-further/nono/pull/199))

- *(network)* Add claude.ai to llm_apis allow list (#206) ([#206](https://github.com/always-further/nono/pull/206))


### CI/CD

- Add conventional commits enforcement and auto-labeling (#194) ([#194](https://github.com/always-further/nono/pull/194))


### Features

- Add 7 new integration test suites and parallelize test runner (#214) ([#214](https://github.com/always-further/nono/pull/214))


### Miscellaneous

- *(docs)* Add 1Password credential injection documentation (#198) ([#198](https://github.com/always-further/nono/pull/198))

## [0.7.0] - 2026-03-01

### 🚀 Features

- Add 1Password secret injection via op:// URI support (#183)
## [0.6.1] - 2026-02-27

### 🚀 Features

- First release of seperarate nono and nono-cli packages
