# Relative `extends` paths and save-to-extended-profile Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a profile `extends` another profile file by a `./` or `../` path, and let the save-on-exit prompt write grants into any writable profile file in the chain, keeping JSONC comments.

**Architecture:** A new `profile/extends_ref.rs` owns classifying and resolving each `extends` entry; the resolver, CLI `--extends`, the official-pack chain walker and `profile init` all call it. Each loaded `Profile` records the files it was built from (`source_files`), which is threaded to the save offer. Profile updates go through a new comment-preserving writer built on `jsonc-parser`'s `cst` feature.

**Tech Stack:** Rust (nono-cli binary crate), `jsonc-parser` 0.34 with `cst`, existing `test_env` helpers.

**Spec:** `docs/superpowers/specs/2026-10-06-relative-extends-design.md` (issue nolabs-ai/nono#2065)

## Global Constraints

- Path entries start with `./` or `../` and must end in `.json` or `.jsonc`.
- Entries starting with `/` or `~` error: "absolute and `~/` paths are not supported in `extends`; use a relative path".
- Path target inside the pack store errors: "extend a pack by name (`org/pack`), not by path".
- Path entries are rejected in pack-store profiles, drafts (`profile-drafts/`) and built-ins. These rules never apply to CLI `--extends` entries.
- CLI Path entries resolve against the cwd; CLI Name entries keep today's resolution (including the selected profile's sibling context).
- Compare paths with `Path::starts_with` on canonical paths, never string prefixes.
- No production `.unwrap()`/`.expect()`; expected failures return `NonoError` (`ProfileInheritance` for extends errors, `LearnError` for save errors).
- A failed write leaves the profile file unchanged.
- Save menu: only when 2+ writable files; precedence order; "a new user profile" only when no writable file exists.
- Commits: `git commit -s`, conventional prefix, ending with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Focused test command: `cargo test -p nono-cli --bin nono <filter>`. Before handoff: `make ci` and `make clippy`.

## Review Focus

1. A Path entry that is a symlink to a file in another directory: its own bare-name siblings resolve next to the canonical target, not the link. (Task 2 test.)
2. The same base reached as `./a.json` from one file and `../x/a.json` from another, with no cycle: must load, not error. (Task 2 test.)
3. A `.jsonc` profile whose `filesystem` key is absent, or holds an empty array on one line: the writer creates/appends without breaking JSON. (Task 5 test.)
4. A profile file that changed on disk to invalid JSON before the save: the save errors and the file is unchanged. (Task 5 test.)
5. `--profile ./x.json` where `x.json` is a symlink into the pack store: no update offered. (Task 7 test.)

---

### Task 1: Classify and resolve `extends` entries

**Files:**
- Create: `crates/nono-cli/src/profile/extends_ref.rs`
- Modify: `crates/nono-cli/src/profile/mod.rs` (add `mod extends_ref;` + `pub(crate) use extends_ref::{...}` next to `mod credential_provider;` at line 8)

**Interfaces:**
- Produces:
  ```rust
  pub(crate) enum ExtendsRef { Name(String), Registry(String), Path(PathBuf) } // Path is canonical
  pub(crate) enum ExtendsOrigin<'a> { File(&'a Path), Cli(&'a Path), Builtin }
  // File(p): entry written in the profile file at p (canonical when loaded; may not exist yet for `profile init`).
  // Cli(dir): entry from `--extends`; paths resolve against dir.
  pub(crate) fn classify_extends_entry(raw: &str, origin: ExtendsOrigin<'_>) -> Result<ExtendsRef>;
  impl ExtendsRef { pub(crate) fn visited_key(&self) -> String } // name, or canonical path string
  pub(crate) fn is_under_pack_store(path: &Path) -> bool;
  ```

- [ ] **Step 1: Write failing tests** in `extends_ref.rs` `#[cfg(test)] mod tests`, using `crate::test_env::with_isolated_config_home` and `tempfile::tempdir`:
  - `bare_name_is_name` — `"default"` → `Name("default")`.
  - `registry_ref_is_registry` — `"nolabs-ai/claude"` → `Registry`.
  - `dot_slash_resolves_against_declaring_file_dir` — file `d/child.json`, sibling `d/base.json`; `"./base.json"` → `Path(canonical d/base.json)`.
  - `dot_dot_resolves_to_parent` — `d/sub/child.json`, `"../base.json"` → `Path(d/base.json)`.
  - `cli_origin_resolves_against_given_dir` — `Cli(dir)`, `"./x.json"` → `Path(dir/x.json)`.
  - `missing_path_errors_with_resolved_path` — error string contains the entry and the joined path.
  - `path_without_json_extension_errors` — `"./base"` errors.
  - `absolute_and_tilde_rejected` — `"/x.json"`, `"~/x.json"` error containing `absolute and \`~/\` paths are not supported`.
  - `path_into_pack_store_rejected` — target under `<config>/nono/packages/...` errors containing `extend a pack by name`.
  - `path_entry_in_pack_store_profile_rejected` — `File(<pack store>/ns/p/profiles/x.json)` with `"./y.json"` errors.
  - `path_entry_in_draft_rejected` — `File(<config>/nono/profile-drafts/x.json)` errors.
  - `path_entry_in_builtin_rejected` — `Builtin` origin errors.
  - `cli_origin_skips_file_rules` — `Cli(<drafts dir>)` with an existing `./x.json` there → `Path`.
  - `symlinked_target_returns_canonical` (`#[cfg(unix)]`) — link `d/base.json → e/real.json` returns `e/real.json`.
  - `shared_slash_json_is_still_invalid` — `"shared/base.json"` errors with `invalid base profile name`.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile::extends_ref` — expect compile failure (module missing).

- [ ] **Step 3: Implement.** Order of checks: `./`/`../` → Path; `/` or `~` prefix → error; `is_registry_ref` → Registry; `is_valid_profile_name` → Name; else the existing "invalid base profile name '{raw}'" message. For Path: origin rules first (File under `user_profile_draft_dir`/pack store, Builtin → error), base dir = `Cli(dir)` or `nono::try_canonicalize(file.parent())`, join, `canonicalize` (missing → error naming entry and joined path), then reject `is_under_pack_store(target)`. `is_under_pack_store` canonicalizes `package_store_dir()`; a missing store returns false. All errors are `NonoError::ProfileInheritance`.

- [ ] **Step 4: Run** the same command — all pass.

- [ ] **Step 5: Refactor.** Error messages are `const`s that the tests reference; classification reuses `is_registry_ref` / `is_valid_profile_name` rather than copying their logic. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(profile): classify relative-path extends entries (#2065)`.

### Task 2: Resolve Path entries written in profile files

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` — `resolve_extends` (~3593), `load_base_profile_raw` (~3699), `ResolvedBase`
- Test: `crates/nono-cli/src/profile/mod.rs` tests module (next to `test_transitive_extends_uses_symlinked_parent_referent`, ~7747)

**Interfaces:**
- Consumes: Task 1 `classify_extends_entry`, `ExtendsOrigin::{File, Builtin}`, `ExtendsRef::visited_key`.
- Produces: `resolve_extends(child, visited, depth, context_dir, source_file, leading: &[ExtendsRef])` — `leading` is used by Task 3; this task passes `&[]` everywhere. `visited: &mut Vec<String>` now holds `visited_key()` values.

- [ ] **Step 1: Write failing tests** (temp dirs; `load_from_file(&child, &[])`):
  - `test_extends_relative_path_sibling_dir` — `proj/.nono/agent.json` extends `"../shared/base.json"`; `filesystem.read` contains the base's entry then the child's.
  - `test_extends_relative_path_base_finds_own_sibling` — `shared/base.json` extends `"common"`; `shared/common.json` is loaded (and a decoy `common.json` beside the child is not).
  - `test_extends_relative_path_symlink_uses_target_dir` (`#[cfg(unix)]`) — Review Focus 1.
  - `test_extends_relative_path_cycle_detected` — `a.json → ./b.json → ./a.json` errors with `circular dependency`.
  - `test_extends_same_file_two_spellings_is_not_cycle` — child extends `["./x/a.json", "./y/b.json"]`, `y/b.json` extends `"../x/a.json"`; loads (Review Focus 2).
  - `test_extends_path_entry_in_pack_profile_rejected` — `build_fake_pack_store` profile with `"extends": "./other.json"`; `load_profile("<ns>/<name>")` errors.
  - `test_extends_name_entries_unchanged` — existing `test_extends_*` tests still pass (run, don't edit).

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile::tests::test_extends` — new tests fail.

- [ ] **Step 3: Implement.** In `resolve_extends`, classify each raw entry with `ExtendsOrigin::File(source_file)` when `source_file` is `Some`, else `Builtin`; keep the cycle check on `visited_key()`. For `ExtendsRef::Path(p)`: `parse_file_backed_profile(&p)` → `ResolvedBase::Sibling(profile, p)`. Name/Registry go to the existing `load_base_profile_raw` unchanged. Change `ResolvedBase::Global(Profile)` to `Global(Profile, Option<PathBuf>)`: pack-store bases carry their profile path, built-ins carry `None`. Recurse into a pack base with `context_dir = None` (name lookup unchanged) but `source_file = Some(pack_path)`, so its path entries hit the pack-store rule and its message; built-in bases hit the Builtin rule. A pack-store top-level profile (`load_from_file` on a store path) already passes `Some(source_path)`.

- [ ] **Step 4: Run** `cargo test -p nono-cli --bin nono profile::` — all pass.

- [ ] **Step 5: Refactor.** The "invalid base profile name" check in `load_base_profile_raw` is now done by `classify_extends_entry`; remove the duplicate. Path and sibling bases share `parse_file_backed_profile`. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(profile): resolve relative-path extends entries (#2065)`.

### Task 3: CLI `--extends` as a separate resolved list

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` — `load_profile_impl`, `load_profile_inner`, `load_registry_profile`, `load_profile_from_path_impl`, `load_from_file`, built-in branch; remove `prepend_cli_extends`.
- Test: same tests module, next to `test_load_profile_with_extends_prepends_cli_bases` (~5066).

**Interfaces:**
- Consumes: Task 1 `ExtendsOrigin::Cli`; Task 2 `resolve_extends(..., leading)`.
- Produces: internal `fn load_profile_with_cli_bases(name_or_path: &str, cli: &[ExtendsRef]) -> Result<Profile>`; `load_profile_with_extends(name_or_path, cli_extends: &[String])` keeps its signature and classifies with `ExtendsOrigin::Cli(&std::env::current_dir()?)`.

Note: CLI `Name` entries must still resolve with the selected profile's `context_dir` (pinned by `test_cli_extends_preserves_global_file_source_context`). Only `Path` entries are pre-resolved.

- [ ] **Step 1: Write failing tests:**
  - `test_cli_path_extends_with_pack_profile` — fake pack profile + `cli = [Path(<tmp>/extra.json)]` via `load_profile_with_cli_bases("<ns>/<name>", ...)`; result includes `extra.json`'s read entry.
  - `test_cli_path_extends_with_builtin_profile` — `load_profile_with_cli_bases("default", [Path(..)])` includes the entry.
  - `test_cli_path_resolves_against_cwd_not_profile_dir` — profile in `a/`, `extra.json` in both `a/` and `b/` with different reads; `Cli(b)` classification picks `b/extra.json`.
  - Existing `test_load_profile_with_extends_*` and `test_cli_extends_preserves_global_file_source_context` keep passing unedited (ordering: CLI bases, then the profile's own bases, then the child).

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile::tests::test_cli` and `profile::tests::test_load_profile_with_extends` — new tests fail.

- [ ] **Step 3: Implement.** Thread `cli: &[ExtendsRef]` through the load functions instead of `&[String]`. `resolve_extends` iterates `leading` before the child's own entries at depth 0 only (recursive calls pass `&[]`). The built-in branch calls `resolve_extends(def.to_raw_profile(), .., None, None, cli)` then `finalize_profile`. Delete `prepend_cli_extends`.

- [ ] **Step 4: Run** `cargo test -p nono-cli --bin nono profile::` — all pass.

- [ ] **Step 5: Refactor.** One place converts `&[String]` CLI bases into `Vec<ExtendsRef>`; no leftover `cli_extends: &[String]` parameters below `load_profile_impl`. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(cli): resolve --extends paths against the cwd (#2065)`.

### Task 4: Chain walker and `profile init --extends`

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` — extract `fn locate_profile_file(name_or_path: &str) -> Option<PathBuf>` from `load_profile_extends` (~2867); add `load_profile_extends_resolved`.
- Modify: `crates/nono-cli/src/package_status.rs:220` `walk_extends_chain` — call `load_profile_extends_resolved`.
- Modify: `crates/nono-cli/src/profile_cmd.rs:126-134` — `--extends` validation.

**Interfaces:**
- Produces: `pub(crate) fn load_profile_extends_resolved(name_or_path: &str) -> Option<Vec<String>>` — like `load_profile_extends`, but Path entries become canonical absolute path strings (entries that fail to classify are dropped; detection is best-effort and the real load reports the error).

- [ ] **Step 1: Write failing tests:**
  - `package_status.rs`: `claude_code_detection_follows_relative_path_extends` — `proj/.nono/agent.json` extends `"../shared/base.json"`, which extends `"nolabs-ai/claude"`; `selects_claude_code(<agent.json path>)` is true.
  - `profile_cmd.rs`: `test_init_extends_relative_path_validates_against_output_dir` — `-o <tmp>/proj/.nono/new.json --extends ../base.json` with `<tmp>/proj/base.json` present succeeds and writes `"extends": "../base.json"` verbatim; with it absent, fails with the Task 1 missing-path message.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono package_status` and `profile_cmd::tests::test_init` — new tests fail.

- [ ] **Step 3: Implement.** `locate_profile_file` mirrors `load_profile_extends`' lookup order (path, registry ref → pack store, user dir, pack store) and returns the canonical file; `load_profile_extends` uses it (built-ins keep their branch). In `cmd_init`, a base starting with `./`/`../` is checked with `classify_extends_entry(base, ExtendsOrigin::File(&output_path))`; other bases keep `profile_exists`.

- [ ] **Step 4: Run** both commands — pass.

- [ ] **Step 5: Refactor.** `load_profile_extends` and `load_profile_extends_resolved` share `locate_profile_file`; there is one copy of the lookup order. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(profile): follow relative extends in pack detection and profile init (#2065)`.

### Task 5: Comment-preserving profile updates

**Files:**
- Modify: `crates/nono-cli/Cargo.toml:98` → `features = ["serde", "cst"]`
- Create: `crates/nono-cli/src/profile_file_edit.rs` (+ `mod profile_file_edit;` in `main.rs`)
- Modify: `crates/nono-cli/src/profile_save_runtime.rs` — `PreparedProfileSave` (line 20), `write_profile` (730), `prepare_profile_save_from_patch` (1679)

**Interfaces:**
- Produces:
  ```rust
  // profile_file_edit.rs
  pub(crate) fn apply_patch_to_profile_text(text: &str, patch: &profile::Profile) -> Result<String>;
  // profile_save_runtime.rs
  pub(crate) struct PreparedProfileSave { action, profile_name, profile_path, profile, patch: profile::Profile }
  ```
  `write_profile`: `Created` → existing `serde_json` path; `Updated` → read file, `apply_patch_to_profile_text`, `profile::parse_profile_bytes` on the result (error → `LearnError`, file untouched), then `atomic_write`.

- [ ] **Step 1: Write failing tests** in `profile_file_edit.rs`:
  - `keeps_comments_and_appends_new_entries` — input with `// keep me` comments and `"read": ["/a"]`; patch read `["/a", "/b"]`; output contains `// keep me`, `"/b"` once, `"/a"` once.
  - `creates_missing_sections` — `{ "meta": { "name": "x" } }` + patch on `filesystem.read_file` and `open_urls.allow_origins` → both created (Review Focus 3).
  - `appends_to_empty_inline_array` — `"read": []` (Review Focus 3).
  - `allow_localhost_only_flips_to_true` — existing `false` + patch `true` → `true`; existing `true` + patch `false` → stays `true`.
  - `matches_merge_profile_patch` — for 4 representative patches (filesystem lists, `bypass_protection`, `unsafe_macos_seatbelt_rules`, `open_urls`): `serde_json::to_value(parse_profile_bytes(output))` equals `serde_json::to_value({ let mut p = parse_profile_bytes(input); merge_profile_patch(&mut p, &patch); p })`.
  - `non_object_section_errors` — `"filesystem": []` returns `Err`.
  In `profile_save_runtime.rs` tests:
  - `write_profile_update_keeps_jsonc_comments` — `.jsonc` user profile with comments, update via `prepare_profile_save_from_patch` + `write_profile`; comments survive.
  - `write_profile_update_invalid_file_left_unchanged` — file rewritten to `{ invalid` after prepare; `write_profile` errs; bytes unchanged (Review Focus 4).
  - `write_profile_update_rejects_invalid_profile_left_unchanged` — file contains `"bogus_field": 1` (valid JSONC; `ProfileDeserialize` has `deny_unknown_fields`); the CST edit succeeds, the `parse_profile_bytes` re-check fails, `write_profile` errs, bytes unchanged. This pins the re-check itself.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile_file_edit` and `profile_save_runtime::tests::write_profile` — fail.

- [ ] **Step 3: Implement** with `jsonc_parser::cst::CstRootNode::parse(text, &ParseOptions::default())`, `object_value_or_set`, `object_value_or_create(name)` / `array_value_or_create(name)` (`None` → `LearnError` naming the key), `CstArray::elements()` + `as_string_lit()?.decoded_value()` for de-dup, `CstArray::append(value.into())`, `root.to_string()`. Fields: `filesystem.{allow,read,write,allow_file,read_file,write_file,bypass_protection,suppress_save_prompt}`, top-level `unsafe_macos_seatbelt_rules`, `open_urls.allow_origins`, `open_urls.allow_localhost`. Add a comment in `merge_profile_patch` pointing at `apply_patch_to_profile_text` (the two field lists must match; `matches_merge_profile_patch` enforces it).

- [ ] **Step 4: Run** both commands, then `cargo test -p nono-cli --bin nono profile_save_runtime` — all pass.

- [ ] **Step 5: Refactor.** The patched fields are one table in `profile_file_edit.rs` (section, key, accessor), not repeated code per field; the comment in `merge_profile_patch` names it. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `fix(cli): keep comments when the save prompt updates a profile (#2065)`.

### Task 6: Record profile source files and thread them to the save offer

**Files:**
- Modify: `crates/nono-cli/src/profile/mod.rs` — `Profile` (~2576), `ProfileDeserialize` → `From` (~2805), `load_from_file`, `resolve_extends`, `load_base_profile_raw` pack branch, `merge_profiles` (~4103 next to `packs`)
- Modify: `crates/nono-cli/src/sandbox_prepare.rs` — `PreparedSandbox` (506) + its 3 constructors (~1552, ~1954, ~2938)
- Modify: `crates/nono-cli/src/launch_runtime.rs` — `ExecutionFlags` (229) + 307
- Modify: `crates/nono-cli/src/exec_strategy.rs` — `ExecConfig` (~294), `ProfileSaveOffer` (~113), 1764
- Modify: `crates/nono-cli/src/execution_runtime.rs:725`

**Interfaces:**
- Produces:
  ```rust
  #[derive(Debug, Clone, PartialEq, Eq, Hash)]
  pub(crate) struct ProfileSourceFile { pub(crate) path: PathBuf, pub(crate) kind: ProfileSourceKind }
  #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
  pub(crate) enum ProfileSourceKind { User, Draft, Project, Pack }
  impl ProfileSourceFile { pub(crate) fn new(canonical: PathBuf) -> Self } // kind by Path::starts_with on canonical user/draft/pack dirs
  impl ProfileSourceKind { pub(crate) fn is_writable(self) -> bool }        // Pack → false
  // Profile: #[serde(skip)] pub(crate) source_files: Vec<ProfileSourceFile>  (merge order: bases first, top-level last)
  impl Profile { pub(crate) fn writable_source_files(&self) -> Vec<ProfileSourceFile> } // writable only, reversed = precedence order
  // ProfileSaveOffer / ExecConfig: profile_save_files: &'a [profile::ProfileSourceFile]
  // ExecutionFlags / PreparedSandbox: profile_save_files: Vec<profile::ProfileSourceFile>
  ```

- [ ] **Step 1: Write failing tests** (profile tests module):
  - `test_source_files_record_kinds` — path profile `proj/agent.json` extends `["../shared/base.json", "<pack install_as>", "default"]`; `source_files` kinds are `[Project(shared/base), Pack, Project(agent)]` in that order; no entry for `default`.
  - `test_writable_source_files_precedence_order` — chain `top extends ["./a.json", "./b.json"]`, `a extends "./c.json"`; `writable_source_files()` paths are `[top, b, a, c]`.
  - `test_source_files_draft_and_user_kinds` — a user profile loads as `User`; a draft path loads as `Draft`.
  - `test_source_files_not_serialized` — `serde_json::to_value(&profile)` has no `source_files` key.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile::tests::test_source_files profile::tests::test_writable_source` — fail.

- [ ] **Step 3: Implement.** Push `ProfileSourceFile::new(source_path)` in `load_from_file` after parsing, and onto each `ResolvedBase::Sibling` base before recursing; push a `Pack` entry (via `nono::try_canonicalize`) in the pack-store branches of `load_base_profile_raw`. `merge_profiles`: `source_files: dedup_append(&base.source_files, &child.source_files)`. Fix every `Profile { .. }` literal the compiler flags with `source_files: Vec::new()`. Set `PreparedSandbox.profile_save_files` from `loaded_profile.as_ref().map(Profile::writable_source_files).unwrap_or_default()` where `ignored_denial_paths` is set from the profile (~1954); `Vec::new()` at the other two constructors. Thread through exactly as `ignored_denial_paths` is threaded.

- [ ] **Step 4: Run** `cargo test -p nono-cli --bin nono` — all pass (no behaviour change yet).

- [ ] **Step 5: Refactor.** Kind detection lives only in `ProfileSourceFile::new`, reusing `is_under_pack_store` (Task 1) and `is_under_user_profile_draft_dir`. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(profile): record the files a loaded profile came from (#2065)`.

### Task 7: Save to the profile file the session ran with

**Files:**
- Modify: `crates/nono-cli/src/profile_save_runtime.rs` — `offer_save_run_profile` (260), `offer_url_only_save` (307), `offer_save_with_patch` (335), `offer_save_text_prompt` (382), `prompt_profile_save_choice` (547), `prepare_profile_save_from_patch` (1679)

**Interfaces:**
- Consumes: Task 6 `offer.profile_save_files` (precedence order); Task 5 `PreparedProfileSave.patch`.
- Produces:
  ```rust
  enum SaveTarget { File(PathBuf), NewUserProfile }
  fn save_targets(save_files: &[profile::ProfileSourceFile]) -> Vec<SaveTarget>; // files in order; [NewUserProfile] when empty
  pub(crate) fn prepare_profile_save_to_file(patch: &profile::Profile, path: &Path, run_with: &str) -> Result<PreparedProfileSave>; // action Updated
  ```
  `run_with` is the `--profile` value to print in "Run with:" (the top-level `compared_profile`, not the base file).

- [ ] **Step 1: Write failing tests:**
  - `save_targets_empty_is_new_user_profile` — `[]` → `[NewUserProfile]`.
  - `save_targets_files_never_include_new_user_profile` — two files → `[File(a), File(b)]`.
  - `prepare_profile_save_to_file_updates_path_profile` — `proj/.nono/agent.json`; result `Updated`, path equals it, `profile_name == "./proj/.nono/agent.json"` as passed.
  - `path_profile_symlinked_into_pack_store_not_offered` — a `ProfileSourceFile::new` for a symlink into the store has kind `Pack` and `writable_source_files` drops it (Review Focus 5).
  - Existing `prepare_profile_save_from_patch_*` tests still pass.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile_save_runtime` — fail.

- [ ] **Step 3: Implement.** Replace both `compared_profile.filter(... is_user_override)` branches with: `match save_targets(files).as_slice()` → `[SaveTarget::File(p)]` uses `prepare_profile_save_to_file` (selector: no extra question; text prompt: existing question with the full path in place of the name); `[NewUserProfile]` keeps the name prompt + `prepare_profile_save_from_patch`; 2+ files → for this task take the first (Task 8 adds the menu). Change the `prompt_profile_save_choice` wording from `user profile '{name}'` to `profile '{path}'`.

- [ ] **Step 4: Run** `cargo test -p nono-cli --bin nono profile_save_runtime` — pass.

- [ ] **Step 5: Refactor.** The selector and text-prompt flows share one helper that writes to a `SaveTarget`; no duplicated `prepare` + `write_profile` + `print_profile_save` sequences. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `fix(cli): let the save prompt update a --profile path (#2065)`.

### Task 8: Save-target menu

**Files:**
- Modify: `crates/nono-cli/src/profile_save_runtime.rs`

**Interfaces:**
- Consumes: Task 7 `SaveTarget`, `save_targets`, `prepare_profile_save_to_file`.
- Produces:
  ```rust
  fn render_save_target_menu(files: &[PathBuf]) -> String;
  fn parse_save_target_choice(input: &str, count: usize) -> Option<Option<usize>>; // Some(Some(i)) pick, Some(None) skip, None invalid
  fn chosen_save_target(files: &[PathBuf], input: &str) -> Option<Option<PathBuf>>; // parse + index into files
  fn prompt_save_target(files: &[PathBuf]) -> Result<Option<PathBuf>>;          // loops on invalid input; uses chosen_save_target
  ```

- [ ] **Step 1: Write failing tests:**
  - `render_menu_labels_top_and_bases` — two paths; output equals
    ```
    Save the selected rules to:
      1) <a>    (this profile)
      2) <b>    (base — applies to every profile that extends it)
    Choice [1]: 
    ```
    (column-align the labels; the test asserts each line's prefix, path and label).
  - `parse_choice_enter_is_first` — `""` → `Some(Some(0))`; `"2"` → `Some(Some(1))`; `" skip "` → `Some(None)`; `"3"` with count 2 → `None`; `"x"` → `None`.
  - `menu_choice_two_writes_base_only` — temp `top.json` and `base.json` (in precedence order); `chosen_save_target(&files, "2")` → `Some(Some(base))`; `prepare_profile_save_to_file(&patch, &base, "./top.json")` + `write_profile`; `base.json` gains the patch entry and `top.json`'s bytes are unchanged.

- [ ] **Step 2: Run** `cargo test -p nono-cli --bin nono profile_save_runtime::tests::render_menu profile_save_runtime::tests::parse_choice profile_save_runtime::tests::menu_choice` — fail.

- [ ] **Step 3: Implement.** In Task 7's 2+ files arm, call `prompt_save_target` after the selector/override confirmation and before writing, for both the selector and text-prompt flows (`prompt_print`/`read_input_line`; invalid input prints "Enter a number from 1 to N, press Enter for 1, or type skip." in red). `skip` writes nothing.

- [ ] **Step 4: Run** `cargo test -p nono-cli --bin nono profile_save_runtime` — pass.

- [ ] **Step 5: Refactor.** Both flows call `prompt_save_target`; `prompt_save_target` is a thin loop over `chosen_save_target`. Re-run the Step 4 command — still passes.

- [ ] **Step 6: Commit** `feat(cli): choose which profile file the save prompt updates (#2065)`.

### Task 9: Docs and full verification

**Files:**
- Modify: `docs/cli/features/profile-authoring.mdx` — "How `extends` Works" (~35) and the post-run save prompt text (~460)

- [ ] **Step 1:** Document, leading with a project profile (`--profile ./.nono/agent.json`) that has `"extends": "claude-code"` plus `"../shared/base.json"`: the `./`/`../` rule, extension requirement, the error cases from Global Constraints, CLI `--extends` resolving from the cwd. In the save section: which files can be updated, the menu, precedence order, packs never offered, comments kept.
- [ ] **Step 2: Run** `make fmt`, then `make ci` and `make clippy` — both end without errors (`CI checks passed`).
- [ ] **Step 3: Grep-verify** each task's claim on the current tree: `grep -n "fn classify_extends_entry" crates/nono-cli/src/profile/extends_ref.rs`, `grep -n "prepend_cli_extends" -r crates/nono-cli/src` (no hits), `grep -n '"cst"' crates/nono-cli/Cargo.toml`, `grep -n "source_files" crates/nono-cli/src/profile/mod.rs`, `grep -n "fn prompt_save_target" crates/nono-cli/src/profile_save_runtime.rs`.
- [ ] **Step 4: Commit** `docs(profile): document relative extends and save targets (#2065)`.
