# Relative paths in `extends`, and save to an extended profile — design

Issue: [nolabs-ai/nono#2065](https://github.com/nolabs-ai/nono/issues/2065).
Both phases ship in one PR. Phase 1 commits come first; phase 2 builds on the
phase 1 writer and path-profile save.

## Goal

A profile can extend another profile file by a path relative to itself, so a
project can keep a shared base profile anywhere in its tree. Also fix two bugs
in the save-on-exit flow that block path-based profiles:

- Bug 3: `--profile ./x.json` cannot be updated on exit.
- Bug 4: updating a profile rewrites it with `serde_json` and strips comments.

Phase 2: on exit, the user can save grants to any writable profile file in the
resolved `extends` chain, not only the top-level profile. Pack and built-in
profiles are never offered.

## Entry syntax

Each `extends` entry written in a profile file is classified once, in this
order. CLI `--extends` entries follow the same table, except that a Path entry
resolves against the cwd (see "CLI `--extends`" below).

| Entry | Kind | Rule |
|---|---|---|
| starts with `./` or `../` | Path | Must end in `.json` or `.jsonc`. |
| starts with `/` or `~` | — | Error: "absolute and `~/` paths are not supported in `extends`; use a relative path". |
| `org/name[@ver]` (`is_registry_ref`) | Registry | Unchanged. |
| valid profile name | Name | Unchanged lookup: sibling `.json`, user dir, pack store, built-in. |
| anything else | — | Error: "invalid base profile name" (unchanged). |

`shared/base.json` (no `./`) is not a path. It stays an invalid name, as today.
This keeps the rule to one check and stops it colliding with registry refs.

## Path resolution

1. Base directory:
   - For an entry in a file: the parent of the canonical path of that file.
     `load_from_file` already canonicalizes, so this is the existing
     `context_dir`.
   - For a CLI `--extends` entry: the current working directory.
2. Join, then `canonicalize`. A missing file is an error naming the entry and
   the resolved path. There is no fallback to name lookup.
3. Reject when the canonical target is inside the pack store
   (`package_store_dir()`, canonicalized; `Path::starts_with`). Message:
   "extend a pack by name (`org/pack`), not by path". Reason: a path load skips
   the pack bookkeeping (verification list, session hook provenance,
   `$PACK_DIR`).
4. Load the file with `parse_file_backed_profile`. Return it as
   `ResolvedBase::Sibling(profile, canonical_path)`. Its own entries then
   resolve relative to its directory, and its bare names find siblings there.

### Where path entries are rejected

These rules apply to entries written in a profile file. They never apply to CLI
`--extends` entries.

- In a profile loaded from the pack store: any Path entry is an error. A pack
  must not load files outside itself.
- In a profile under `profile-drafts/`: any Path entry is an error, because
  `profile promote` moves the file and changes what the path means.
- In a built-in profile: no file context exists. Treat as an error (cannot
  happen with shipped policy, but fail closed).

### Cycle detection

`visited` holds a key per entry: the name for Name/Registry entries, and the
canonical path for Path entries. So `./a.json` and `../x/a.json` that point at
the same file are one node. `MAX_INHERITANCE_DEPTH` is unchanged.

## Callers that must understand Path entries

- `resolve_extends` / `load_base_profile_raw` — the main change.
- `prepend_cli_extends` — see "CLI `--extends`" below.
- `package_status::walk_extends_chain` (Claude Code / official pack detection)
  — it walks raw strings without a directory. It must resolve Path entries
  relative to the declaring file, using the same classify-and-resolve function.
  It must not duplicate the rules.
- `profile init --extends <path>` — write the entry as given. Validate it
  relative to the output file's directory, because that is what it means when
  loaded.
- `profile show` / `diff` / `validate` / `why` — show the raw entry as written.
  They resolve through the shared loader, so no extra logic.

### CLI `--extends`

Today `prepend_cli_extends` inserts CLI bases into the selected profile's own
`extends` list (`load_from_file`, the pack-store branch, and the built-in
branch of `load_profile_inner`). That would put a CLI path inside a pack or
built-in profile's list, where path entries are rejected, and the resolved
absolute path would hit the "no absolute paths" rule.

Change: CLI bases do not go into `profile.extends`. Classify and resolve them
first (Path entries against the cwd, to a canonical path), then pass the
resolved entries to the resolver as a separate list that is merged ahead of the
profile's own bases, in the same position they take today. The pack-store,
built-in and "no absolute paths" rules check only entries written in a file.

So `nono run --profile claude-code --extends ./project-extra.json` works. The
main pattern is still a project profile with `"extends": "claude-code"`, run
as `--profile ./.nono/agent.json`; that needs no CLI change.

One function owns classification and resolution
(`classify_extends_entry(raw, base_dir, declaring_file) -> Result<ExtendsRef>`).
Every caller above uses it.

## Bug 3: update a path profile on exit

When `profile_save_base` is a file path (`is_file_path_ref`):

- Canonicalize it. If it is inside the pack store, do not offer an update; keep
  the current new-user-profile flow.
- Otherwise update that file, exactly like the existing named-user-profile
  branch: the interactive selector writes without a further question (the item
  selection is the confirmation), and the text prompt asks its existing
  "Update …? [g/s/Enter]" question. In both, the prompt and the
  `print_profile_save` output show the full path, because the file can be in a
  git repo.

`prepare_profile_save_from_patch` takes a name today. Add a path-based entry
point; keep the name-based one for user profiles.

## Bug 4: keep comments when updating

Enable the `cst` feature of `jsonc-parser` (already a dependency, v0.34). For
the `Updated` action only:

1. Read the original text. Parse with `CstRootNode::parse`.
2. For each field that `merge_profile_patch` touches, append values that are
   not already present as plain strings:
   `filesystem.{allow,read,write,allow_file,read_file,write_file,bypass_protection,suppress_save_prompt}`,
   `unsafe_macos_seatbelt_rules`, `open_urls.allow_origins`. Use
   `object_value_or_create` / `array_value_or_create` / `CstArray::append`.
3. `open_urls.allow_localhost`: set to `true` only if the patch sets it (same
   monotonic rule).
4. Re-parse the output with `parse_profile_bytes` before the atomic write. If
   it fails, return an error and leave the file unchanged.

New profiles (`Created`) keep the `serde_json` writer; they have no comments.

The CST write is the only writer for updates, so the set of patched fields
lives in two places (`merge_profile_patch` and the CST glue). A test pins them
together (below).

## Phase 2: choose the save target on exit

### Recording where each layer came from

Add `source_files: Vec<ProfileSourceFile>` to `Profile` (`#[serde(skip)]`, not
part of the file format). It is filled at load and merged in `merge_profiles`
the same way as `packs`. Each entry has the canonical path and a kind:

| Kind | How it is detected | Writable |
|---|---|---|
| User | under `user_profile_dir()` | yes |
| Draft | under `user_profile_draft_dir()` | yes |
| Project | any other file (path entry, `--profile <path>`, sibling) | yes |
| Pack | under `package_store_dir()` | no — verification fails on change and `nono pull` replaces it |
| Built-in | no file | not listed |

Detection uses `Path::starts_with` on canonical paths. The list is recorded at
load, so the save offer uses the files the session actually ran with. It is
not re-walked at exit.

The loaded profile's `source_files` (writable entries only) is passed to
`ProfileSaveOffer` next to `profile_save_base`.

### Save flow

1. The session ends with denials. nono builds the patch (no change).
2. The user selects items in the selector or the text prompt (no change).
   The `override` confirmation stays where it is.
3. Build the target list:
   - Writable source files in precedence order: the reverse of the recorded
     merge order. The top-level profile is first; then the base whose values
     win, down to the base that wins least. For `extends: ["a", "b"]` where
     `a` extends `c`, the merge records `[c, a, b, top]` and the menu shows
     `top, b, a, c`. Duplicates are already removed by the merge.
   - "a new user profile", only when the top-level profile was selected by
     name or registry ref, or there is no profile. A new user profile cannot
     extend a path profile (absolute paths are out of scope), so it would drop
     the user's base.
4. If the list has one entry, behave as today: update that file, or prompt for
   a new user profile name.
5. If the list has two or more entries, show a numbered menu. The same menu is
   used after the interactive selector and in the text prompt (the selector
   has already left raw mode).

   ```
   Save the selected rules to:
     1) /path/proj/.nono/agent.json    (this profile)
     2) /path/proj/shared/base.json    (base — applies to every profile that extends it)
     3) a new user profile
   Choice [1]:
   ```

   - Enter selects 1. `skip` cancels. Invalid input prints help and asks again.
   - Paths are shown in full: a project file can be in a git repo.
6. Write to the chosen file with the phase 1 CST writer, or run the existing
   new-user-profile flow.

No terminal (`terminal_prompts_available()` is false): no prompt, as today.

### Phase 2 tests

- Source recording: user, draft, project, pack, built-in layers get the right
  kind; a pack layer is never in the writable list; merge keeps all layers.
- Target list order: precedence order (`top, b, a, c` for the example in the
  save flow); duplicates removed.
- "a new user profile" is listed for a named top-level profile and absent for
  a path top-level profile.
- One target: no menu, current behaviour.
- Menu: Enter picks the top-level profile; `2` writes to the base and leaves the
  top-level file unchanged; `skip` writes nothing; invalid input re-prompts.
- Writing to a base keeps its comments (phase 1 writer).

## Out of scope

- Absolute and `~/` paths (reasons in the issue).
- `.json` vs `.jsonc` precedence in bare-name sibling lookup. Today sibling
  lookup checks only `.json`, and the user dir prefers `.jsonc`. Changing that
  alters existing resolution; it needs its own issue.
- Choosing a different save target per item.

## Security notes

- A path can reach any file the user can read. This adds no trust: the
  top-level profile can already grant the same access directly.
- Packs cannot use paths, and paths cannot reach into packs, so pack
  verification and hook provenance stay intact.
- Paths are compared with `Path::starts_with` on canonical paths, never string
  prefixes. Canonicalizing at load also removes `..` and symlink tricks from
  cycle detection.
- TOCTOU: the file is canonicalized and read once per resolution, the same as
  sibling lookup today.
- A grant saved to a shared base applies to every profile that extends it. The
  menu says so, and the default is the top-level profile.
- Pack files are never write targets, so a save cannot break pack
  verification.
- Linux and macOS: no change to enforcement. The resolved profile goes through
  the same merge and validation.

## Tests

Resolution (`profile/mod.rs` tests, using temp dirs and `with_config_env`):

- `./base.json` and `../shared/base.json` resolve and merge.
- A path base with a bare-name `extends` finds its own sibling.
- A symlinked directory resolves via the canonical path.
- Cycle through paths (`a -> ./b.json -> ./a.json`) errors; the same file
  reached by two spellings is detected as a cycle.
- Missing file, missing extension, `/abs.json`, `~/x.json` each error with the
  documented message.
- Path entry in a pack-store profile errors; path entry in a draft errors;
  path target inside the pack store errors.
- CLI `--extends ./x.json` resolves against the cwd, not the profile's
  directory.
- CLI `--extends ./x.json` works with a pack-store top-level profile and with a
  built-in top-level profile.
- `walk_extends_chain` follows a Path entry to the Claude pack.
- `profile init --extends ../base.json` validates relative to the output file.

Save:

- `--profile ./x.json` run updates that file: no extra question after the
  interactive selector; the existing question in the text prompt; the full path
  is printed.
- A path profile inside the pack store is not offered for update.
- Updating a `.jsonc` profile keeps comments and layout; only new entries are
  added.
- Equivalence: for a set of patches, `parse(cst_write(original))` equals
  `merge_profile_patch(parse(original), patch)`. This pins the CST field list
  to `merge_profile_patch`.
- Invalid CST output (forced) leaves the file unchanged and returns an error.

## Docs

Update `docs/cli/features/profile-authoring.mdx` ("How `extends` Works") with
path entries, the rules, and the error cases. Lead with the main pattern: a
project profile that extends the harness profile (`"extends": "claude-code"`). Update the post-run save prompt
text near line 460 of the same page with the save-target menu and which files
it offers.
