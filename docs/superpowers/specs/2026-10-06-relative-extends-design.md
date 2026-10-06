# Relative paths in `extends` (phase 1) — design

Issue: [nolabs-ai/nono#2065](https://github.com/nolabs-ai/nono/issues/2065).
Phase 2 (choose the save target on exit) is described in the issue and gets its
own spec.

## Goal

A profile can extend another profile file by a path relative to itself, so a
project can keep a shared base profile anywhere in its tree. Also fix two bugs
in the save-on-exit flow that block path-based profiles:

- Bug 3: `--profile ./x.json` cannot be updated on exit.
- Bug 4: updating a profile rewrites it with `serde_json` and strips comments.

## Entry syntax

Each `extends` entry (in a file, or from `--extends` on the CLI) is classified
once, in this order:

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
- `prepend_cli_extends` — CLI Path entries resolve against the cwd, not the
  profile's directory. Resolve them to canonical paths before they join the
  chain, so the profile's `context_dir` cannot change their meaning.
- `package_status::walk_extends_chain` (Claude Code / official pack detection)
  — it walks raw strings without a directory. It must resolve Path entries
  relative to the declaring file, using the same classify-and-resolve function.
  It must not duplicate the rules.
- `profile init --extends <path>` — write the entry as given. Validate it
  relative to the output file's directory, because that is what it means when
  loaded.
- `profile show` / `diff` / `validate` / `why` — show the raw entry as written.
  They resolve through the shared loader, so no extra logic.

One function owns classification and resolution
(`classify_extends_entry(raw, base_dir, declaring_file) -> Result<ExtendsRef>`).
Every caller above uses it.

## Bug 3: update a path profile on exit

When `profile_save_base` is a file path (`is_file_path_ref`):

- Canonicalize it. If it is inside the pack store, do not offer an update; keep
  the current new-user-profile flow.
- Otherwise offer "Update profile `<full path>`?" and write to that file, the
  same as the existing named-user-profile branch. Show the full path, because
  the file can be in a git repo.

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

## Out of scope

- Absolute and `~/` paths (reasons in the issue).
- `.json` vs `.jsonc` precedence in bare-name sibling lookup. Today sibling
  lookup checks only `.json`, and the user dir prefers `.jsonc`. Changing that
  alters existing resolution; it needs its own issue.
- Phase 2 (save to a base profile).

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
- `walk_extends_chain` follows a Path entry to the Claude pack.
- `profile init --extends ../base.json` validates relative to the output file.

Save:

- `--profile ./x.json` run offers and writes an update to that file.
- A path profile inside the pack store is not offered for update.
- Updating a `.jsonc` profile keeps comments and layout; only new entries are
  added.
- Equivalence: for a set of patches, `parse(cst_write(original))` equals
  `merge_profile_patch(parse(original), patch)`. This pins the CST field list
  to `merge_profile_patch`.
- Invalid CST output (forced) leaves the file unchanged and returns an error.

## Docs

Update `docs/cli/features/profile-authoring.mdx` ("How `extends` Works") with
path entries, the rules, and the error cases.
