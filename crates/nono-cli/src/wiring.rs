//! Declarative install-time wiring for nono packs.
//!
//! Packs that need to place files in agent-specific locations (Claude
//! Code's marketplace dirs, Codex's config.toml entries, etc) declare
//! the operations as data in their `package.json::wiring` array. The
//! CLI executes that data via a closed vocabulary of directive types.
//!
//! Design rules:
//!   - The CLI knows nothing about specific agents. The directives
//!     are agent-agnostic file ops; the pack supplies the inputs.
//!   - The vocabulary is fixed and small (6 types). New directive
//!     types require a CLI release; new agents do not.
//!   - Every directive records what it did into a `WiringRecord`,
//!     stored in the lockfile. `nono remove` replays records in
//!     reverse — the install plan never has to be re-derived.
//!   - Variables expanded at execution time: `$PACK_DIR`, `$NS`
//!     (pack namespace), `$PLUGIN` (pack name, the second segment
//!     of `<ns>/<pack>`), `$HOME`, `$XDG_CONFIG_HOME`, `$NONO_CONFIG`,
//!     `$NONO_PACKAGES`. No shell evaluation, no user-controlled inputs
//!     flow in.
//!   - Idempotent: re-running a directive with the same inputs is a
//!     no-op and reports `wiring_changed = false`.

use chrono::Utc;
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use serde_yaml_ng as yaml;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::os::unix::fs as unix_fs;
use std::path::{Path, PathBuf};

/// A single declarative wiring step. Tagged by `type` so the manifest
/// JSON reads naturally — `{ "type": "symlink", ... }`.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WiringDirective {
    /// Internal no-op produced when a manifest directive's `when`
    /// predicate does not match this host. This variant is never
    /// recorded in the lockfile.
    #[serde(skip_serializing)]
    Skipped,

    /// Create a symlink at `link` pointing to `target`. Both fields
    /// are variable-expanded. If `link` already exists as a symlink
    /// pointing at the right `target`, no-op. If it points elsewhere,
    /// it's replaced. If a real file/dir occupies the path, refuse
    /// (records as conflict, no rewrite).
    Symlink { link: String, target: String },

    /// Copy a file from inside the pack to an absolute path. `source`
    /// is a pack-relative path (no `..`, no leading `/`); `dest` is
    /// the absolute destination, variable-expanded. Mode preserved.
    WriteFile { source: String, dest: String },

    /// Read a JSON document from a pack-relative `patch` file and
    /// merge it into the JSON file at `file`. Object keys are deep-
    /// merged (last writer wins); arrays are replaced wholesale (use
    /// `JsonArrayAppend` when you need to extend an array).
    JsonMerge { file: String, patch: String },

    /// Append entries to a JSON array at `path` inside `file`. Each
    /// entry from `patch_entries` (a JSON array file in the pack) is
    /// added unless an entry already exists with a matching value at
    /// the `key_field`. Idempotent.
    JsonArrayAppend {
        file: String,
        path: String,
        patch_entries: String,
        key_field: String,
    },

    /// Insert (or replace) a fenced text block in `file`, identified
    /// by `marker_id`. Markers are derived as
    /// `# >>> nono:<marker_id> >>>` and `# <<< nono:<marker_id> <<<`.
    /// `content` is a pack-relative file holding the block body.
    /// Re-running replaces just that block; lines outside the markers
    /// are never touched.
    TomlBlock {
        file: String,
        marker_id: String,
        content: String,
    },

    /// Read a YAML mapping from a pack-relative `patch` file and
    /// merge it into the YAML file at `file`. Mapping keys are deep-
    /// merged (last writer wins); sequences are replaced wholesale
    /// (use a future `YamlArrayAppend` for additive sequence merges).
    /// Internally projects YAML onto the JSON value model so merge
    /// and reversal logic is shared with `JsonMerge`. Comments and
    /// anchors in the target file are not preserved (lossy round-
    /// trip, same as `JsonMerge` on formatting). Mapping keys must
    /// be strings; custom YAML tags are rejected.
    YamlMerge { file: String, patch: String },
}

impl<'de> Deserialize<'de> for WiringDirective {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let mut value = serde_json::Value::deserialize(deserializer)?;
        if let serde_json::Value::Object(object) = &mut value
            && let Some(when_value) = object.remove("when")
        {
            let when =
                crate::platform::When::deserialize(when_value).map_err(serde::de::Error::custom)?;
            if !crate::platform::when_matches_current(Some(&when))
                .map_err(serde::de::Error::custom)?
            {
                return Ok(Self::Skipped);
            }
        }

        // Keep this in lockstep with `WiringDirective`. The duplicate raw
        // enum lets deserialization remove manifest-only `when` before
        // applying the closed tagged directive vocabulary.
        #[derive(Deserialize)]
        #[serde(tag = "type", rename_all = "snake_case")]
        enum RawWiringDirective {
            Symlink {
                link: String,
                target: String,
            },
            WriteFile {
                source: String,
                dest: String,
            },
            JsonMerge {
                file: String,
                patch: String,
            },
            JsonArrayAppend {
                file: String,
                path: String,
                patch_entries: String,
                key_field: String,
            },
            TomlBlock {
                file: String,
                marker_id: String,
                content: String,
            },
            YamlMerge {
                file: String,
                patch: String,
            },
        }

        let raw = serde_json::from_value::<RawWiringDirective>(value)
            .map_err(serde::de::Error::custom)?;
        Ok(match raw {
            RawWiringDirective::Symlink { link, target } => Self::Symlink { link, target },
            RawWiringDirective::WriteFile { source, dest } => Self::WriteFile { source, dest },
            RawWiringDirective::JsonMerge { file, patch } => Self::JsonMerge { file, patch },
            RawWiringDirective::JsonArrayAppend {
                file,
                path,
                patch_entries,
                key_field,
            } => Self::JsonArrayAppend {
                file,
                path,
                patch_entries,
                key_field,
            },
            RawWiringDirective::TomlBlock {
                file,
                marker_id,
                content,
            } => Self::TomlBlock {
                file,
                marker_id,
                content,
            },
            RawWiringDirective::YamlMerge { file, patch } => Self::YamlMerge { file, patch },
        })
    }
}

/// What a single directive did, recorded into the lockfile so removal
/// can undo it without re-evaluating the original directive list (the
/// pack might have been updated or removed in the meantime).
///
/// Each variant carries enough information to reverse safely without
/// destroying user-owned config. Specifically:
///  - `WriteFile` stores the SHA-256 of what we wrote, so removal can
///    refuse to delete a file the user has since modified.
///  - `JsonMerge` stores per-leaf (path, prior_value) so removal can
///    restore the prior value (or delete just the leaf if it didn't
///    exist before), without taking out neighbouring keys at the same
///    parent path.
///  - `JsonArrayAppend` stores per-entry prior value when an existing
///    entry was replaced, so removal restores it instead of deleting
///    a user-owned entry that happened to share a dedup key.
///  - `YamlMerge` stores per-leaf (path, prior_value) — identical
///    semantics to `JsonMerge` but operates on YAML files via the
///    JSON value model.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WiringRecord {
    /// Symlink created (or repointed) at `link`.
    Symlink { link: String },
    /// File copied to `dest`. `sha256` is the digest of the bytes we
    /// wrote; reversal compares the on-disk content against this and
    /// only removes if it still matches (otherwise the user has
    /// modified the file and we leave it alone).
    WriteFile { dest: String, sha256: String },
    /// JSON leaves we touched in `file`. Each leaf records the JSON
    /// path (object keys), what we wrote, and what was there before
    /// (None = leaf didn't exist). Reversal walks each path: if the
    /// current value still equals `installed_value`, restore
    /// `prior_value` (or delete the leaf when `prior_value` is None);
    /// otherwise leave it alone.
    /// `created_parents` lists object paths we created to host a leaf
    /// (i.e. paths that didn't exist pre-merge); reversal prunes any
    /// of those that are still empty after leaf restoration, so we
    /// don't leave dangling `{}` placeholders on disk.
    JsonMerge {
        file: String,
        leaves: Vec<JsonLeaf>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        created_parents: Vec<Vec<String>>,
    },
    /// Entries we placed in a JSON array at `path` inside `file`,
    /// matched by `key_field`. Each entry records its dedup key and,
    /// when an existing entry was replaced rather than newly added,
    /// the original entry — so reversal restores it instead of
    /// deleting a user-owned entry that shared the dedup key.
    JsonArrayAppend {
        file: String,
        path: String,
        key_field: String,
        entries: Vec<AppendedEntry>,
    },
    /// TOML fenced block we wrote in `file` under `marker_id`.
    TomlBlock { file: String, marker_id: String },
    /// YAML leaves we touched in `file`. Uses `JsonLeaf` because
    /// the merge operates on the JSON value model internally.
    /// Reversal semantics are identical to `JsonMerge`.
    YamlMerge {
        file: String,
        leaves: Vec<JsonLeaf>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        created_parents: Vec<Vec<String>>,
    },
}

/// Per-leaf record for `JsonMerge`. `path` is the chain of object
/// keys from the document root to the leaf (e.g.
/// `["enabledPlugins", "nono@always-further"]`). `installed_value` is
/// what we wrote at that leaf; `prior_value` is what was there before
/// (None when the leaf didn't exist pre-merge).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct JsonLeaf {
    pub path: Vec<String>,
    pub installed_value: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_value: Option<Value>,
}

/// Per-entry record for `JsonArrayAppend`. `installed` is the entry
/// we placed (so reverse can verify the entry is still as we wrote it
/// before touching it — user edits are preserved). `prior` is the
/// entry that was at this dedup key before we replaced it (None for
/// newly added).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct AppendedEntry {
    pub key: String,
    pub installed: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior: Option<Value>,
}

/// Per-record reversal failure surfaced by `reverse()`. The caller
/// (`run_remove`) uses this to decide whether to keep the lockfile
/// entry intact (so the user can retry) or proceed under `--force`.
/// `record_index` is kept for diagnostic / future-tooling use even
/// though `run_remove` only consumes the human-facing summary today.
#[derive(Debug, Clone)]
pub struct ReversalFailure {
    #[allow(dead_code)]
    pub record_index: usize,
    pub record_summary: String,
    pub error: String,
}

/// Context for variable expansion — supplied by the caller, NOT by
/// pack content. Closed set, no shell evaluation.
#[derive(Debug)]
pub struct WiringContext {
    /// Absolute path of the pack inside the package store.
    pub pack_dir: PathBuf,
    /// Pack namespace (the `<ns>` in `<ns>/<pack>`).
    pub namespace: String,
    /// Pack name (the `<pack>` in `<ns>/<pack>`).
    pub pack_name: String,
}

/// Outcome of executing a directive list.
#[derive(Debug, Default)]
pub struct WiringReport {
    /// Records of every directive that ran successfully — go into
    /// the lockfile so `reverse()` knows what to undo.
    pub records: Vec<WiringRecord>,
    /// Conflicts encountered (path occupied, etc) that didn't abort
    /// but the user should know about.
    pub conflicts: Vec<String>,
    /// True if any directive actually changed disk state.
    pub changed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ExecuteOptions {
    /// Allows `WriteFile` to claim an existing unmanaged destination only when
    /// its content already exactly matches the pack source. Used for
    /// `nono pull --force` recovery after local package metadata loss.
    pub allow_unmanaged_identical_write_files: bool,
}

/// Execute a list of directives in order. Stops on hard errors; soft
/// conflicts (a real file where we'd symlink) are recorded and
/// execution continues with the next directive.
///
/// `pack_owned_files` maps absolute paths the lockfile says were
/// written by **this same pack** in a previous install to the SHA-256
/// of what we wrote. WriteFile uses this to permit overwrites of
/// files we own AND haven't been edited since (`current_hash ==
/// recorded_hash`). It refuses if the path is owned by a different
/// pack/the user (no entry) or owned by us but edited (hash
/// mismatch). Caller (`run_pull`) typically empties this map by
/// reversing prior records first — but the safety net is here.
pub fn execute(
    directives: &[WiringDirective],
    ctx: &WiringContext,
    pack_owned_files: &HashMap<PathBuf, String>,
) -> Result<WiringReport> {
    execute_with_options(directives, ctx, pack_owned_files, ExecuteOptions::default())
}

pub fn execute_with_options(
    directives: &[WiringDirective],
    ctx: &WiringContext,
    pack_owned_files: &HashMap<PathBuf, String>,
    options: ExecuteOptions,
) -> Result<WiringReport> {
    let mut report = WiringReport::default();
    for directive in directives {
        execute_one(directive, ctx, pack_owned_files, options, &mut report)?;
    }
    Ok(report)
}

fn execute_one(
    directive: &WiringDirective,
    ctx: &WiringContext,
    pack_owned_files: &HashMap<PathBuf, String>,
    options: ExecuteOptions,
    report: &mut WiringReport,
) -> Result<()> {
    match directive {
        WiringDirective::Skipped => {}
        WiringDirective::Symlink { link, target } => {
            let link_path = expand_to_path(link, ctx)?;
            let target_path = expand_to_path(target, ctx)?;
            match ensure_symlink(&link_path, &target_path)? {
                SymlinkOutcome::Created | SymlinkOutcome::Repointed => {
                    report.changed = true;
                    report.records.push(WiringRecord::Symlink {
                        link: link_path.to_string_lossy().into_owned(),
                    });
                }
                SymlinkOutcome::AlreadyCorrect => {
                    // Still record so removal knows we own it.
                    report.records.push(WiringRecord::Symlink {
                        link: link_path.to_string_lossy().into_owned(),
                    });
                }
                SymlinkOutcome::Conflict(msg) => {
                    report.conflicts.push(msg);
                }
            }
        }
        WiringDirective::WriteFile { source, dest } => {
            let source_path = pack_relative(source, ctx)?;
            let dest_path = expand_to_path(dest, ctx)?;
            // Conflict policy (security review fix). If the dest
            // exists, decide based on ownership:
            //   - Not in pack_owned_files → refuse (user/other pack
            //     owns it; we never overwrite).
            //   - In pack_owned_files but on-disk content has been
            //     edited since we wrote it → refuse (user has made
            //     changes and we mustn't clobber them).
            //   - In pack_owned_files and content matches → overwrite
            //     freely (true idempotent re-pull).
            if dest_path.exists() {
                let recorded_hash = pack_owned_files.get(&dest_path);
                let current_hash = match fs::read(&dest_path) {
                    Ok(b) => hash_bytes(&b),
                    Err(e) => return Err(NonoError::Io(e)),
                };
                match recorded_hash {
                    None => {
                        let source_hash = match fs::read(&source_path) {
                            Ok(bytes) => hash_bytes(&bytes),
                            Err(e) => return Err(NonoError::Io(e)),
                        };
                        if !options.allow_unmanaged_identical_write_files
                            || source_hash != current_hash
                        {
                            return Err(NonoError::PackageInstall(format!(
                                "write_file: refusing to overwrite '{}' — \
                                 file already exists and was not written by a \
                                 managed pack. Move/remove it manually then re-pull.",
                                dest_path.display()
                            )));
                        }
                    }
                    Some(prior) if prior != &current_hash => {
                        return Err(NonoError::PackageInstall(format!(
                            "write_file: refusing to overwrite '{}' — \
                             file has been edited since the last install \
                             (sha256 mismatch). Either revert your changes \
                             then re-pull, or `nono remove` this pack first.",
                            dest_path.display()
                        )));
                    }
                    _ => {}
                }
            }
            let outcome = copy_file_atomic(&source_path, &dest_path)?;
            if outcome.mutated {
                report.changed = true;
            }
            report.records.push(WiringRecord::WriteFile {
                dest: dest_path.to_string_lossy().into_owned(),
                sha256: outcome.sha256,
            });
        }
        WiringDirective::JsonMerge { file, patch } => {
            let file_path = expand_to_path(file, ctx)?;
            let patch_path = pack_relative(patch, ctx)?;
            let patch_value = read_pack_json(&patch_path, ctx)?;
            let outcome = merge_json_into_file(&file_path, &patch_value)?;
            if outcome.leaves.iter().any(leaf_changed_disk) || !outcome.created_parents.is_empty() {
                report.changed = true;
            }
            report.records.push(WiringRecord::JsonMerge {
                file: file_path.to_string_lossy().into_owned(),
                leaves: outcome.leaves,
                created_parents: outcome.created_parents,
            });
        }
        WiringDirective::JsonArrayAppend {
            file,
            path,
            patch_entries,
            key_field,
        } => {
            let file_path = expand_to_path(file, ctx)?;
            let entries_path = pack_relative(patch_entries, ctx)?;
            let entries_value = read_pack_json(&entries_path, ctx)?;
            let entries = entries_value.as_array().ok_or_else(|| {
                NonoError::PackageInstall(format!(
                    "json_array_append: {} must be a JSON array",
                    entries_path.display()
                ))
            })?;
            let outcome = append_json_entries(&file_path, path, entries, key_field)?;
            if outcome.mutated {
                report.changed = true;
            }
            report.records.push(WiringRecord::JsonArrayAppend {
                file: file_path.to_string_lossy().into_owned(),
                path: path.clone(),
                key_field: key_field.clone(),
                entries: outcome.entries,
            });
        }
        WiringDirective::TomlBlock {
            file,
            marker_id,
            content,
        } => {
            let file_path = expand_to_path(file, ctx)?;
            let content_path = pack_relative(content, ctx)?;
            let raw_body = fs::read_to_string(&content_path).map_err(NonoError::Io)?;
            // Expand `$VAR` placeholders inside the body so packs can
            // declare absolute paths (e.g. `source = "$HOME/.codex/..."`)
            // without committing user-specific paths to the registry.
            let body = expand_vars(&raw_body, ctx)?;
            let changed = upsert_toml_block(&file_path, marker_id, &body)?;
            if changed {
                report.changed = true;
            }
            report.records.push(WiringRecord::TomlBlock {
                file: file_path.to_string_lossy().into_owned(),
                marker_id: marker_id.clone(),
            });
        }
        WiringDirective::YamlMerge { file, patch } => {
            let file_path = expand_to_path(file, ctx)?;
            let patch_path = pack_relative(patch, ctx)?;
            let patch_value = read_pack_yaml(&patch_path, ctx)?;
            let outcome = merge_yaml_into_file(&file_path, &patch_value)?;
            if outcome.leaves.iter().any(leaf_changed_disk) || !outcome.created_parents.is_empty() {
                report.changed = true;
            }
            report.records.push(WiringRecord::YamlMerge {
                file: file_path.to_string_lossy().into_owned(),
                leaves: outcome.leaves,
                created_parents: outcome.created_parents,
            });
        }
    }
    Ok(())
}

/// Replay a record list in reverse, undoing each. Returns a list of
/// per-record failures so callers can decide whether to keep the
/// lockfile entry intact for retry.
///
/// Each record is attempted independently — one failure does not stop
/// later reversals from running. A missing file or already-removed
/// key is treated as success (idempotent), but a permission error or
/// content-mismatch is a real failure that surfaces here.
pub fn reverse(records: &[WiringRecord]) -> Vec<ReversalFailure> {
    let mut failures = Vec::new();
    for (i, record) in records.iter().enumerate().rev() {
        if let Err(e) = reverse_one(record) {
            failures.push(ReversalFailure {
                record_index: i,
                record_summary: summarise_record(record),
                error: e.to_string(),
            });
        }
    }
    failures
}

fn summarise_record(record: &WiringRecord) -> String {
    match record {
        WiringRecord::Symlink { link } => format!("symlink {link}"),
        WiringRecord::WriteFile { dest, .. } => format!("write_file {dest}"),
        WiringRecord::JsonMerge { file, .. } => format!("json_merge {file}"),
        WiringRecord::JsonArrayAppend { file, path, .. } => {
            format!("json_array_append {file} at {path}")
        }
        WiringRecord::TomlBlock { file, marker_id } => {
            format!("toml_block {file} #{marker_id}")
        }
        WiringRecord::YamlMerge { file, .. } => format!("yaml_merge {file}"),
    }
}

fn reverse_one(record: &WiringRecord) -> Result<()> {
    match record {
        WiringRecord::Symlink { link } => {
            let path = Path::new(link);
            if let Ok(meta) = path.symlink_metadata()
                && meta.file_type().is_symlink()
            {
                fs::remove_file(path).map_err(NonoError::Io)?;
            }
        }
        WiringRecord::WriteFile { dest, sha256 } => {
            // Only remove if the on-disk content still matches what
            // we wrote — otherwise the user has modified it and we
            // leave it alone (security review fix).
            let path = Path::new(dest);
            if !path.exists() {
                return Ok(());
            }
            let bytes = fs::read(path).map_err(NonoError::Io)?;
            if hash_bytes(&bytes) != *sha256 {
                tracing::info!(
                    "write_file: leaving '{}' in place — content has been \
                     modified since install (sha256 mismatch).",
                    path.display()
                );
                return Ok(());
            }
            fs::remove_file(path).map_err(NonoError::Io)?;
        }
        WiringRecord::JsonMerge {
            file,
            leaves,
            created_parents,
        } => {
            restore_json_leaves(Path::new(file), leaves, created_parents)?;
        }
        WiringRecord::JsonArrayAppend {
            file,
            path,
            key_field,
            entries,
        } => {
            restore_json_array_entries(Path::new(file), path, key_field, entries)?;
        }
        WiringRecord::TomlBlock { file, marker_id } => {
            strip_toml_block(Path::new(file), marker_id)?;
        }
        WiringRecord::YamlMerge {
            file,
            leaves,
            created_parents,
        } => {
            restore_yaml_leaves(Path::new(file), leaves, created_parents)?;
        }
    }
    Ok(())
}

fn hash_bytes(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

/// True if a leaf record represents a real disk change (i.e. either
/// we created the leaf, or we changed an existing one). Used by
/// `WiringReport::changed`.
fn leaf_changed_disk(leaf: &JsonLeaf) -> bool {
    leaf.prior_value.as_ref() != Some(&leaf.installed_value)
}

// ---------------------------------------------------------------------------
// Variable expansion + path validation
// ---------------------------------------------------------------------------

/// Expand `$VAR` placeholders in a string against the closed set of
/// allowed variables, then return as a path. Refuses unknown variables
/// and `..` traversal.
fn expand_to_path(template: &str, ctx: &WiringContext) -> Result<PathBuf> {
    let expanded = expand_vars(template, ctx)?;
    let path = PathBuf::from(&expanded);
    if path
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(NonoError::PackageInstall(format!(
            "wiring path contains '..': '{template}'"
        )));
    }
    Ok(path)
}

/// Resolve a pack-relative path safely (no escape via `..`, no
/// absolute paths).
fn pack_relative(rel: &str, ctx: &WiringContext) -> Result<PathBuf> {
    let p = Path::new(rel);
    if p.is_absolute() {
        return Err(NonoError::PackageInstall(format!(
            "wiring source must be pack-relative, got '{rel}'"
        )));
    }
    if p.components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(NonoError::PackageInstall(format!(
            "wiring source contains '..': '{rel}'"
        )));
    }
    Ok(ctx.pack_dir.join(p))
}

fn expand_vars(template: &str, ctx: &WiringContext) -> Result<String> {
    let home = xdg_home::home_dir()
        .ok_or_else(|| NonoError::PackageInstall("HOME not set".to_string()))?;
    let xdg_config_home = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| home.join(".config"));
    let nono_config = crate::package::nono_config_dir()
        .map_err(|e| NonoError::PackageInstall(format!("failed to resolve $NONO_CONFIG: {e}")))?;
    let nono_packages = crate::package::package_store_dir()
        .map_err(|e| NonoError::PackageInstall(format!("failed to resolve $NONO_PACKAGES: {e}")))?;

    let pack_dir = ctx.pack_dir.to_string_lossy().into_owned();
    let home_str = home.to_string_lossy().into_owned();
    let xdg_str = xdg_config_home.to_string_lossy().into_owned();
    let nono_config_str = nono_config.to_string_lossy().into_owned();
    let nono_packages_str = nono_packages.to_string_lossy().into_owned();

    // `$` is a variable sigil only when followed by an ASCII uppercase
    // letter or underscore — i.e. the start of an identifier from the
    // closed set below. Any other `$` (regex end-anchor `$`, a literal
    // dollar sign in a comment, jq's `$var` lowercase) is passed
    // through untouched. This keeps pack content like
    // `"matcher": "^(Bash|apply_patch)$"` from needing a `$$` escape.
    let mut out = String::with_capacity(template.len());
    let mut chars = template.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '$' {
            out.push(c);
            continue;
        }
        match chars.peek() {
            Some(&p) if p.is_ascii_uppercase() || p == '_' => {}
            _ => {
                out.push('$');
                continue;
            }
        }
        let mut name = String::new();
        while let Some(&peek) = chars.peek() {
            if peek.is_ascii_alphanumeric() || peek == '_' {
                name.push(peek);
                chars.next();
            } else {
                break;
            }
        }
        let value = match name.as_str() {
            "PACK_DIR" => pack_dir.clone(),
            "NS" => ctx.namespace.clone(),
            "PLUGIN" => ctx.pack_name.clone(),
            "HOME" => home_str.clone(),
            "XDG_CONFIG_HOME" => xdg_str.clone(),
            "NONO_CONFIG" => nono_config_str.clone(),
            "NONO_PACKAGES" => nono_packages_str.clone(),
            // Install-time UTC timestamp (RFC3339, milliseconds), for
            // agents that require a `lastUpdated`-style field on their
            // config entries (Claude Code's marketplace registry being
            // the case that drove this in). Resolved per call so each
            // expansion within a single install carries the same
            // monotonic value.
            "NOW" => Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string(),
            other => {
                return Err(NonoError::PackageInstall(format!(
                    "wiring template references unknown variable '${other}' in '{template}'"
                )));
            }
        };
        out.push_str(&value);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Symlink primitive
// ---------------------------------------------------------------------------

enum SymlinkOutcome {
    Created,
    Repointed,
    AlreadyCorrect,
    Conflict(String),
}

fn ensure_symlink(link: &Path, target: &Path) -> Result<SymlinkOutcome> {
    if let Some(parent) = link.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    match link.symlink_metadata() {
        Ok(meta) => {
            if !meta.file_type().is_symlink() {
                return Ok(SymlinkOutcome::Conflict(format!(
                    "{} exists and is not a nono-managed symlink — leaving it alone",
                    link.display()
                )));
            }
            let current = fs::read_link(link).map_err(NonoError::Io)?;
            if current == target {
                return Ok(SymlinkOutcome::AlreadyCorrect);
            }
            fs::remove_file(link).map_err(NonoError::Io)?;
            unix_fs::symlink(target, link).map_err(NonoError::Io)?;
            Ok(SymlinkOutcome::Repointed)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            unix_fs::symlink(target, link).map_err(NonoError::Io)?;
            Ok(SymlinkOutcome::Created)
        }
        Err(e) => Err(NonoError::Io(e)),
    }
}

// ---------------------------------------------------------------------------
// File copy primitive
// ---------------------------------------------------------------------------

struct CopyOutcome {
    mutated: bool,
    sha256: String,
}

fn copy_file_atomic(source: &Path, dest: &Path) -> Result<CopyOutcome> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let source_bytes = fs::read(source).map_err(NonoError::Io)?;
    let sha256 = hash_bytes(&source_bytes);
    // Skip-no-op only if existing content matches exactly. Caller has
    // already enforced the conflict policy (only owned files reach
    // here when dest exists), so a hash match is a real no-op re-pull.
    if let Ok(existing) = fs::read(dest)
        && existing == source_bytes
    {
        return Ok(CopyOutcome {
            mutated: false,
            sha256,
        });
    }
    let tmp = dest.with_extension("nono-tmp");
    fs::write(&tmp, &source_bytes).map_err(NonoError::Io)?;
    fs::rename(&tmp, dest).map_err(NonoError::Io)?;
    Ok(CopyOutcome {
        mutated: true,
        sha256,
    })
}

// ---------------------------------------------------------------------------
// JSON merge / append primitives
// ---------------------------------------------------------------------------

fn read_json(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    crate::jsonc::parse(&content)
        .map_err(|e| NonoError::PackageInstall(format!("invalid JSON in {}: {e}", path.display())))
}

/// Read a JSON file shipped inside the pack and expand `$VAR`
/// placeholders inside string values (recursively, including inside
/// arrays and nested objects). Used for `JsonMerge` and
/// `JsonArrayAppend` patch files so packs can declare paths like
/// `"$HOME/.claude/plugins/marketplaces/$NS"` inside the JSON
/// content. Object keys are NOT expanded — they're treated as
/// literal identifiers so a user-controlled value can't accidentally
/// rewrite a key path.
fn read_pack_json(path: &Path, ctx: &WiringContext) -> Result<Value> {
    let mut value = read_json(path)?;
    expand_json_strings(&mut value, ctx)?;
    Ok(value)
}

fn expand_json_strings(value: &mut Value, ctx: &WiringContext) -> Result<()> {
    match value {
        Value::String(s) if s.contains('$') => {
            *s = expand_vars(s, ctx)?;
        }
        Value::String(_) => {}
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                expand_json_strings(v, ctx)?;
            }
        }
        Value::Object(obj) => {
            for (_k, v) in obj.iter_mut() {
                expand_json_strings(v, ctx)?;
            }
        }
        _ => {}
    }
    Ok(())
}

struct MergeOutcome {
    leaves: Vec<JsonLeaf>,
    created_parents: Vec<Vec<String>>,
}

/// Deep-merge `patch` into the JSON document at `file`, walking down
/// to non-object leaves. Returns one `JsonLeaf` per leaf the patch
/// touched, recording the path, the value we wrote, and the value
/// that was at that path before (None if it didn't exist). Also
/// returns `created_parents` — object paths that didn't exist before
/// the merge, so reversal can prune them after restoring leaves.
/// Together these prevent removal from disturbing neighbouring keys
/// at the same parent (security review fix).
///
/// "Leaf" here means: any value in the patch that is not a JSON
/// object. Arrays count as leaves and are written wholesale —
/// `JsonArrayAppend` is the directive for additive array merges.
fn merge_json_into_file(file: &Path, patch: &Value) -> Result<MergeOutcome> {
    let mut existing = if file.exists() {
        read_json(file)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    if !patch.is_object() || !existing.is_object() {
        return Err(NonoError::PackageInstall(format!(
            "json_merge: {} must be a JSON object at the root",
            file.display()
        )));
    }
    let before = existing.clone();
    let mut leaves = Vec::new();
    let mut created_parents = Vec::new();
    walk_and_merge(
        &mut existing,
        patch,
        &mut Vec::new(),
        &mut leaves,
        &mut created_parents,
    );
    if existing != before {
        write_json(file, &existing)?;
    }
    Ok(MergeOutcome {
        leaves,
        created_parents,
    })
}

/// Recursive walk: descend through both `target` and `patch` together;
/// at every leaf in `patch`, write to `target` and record what was
/// there before. `path` is the current chain of object keys. When a
/// patch object descends through a target key that didn't exist, the
/// newly-created parent path is recorded so reversal can prune it.
fn walk_and_merge(
    target: &mut Value,
    patch: &Value,
    path: &mut Vec<String>,
    leaves: &mut Vec<JsonLeaf>,
    created_parents: &mut Vec<Vec<String>>,
) {
    if let (Value::Object(dst), Value::Object(src)) = (target, patch) {
        for (k, v) in src {
            path.push(k.clone());
            if v.is_object() {
                let parent_existed = dst.contains_key(k);
                let entry = dst
                    .entry(k.clone())
                    .or_insert_with(|| Value::Object(serde_json::Map::new()));
                if !entry.is_object() {
                    // Patch wants to descend but target has a
                    // non-object here — record the whole subtree as
                    // a single leaf replacement.
                    let prior = Some(entry.clone());
                    *entry = v.clone();
                    leaves.push(JsonLeaf {
                        path: path.clone(),
                        installed_value: v.clone(),
                        prior_value: prior,
                    });
                } else {
                    if !parent_existed {
                        created_parents.push(path.clone());
                    }
                    walk_and_merge(entry, v, path, leaves, created_parents);
                }
            } else {
                let prior = dst.get(k).cloned();
                dst.insert(k.clone(), v.clone());
                leaves.push(JsonLeaf {
                    path: path.clone(),
                    installed_value: v.clone(),
                    prior_value: prior,
                });
            }
            path.pop();
        }
    }
}

/// Append entries to the JSON array at `path` inside `file`. `path`
/// is dot-separated (e.g. `hooks.PostToolUse`). `key_field` is also
/// dot-separated; walking from each entry's root it should resolve to
/// a string used for dedup (e.g. `hooks.0.command` to dedup by the
/// first hook's command path). Returns the list of dedup keys actually
/// appended — paired with `key_field` and `path`, the inverse can
/// filter exactly those entries back out on removal.
/// Outcome of `append_json_entries`. `entries` records what we wrote
/// (and any pre-existing entry we replaced) so `nono remove` can
/// restore the prior state instead of blindly deleting. `mutated` is
/// whether the file's contents actually changed — false for a no-op
/// idempotent re-run.
struct AppendOutcome {
    entries: Vec<AppendedEntry>,
    mutated: bool,
}

fn append_json_entries(
    file: &Path,
    path: &str,
    entries: &[Value],
    key_field: &str,
) -> Result<AppendOutcome> {
    let mut doc = if file.exists() {
        read_json(file)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    let before = doc.clone();
    let array = ensure_array_at(&mut doc, path)?;
    let mut applied = Vec::new();
    for entry in entries {
        let Some(key) = extract_string_at(entry, key_field) else {
            return Err(NonoError::PackageInstall(format!(
                "json_array_append: entry has no string at key_field '{key_field}'"
            )));
        };
        let key_owned = key.to_string();
        // Replace-in-place if the dedup key already matches an entry —
        // pack re-publishes that add or change fields (e.g. flipping
        // `silent: true` on a hook) need the new shape to win, not the
        // pre-existing entry. We record the prior entry so reversal
        // can restore it (security review fix: a user-owned entry
        // that happened to share a dedup key must not be wiped on
        // uninstall). Pure idempotency (identical re-run) is preserved
        // by the `mutated` check below.
        let mut prior_value: Option<Value> = None;
        let mut replaced = false;
        for existing in array.iter_mut() {
            if extract_string_at(existing, key_field) == Some(key) {
                prior_value = Some(existing.clone());
                *existing = entry.clone();
                replaced = true;
                break;
            }
        }
        if !replaced {
            array.push(entry.clone());
        }
        applied.push(AppendedEntry {
            key: key_owned,
            installed: entry.clone(),
            prior: prior_value,
        });
    }
    let mutated = doc != before;
    if mutated {
        write_json(file, &doc)?;
    }
    Ok(AppendOutcome {
        entries: applied,
        mutated,
    })
}

/// Walk `value` along a dot-separated path. Numeric segments index
/// arrays. Returns `None` if any segment doesn't exist or the leaf
/// isn't a string.
fn extract_string_at<'a>(value: &'a Value, path: &str) -> Option<&'a str> {
    let mut cursor = value;
    for seg in path.split('.') {
        cursor = if let Ok(idx) = seg.parse::<usize>() {
            cursor.as_array().and_then(|arr| arr.get(idx))?
        } else {
            cursor.as_object().and_then(|obj| obj.get(seg))?
        };
    }
    cursor.as_str()
}

/// Walk `doc` along `path` (dot-separated), creating empty objects
/// along the way; ensure the leaf is a JSON array and return a
/// mutable reference to it.
fn ensure_array_at<'a>(doc: &'a mut Value, path: &str) -> Result<&'a mut Vec<Value>> {
    let segments: Vec<&str> = path.split('.').collect();
    let mut cursor = doc;
    for (i, seg) in segments.iter().enumerate() {
        let is_last = i == segments.len() - 1;
        let obj = cursor.as_object_mut().ok_or_else(|| {
            NonoError::PackageInstall(format!("json_array_append: '{path}' traverses non-object"))
        })?;
        if is_last {
            let entry = obj
                .entry(seg.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            return entry.as_array_mut().ok_or_else(|| {
                NonoError::PackageInstall(format!("json_array_append: '{path}' is not an array"))
            });
        }
        cursor = obj
            .entry(seg.to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
    }
    unreachable!("segments has at least one element")
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let pretty = serde_json::to_string_pretty(value)
        .map_err(|e| NonoError::PackageInstall(format!("serialize {}: {e}", path.display())))?;
    let tmp = path.with_extension("json.nono-tmp");
    fs::write(&tmp, format!("{pretty}\n")).map_err(NonoError::Io)?;
    fs::rename(&tmp, path).map_err(NonoError::Io)?;
    Ok(())
}

/// Reverse of `merge_json_into_file`: walk each recorded leaf path.
/// For each leaf, only act if the current value at that path still
/// equals what we wrote — that proves nobody has touched our merge
/// since install. Restore the prior value, or delete the leaf when
/// there was no prior value. Empty parent objects we created are
/// pruned only when they contain nothing we did not place.
///
/// Behaviour matrix per leaf:
///   current == installed_value  → restore prior (or delete if None)
///   current != installed_value  → leave alone (user/another pack
///                                  modified it; respect their state)
///   leaf missing                → no-op (already gone)
fn restore_json_leaves(
    file: &Path,
    leaves: &[JsonLeaf],
    created_parents: &[Vec<String>],
) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let mut doc = read_json(file)?;
    let mut changed = false;
    // Reverse-order traversal so deeper leaves run before their
    // parents — lets us prune emptied parent objects bottom-up.
    for leaf in leaves.iter().rev() {
        if restore_one_leaf(
            &mut doc,
            &leaf.path,
            &leaf.installed_value,
            &leaf.prior_value,
        ) {
            changed = true;
        }
    }
    // Prune parents we created during install IF they're empty now
    // (i.e. all our leaves under them were restored/removed). Sort
    // deepest-first so we prune child paths before their ancestors.
    let mut sorted_parents: Vec<&Vec<String>> = created_parents.iter().collect();
    sorted_parents.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for parent_path in sorted_parents {
        if prune_empty_object_at(&mut doc, parent_path) {
            changed = true;
        }
    }
    if changed {
        write_json(file, &doc)?;
    }
    Ok(())
}

/// Remove the object at `path` from `doc` if and only if it's
/// currently an empty object. No-op if the path is missing or
/// non-empty (user added their own keys under our parent — we leave
/// them alone).
fn prune_empty_object_at(doc: &mut Value, path: &[String]) -> bool {
    if path.is_empty() {
        return false;
    }
    let mut cursor: &mut Value = doc;
    for seg in &path[..path.len() - 1] {
        let Some(next) = cursor.as_object_mut().and_then(|o| o.get_mut(seg)) else {
            return false;
        };
        cursor = next;
    }
    let Some(parent) = cursor.as_object_mut() else {
        return false;
    };
    let leaf_key = &path[path.len() - 1];
    let is_empty_object = parent
        .get(leaf_key)
        .and_then(Value::as_object)
        .map(|o| o.is_empty())
        .unwrap_or(false);
    if is_empty_object {
        parent.remove(leaf_key);
        true
    } else {
        false
    }
}

/// Restore one leaf in `doc`. Returns true if a change was applied.
fn restore_one_leaf(
    doc: &mut Value,
    path: &[String],
    installed: &Value,
    prior: &Option<Value>,
) -> bool {
    if path.is_empty() {
        return false;
    }
    // Walk to the parent of the leaf. Bail (no-op) if any segment
    // along the way is absent or non-object.
    let mut cursor: &mut Value = doc;
    for seg in &path[..path.len() - 1] {
        let Some(next) = cursor.as_object_mut().and_then(|o| o.get_mut(seg)) else {
            return false;
        };
        cursor = next;
    }
    let Some(parent) = cursor.as_object_mut() else {
        return false;
    };
    let leaf_key = &path[path.len() - 1];
    match parent.get(leaf_key) {
        None => false,
        Some(current) if current == installed => match prior {
            Some(p) => {
                parent.insert(leaf_key.clone(), p.clone());
                true
            }
            None => {
                parent.remove(leaf_key);
                true
            }
        },
        Some(_) => false, // user/another pack modified it; leave alone
    }
}

/// Reverse of `append_json_entries`: walk to the array and for each
/// recorded entry, only act if the current entry at that key still
/// equals the installed shape (security review fix — a user edit
/// post-install must be preserved). If equal:
///
///   - prior is Some → restore the prior entry (we replaced it).
///   - prior is None → drop the entry (we added it).
///
/// If the current entry differs from installed (user edited it) or
/// the key is no longer present, leave the array alone for that key.
fn restore_json_array_entries(
    file: &Path,
    path: &str,
    key_field: &str,
    entries: &[AppendedEntry],
) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let mut doc = read_json(file)?;
    let Ok(array) = ensure_array_at(&mut doc, path) else {
        return Ok(());
    };
    let mut changed = false;
    // Build a quick lookup keyed by dedup key: (installed, prior).
    let by_key: BTreeMap<&str, (&Value, Option<&Value>)> = entries
        .iter()
        .map(|e| (e.key.as_str(), (&e.installed, e.prior.as_ref())))
        .collect();
    let mut new_array: Vec<Value> = Vec::with_capacity(array.len());
    for entry in array.drain(..) {
        let key = extract_string_at(&entry, key_field);
        let action = key.and_then(|k| by_key.get(k).copied());
        match action {
            Some((installed, prior)) if &entry == installed => {
                // We placed this and it hasn't been touched.
                if let Some(p) = prior {
                    new_array.push((*p).clone());
                }
                changed = true;
            }
            _ => new_array.push(entry), // user edit OR not ours
        }
    }
    *array = new_array;
    if changed {
        write_json(file, &doc)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// YAML merge primitives
// ---------------------------------------------------------------------------

/// Convert a `serde_yaml_ng::Value` to a `serde_json::Value` so that
/// the shared `walk_and_merge` / `restore_one_leaf` /
/// `prune_empty_object_at` logic can be reused unchanged.
///
/// Strict rules per Luke's design:
///   - Mapping keys must be strings (non-string keys → error).
///   - Custom YAML tags (`!foo value`) → error.
fn yaml_to_json(v: yaml::Value) -> Result<Value> {
    match v {
        yaml::Value::Null => Ok(Value::Null),
        yaml::Value::Bool(b) => Ok(Value::Bool(b)),
        yaml::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(Value::Number(i.into()))
            } else if let Some(u) = n.as_u64() {
                Ok(Value::Number(u.into()))
            } else if let Some(f) = n.as_f64() {
                // Reject non-finite values (.inf, -.inf, .nan): JSON has no
                // representation for them and silently coercing to null would
                // corrupt the user's file on the write-back.
                serde_json::Number::from_f64(f)
                    .map(Value::Number)
                    .ok_or_else(|| {
                        NonoError::PackageInstall(
                            "yaml_merge: non-finite float (.inf/.nan) is not representable \
                         in the JSON value model; use a string instead"
                                .to_string(),
                        )
                    })
            } else {
                Err(NonoError::PackageInstall(
                    "yaml_merge: unrepresentable number in YAML".to_string(),
                ))
            }
        }
        yaml::Value::String(s) => Ok(Value::String(s)),
        yaml::Value::Sequence(seq) => {
            let arr: Result<Vec<Value>> = seq.into_iter().map(yaml_to_json).collect();
            Ok(Value::Array(arr?))
        }
        yaml::Value::Mapping(map) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in map {
                let key = match k {
                    yaml::Value::String(s) => s,
                    other => {
                        return Err(NonoError::PackageInstall(format!(
                            "yaml_merge: mapping key must be a string, got {:?}",
                            other
                        )));
                    }
                };
                obj.insert(key, yaml_to_json(v)?);
            }
            Ok(Value::Object(obj))
        }
        yaml::Value::Tagged(_) => Err(NonoError::PackageInstall(
            "yaml_merge: custom YAML tags are not supported".to_string(),
        )),
    }
}

/// Convert a `serde_json::Value` back to `serde_yaml_ng::Value` for
/// writing. All JSON value types map cleanly to YAML; no information
/// is lost (though YAML comments and anchors from the original file
/// are already gone at this point — lossy round-trip, same as
/// `JsonMerge` on formatting).
fn json_to_yaml(v: Value) -> yaml::Value {
    match v {
        Value::Null => yaml::Value::Null,
        Value::Bool(b) => yaml::Value::Bool(b),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                yaml::Value::Number(i.into())
            } else if let Some(u) = n.as_u64() {
                yaml::Value::Number(u.into())
            } else if let Some(f) = n.as_f64() {
                yaml::Value::Number(f.into())
            } else {
                yaml::Value::String(n.to_string())
            }
        }
        Value::String(s) => yaml::Value::String(s),
        Value::Array(arr) => yaml::Value::Sequence(arr.into_iter().map(json_to_yaml).collect()),
        Value::Object(obj) => {
            let mut map = yaml::Mapping::new();
            for (k, v) in obj {
                map.insert(yaml::Value::String(k), json_to_yaml(v));
            }
            yaml::Value::Mapping(map)
        }
    }
}

fn read_yaml(path: &Path) -> Result<Value> {
    let content = fs::read_to_string(path).map_err(NonoError::Io)?;
    let yaml_val: yaml::Value = yaml::from_str(&content).map_err(|e| {
        NonoError::PackageInstall(format!("invalid YAML in {}: {e}", path.display()))
    })?;
    yaml_to_json(yaml_val)
}

fn read_pack_yaml(path: &Path, ctx: &WiringContext) -> Result<Value> {
    let mut value = read_yaml(path)?;
    expand_json_strings(&mut value, ctx)?;
    Ok(value)
}

fn write_yaml(path: &Path, value: &Value) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let yaml_val = json_to_yaml(value.clone());
    let serialized = yaml::to_string(&yaml_val)
        .map_err(|e| NonoError::PackageInstall(format!("serialize {}: {e}", path.display())))?;
    let tmp = path.with_extension("yaml.nono-tmp");
    fs::write(&tmp, &serialized).map_err(NonoError::Io)?;
    fs::rename(&tmp, path).map_err(NonoError::Io)?;
    Ok(())
}

fn merge_yaml_into_file(file: &Path, patch: &Value) -> Result<MergeOutcome> {
    let mut existing = if file.exists() {
        read_yaml(file)?
    } else {
        Value::Object(serde_json::Map::new())
    };
    if !patch.is_object() || !existing.is_object() {
        return Err(NonoError::PackageInstall(format!(
            "yaml_merge: {} must be a YAML mapping at the root",
            file.display()
        )));
    }
    let before = existing.clone();
    let mut leaves = Vec::new();
    let mut created_parents = Vec::new();
    walk_and_merge(
        &mut existing,
        patch,
        &mut Vec::new(),
        &mut leaves,
        &mut created_parents,
    );
    if existing != before {
        write_yaml(file, &existing)?;
    }
    Ok(MergeOutcome {
        leaves,
        created_parents,
    })
}

/// Reverse of `merge_yaml_into_file`: identical logic to
/// `restore_json_leaves` but reads/writes the file as YAML.
fn restore_yaml_leaves(
    file: &Path,
    leaves: &[JsonLeaf],
    created_parents: &[Vec<String>],
) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let mut doc = read_yaml(file)?;
    let mut changed = false;
    for leaf in leaves.iter().rev() {
        if restore_one_leaf(
            &mut doc,
            &leaf.path,
            &leaf.installed_value,
            &leaf.prior_value,
        ) {
            changed = true;
        }
    }
    let mut sorted_parents: Vec<&Vec<String>> = created_parents.iter().collect();
    sorted_parents.sort_by_key(|p| std::cmp::Reverse(p.len()));
    for parent_path in sorted_parents {
        if prune_empty_object_at(&mut doc, parent_path) {
            changed = true;
        }
    }
    if changed {
        write_yaml(file, &doc)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TOML fenced block primitive
// ---------------------------------------------------------------------------

fn block_markers(marker_id: &str) -> (String, String) {
    (
        format!("# >>> nono:{marker_id} >>>"),
        format!("# <<< nono:{marker_id} <<<"),
    )
}

/// Insert or replace a fenced block in `file`. Pure text edit — no
/// TOML parser, since we own the markers exactly. Returns true if
/// disk content changed.
fn upsert_toml_block(file: &Path, marker_id: &str, body: &str) -> Result<bool> {
    let (begin, end) = block_markers(marker_id);
    let existing = fs::read_to_string(file).unwrap_or_default();
    let new_block = format!("{begin}\n{}{end}\n", ensure_trailing_newline(body));

    let updated = match find_block_bounds(&existing, &begin, &end) {
        Some((s, e)) => {
            let mut out = String::with_capacity(existing.len() + new_block.len());
            out.push_str(&existing[..s]);
            out.push_str(&new_block);
            out.push_str(&existing[e..]);
            out
        }
        None => {
            let mut out = existing.clone();
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            if !out.is_empty() && !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push_str(&new_block);
            out
        }
    };

    if updated == existing {
        return Ok(false);
    }
    if let Some(parent) = file.parent() {
        fs::create_dir_all(parent).map_err(NonoError::Io)?;
    }
    let tmp = file.with_extension("toml.nono-tmp");
    fs::write(&tmp, &updated).map_err(NonoError::Io)?;
    fs::rename(&tmp, file).map_err(NonoError::Io)?;
    Ok(true)
}

fn strip_toml_block(file: &Path, marker_id: &str) -> Result<()> {
    if !file.exists() {
        return Ok(());
    }
    let (begin, end) = block_markers(marker_id);
    let existing = fs::read_to_string(file).map_err(NonoError::Io)?;
    let Some((s, e)) = find_block_bounds(&existing, &begin, &end) else {
        return Ok(());
    };
    let mut out = String::with_capacity(existing.len());
    out.push_str(&existing[..s]);
    out.push_str(&existing[e..]);
    if out.ends_with("\n\n") {
        out.pop();
    }
    let tmp = file.with_extension("toml.nono-tmp");
    fs::write(&tmp, &out).map_err(NonoError::Io)?;
    fs::rename(&tmp, file).map_err(NonoError::Io)?;
    Ok(())
}

fn find_block_bounds(content: &str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let s = content.find(begin)?;
    let end_marker_end = content[s..].find(end).map(|rel| s + rel + end.len())?;
    let after = if content[end_marker_end..].starts_with('\n') {
        end_marker_end + 1
    } else {
        end_marker_end
    };
    Some((s, after))
}

fn ensure_trailing_newline(s: &str) -> String {
    if s.ends_with('\n') {
        s.to_string()
    } else {
        format!("{s}\n")
    }
}

// Suppress unused-import warnings for items that are only used in
// callers we haven't wired up yet (lockfile schema additions land in
// a follow-up step). Forward-only — once `package.rs` references
// `WiringRecord`, this goes away.
#[allow(dead_code)]
fn _suppress_unused() {
    let _ = (Utc::now, BTreeMap::<String, String>::new);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use tempfile::TempDir;

    fn ctx_in(home: &Path, pack_dir: PathBuf) -> WiringContext {
        let _ = home; // signature parity with test setup
        WiringContext {
            pack_dir,
            namespace: "always-further".to_string(),
            pack_name: "claude".to_string(),
        }
    }

    fn with_fake_home<F: FnOnce(&Path)>(f: F) {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let home = TempDir::new().expect("tempdir");
        let _env = EnvVarGuard::set_all(&[("HOME", home.path().to_str().expect("utf8"))]);
        f(home.path());
    }

    /// Test wrapper for `execute` with no pre-existing pack-owned
    /// files (the fresh-install case most tests want).
    fn exec(directives: &[WiringDirective], ctx: &WiringContext) -> Result<WiringReport> {
        execute(directives, ctx, &HashMap::new())
    }

    /// Test wrapper for `reverse` that asserts there were no
    /// reversal failures — the success case the existing tests cover.
    /// Tests that exercise the failure path call `reverse` directly.
    fn rev(records: &[WiringRecord]) {
        let failures = reverse(records);
        assert!(
            failures.is_empty(),
            "reverse produced unexpected failures: {failures:?}"
        );
    }

    #[test]
    fn expand_vars_substitutes_known_set() {
        let pack_dir = PathBuf::from("/p");
        let ctx = WiringContext {
            pack_dir,
            namespace: "ns".to_string(),
            pack_name: "name".to_string(),
        };
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("HOME", "/h"), ("XDG_CONFIG_HOME", "__placeholder__")]);
        _env.remove("XDG_CONFIG_HOME");
        assert_eq!(expand_vars("$PACK_DIR/x", &ctx).expect("expand"), "/p/x");
        assert_eq!(expand_vars("$NS/$PLUGIN", &ctx).expect("expand"), "ns/name");
        assert_eq!(
            expand_vars("$HOME/.config", &ctx).expect("expand"),
            "/h/.config"
        );
        assert_eq!(
            expand_vars("$NONO_CONFIG/profile-drafts", &ctx).expect("expand"),
            "/h/.config/nono/profile-drafts"
        );
        assert_eq!(
            expand_vars("$NONO_PACKAGES/always-further/claude", &ctx).expect("expand"),
            "/h/.config/nono/packages/always-further/claude"
        );
    }

    #[test]
    fn expand_vars_nono_config_respects_xdg_config_home() {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let home = TempDir::new().expect("home tempdir");
        let config = TempDir::new().expect("config tempdir");
        let home_str = home.path().to_str().expect("home path");
        let config_str = config.path().to_str().expect("config path");
        let ctx = WiringContext {
            pack_dir: PathBuf::from("/p"),
            namespace: "always-further".to_string(),
            pack_name: "claude".to_string(),
        };
        let _env = EnvVarGuard::set_all(&[("HOME", home_str), ("XDG_CONFIG_HOME", config_str)]);
        let expected_config = format!("{config_str}/nono/profile-drafts");
        let expected_packages = format!("{config_str}/nono/packages/always-further/claude");
        assert_eq!(
            nono::try_canonicalize(Path::new(
                &expand_vars("$NONO_CONFIG/profile-drafts", &ctx).expect("expand")
            )),
            nono::try_canonicalize(Path::new(&expected_config))
        );
        assert_eq!(
            nono::try_canonicalize(Path::new(
                &expand_vars("$NONO_PACKAGES/always-further/claude", &ctx).expect("expand")
            )),
            nono::try_canonicalize(Path::new(&expected_packages))
        );
    }

    #[test]
    fn expand_vars_rejects_unknown() {
        let ctx = WiringContext {
            pack_dir: PathBuf::from("/p"),
            namespace: "n".to_string(),
            pack_name: "p".to_string(),
        };
        assert!(expand_vars("$BOGUS/x", &ctx).is_err());
        // Bare `$` not followed by an uppercase identifier passes through.
        // Lets pack content like regex end-anchors stay literal without
        // needing a `$$` escape.
        assert_eq!(
            expand_vars("trailing $", &ctx).expect("trailing"),
            "trailing $"
        );
        assert_eq!(
            expand_vars("^(Bash|apply_patch)$", &ctx).expect("regex"),
            "^(Bash|apply_patch)$"
        );
        assert_eq!(
            expand_vars("$lowercase", &ctx).expect("lower"),
            "$lowercase"
        );
    }

    #[test]
    fn symlink_directive_creates_records_and_reverses() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            let ctx = ctx_in(home, pack.clone());
            let directives = vec![WiringDirective::Symlink {
                link: "$HOME/link".to_string(),
                target: "$PACK_DIR".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("execute");
            assert!(report.changed);
            assert_eq!(report.records.len(), 1);
            let link = home.join("link");
            assert!(
                link.symlink_metadata()
                    .expect("meta")
                    .file_type()
                    .is_symlink()
            );
            assert_eq!(fs::read_link(&link).expect("readlink"), pack);

            rev(&report.records);
            assert!(link.symlink_metadata().is_err());
        });
    }

    #[test]
    fn symlink_directive_is_idempotent() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::Symlink {
                link: "$HOME/link".to_string(),
                target: "$PACK_DIR".to_string(),
            }];
            let _ = exec(&directives, &ctx).expect("first");
            let r2 = exec(&directives, &ctx).expect("second");
            assert!(!r2.changed, "second run should be no-op");
        });
    }

    #[test]
    fn json_merge_and_strip_round_trip() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("patch.json"),
                r#"{ "enabledPlugins": { "nono": true } }"#,
            )
            .expect("write patch");
            // Seed an existing file with unrelated keys.
            let target = home.join("settings.json");
            fs::write(&target, r#"{ "effortLevel": "xhigh" }"#).expect("seed target");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonMerge {
                file: "$HOME/settings.json".to_string(),
                patch: "patch.json".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("execute");
            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v["effortLevel"], "xhigh", "preserve unrelated keys");
            assert_eq!(v["enabledPlugins"]["nono"], true);

            rev(&report.records);
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v2["effortLevel"], "xhigh", "unrelated keys still present");
            assert!(v2.get("enabledPlugins").is_none(), "merged keys gone");
        });
    }

    #[test]
    fn json_merge_accepts_jsonc_in_target_and_patch() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("patch.json"),
                r#"{
                    // Pack patches may carry comments too.
                    "enabledPlugins": {
                        "nono": true,
                    },
                }"#,
            )
            .expect("write patch");
            let target = home.join("settings.json");
            fs::write(
                &target,
                r#"{
                    // User config comments must not break package wiring.
                    "effortLevel": "xhigh",
                }"#,
            )
            .expect("seed target");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonMerge {
                file: "$HOME/settings.json".to_string(),
                patch: "patch.json".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("execute");
            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v["effortLevel"], "xhigh", "preserve unrelated keys");
            assert_eq!(v["enabledPlugins"]["nono"], true);

            rev(&report.records);
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v2["effortLevel"], "xhigh", "unrelated keys still present");
            assert!(v2.get("enabledPlugins").is_none(), "merged keys gone");
        });
    }

    #[test]
    fn json_array_append_dedups_by_key_field() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x" }]"#,
            )
            .expect("write entries");

            let target = home.join("hooks.json");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let r1 = exec(&directives, &ctx).expect("first");
            assert!(r1.changed);
            let r2 = exec(&directives, &ctx).expect("second");
            assert!(!r2.changed, "dedup by key_field");

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v["hooks"]["PostToolUse"].as_array().expect("array").len(),
                1
            );

            rev(&r1.records);
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v2["hooks"]["PostToolUse"].as_array().expect("array").len(),
                0
            );
        });
    }

    #[test]
    fn json_array_append_accepts_jsonc_in_target_and_patch() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("entries.json"),
                r#"[
                    // Pack-provided append entries can be JSONC.
                    { "name": "nono", "command": "x" },
                ]"#,
            )
            .expect("write entries");

            let target = home.join("hooks.json");
            fs::write(
                &target,
                r#"{
                    // Mirrors user-owned config files such as Copilot config.
                    "hooks": {
                        "PostToolUse": [],
                    },
                }"#,
            )
            .expect("seed target");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("execute");

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            let entries = v["hooks"]["PostToolUse"].as_array().expect("array");
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0]["name"], "nono");

            rev(&report.records);
            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v2["hooks"]["PostToolUse"].as_array().expect("array").len(),
                0
            );
        });
    }

    #[test]
    fn json_array_append_replaces_entry_when_shape_changes() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            // First publish: just name + command.
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x" }]"#,
            )
            .expect("write v1");

            let target = home.join("hooks.json");
            let ctx = ctx_in(home, pack.clone());
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let r1 = exec(&directives, &ctx).expect("first install");
            assert!(r1.changed);

            // Second publish with new shape (added `silent: true`).
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "command": "x", "silent": true }]"#,
            )
            .expect("write v2");

            let r2 = exec(&directives, &ctx).expect("re-install");
            assert!(r2.changed, "shape change must be applied, not skipped");

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            let entries = v["hooks"]["PostToolUse"].as_array().expect("array present");
            assert_eq!(entries.len(), 1, "key dedup keeps a single entry");
            assert_eq!(
                entries[0].get("silent").and_then(|v| v.as_bool()),
                Some(true),
                "new shape (silent:true) replaces old shape"
            );

            // Re-running with the same v2 entries is a true no-op.
            let r3 = exec(&directives, &ctx).expect("third");
            assert!(!r3.changed, "identical re-run must report no change");
        });
    }

    #[test]
    fn toml_block_upsert_strip_round_trip() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("block.toml"), "[plugins.test]\nenabled = true\n")
                .expect("write block");

            let target = home.join("config.toml");
            // Seed unrelated content.
            fs::write(&target, "[features]\ncodex_hooks = true\n").expect("seed");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::TomlBlock {
                file: "$HOME/config.toml".to_string(),
                marker_id: "test".to_string(),
                content: "block.toml".to_string(),
            }];
            let r = exec(&directives, &ctx).expect("execute");
            let after = fs::read_to_string(&target).expect("read");
            assert!(after.contains("# >>> nono:test >>>"));
            assert!(after.contains("[plugins.test]"));
            assert!(after.contains("[features]"), "unrelated section preserved");

            rev(&r.records);
            let after_strip = fs::read_to_string(&target).expect("read");
            assert!(!after_strip.contains("nono:test"));
            assert!(after_strip.contains("[features]"));
        });
    }

    #[test]
    fn write_file_atomic_skips_when_identical() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "hello").expect("seed source");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let r1 = exec(&directives, &ctx).expect("first");
            assert!(r1.changed);

            // Re-pull simulation: caller passes the dest as
            // already-owned by this same pack with the prior hash.
            // Identical content is a no-op; if the hash didn't match,
            // the conflict guard would reject (covered by the
            // `write_file_refuses_to_overwrite_edited_file` test).
            let prior_sha = match &r1.records[0] {
                WiringRecord::WriteFile { sha256, .. } => sha256.clone(),
                other => panic!("expected WriteFile, got {other:?}"),
            };
            let mut owned: HashMap<PathBuf, String> = HashMap::new();
            owned.insert(home.join("dest"), prior_sha);
            let r2 = execute(&directives, &ctx, &owned).expect("second");
            assert!(!r2.changed, "identical content is no-op");

            rev(&r1.records);
            assert!(!home.join("dest").exists());
        });
    }

    #[test]
    fn write_file_refuses_to_overwrite_unmanaged_file() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "from-pack").expect("seed source");
            // Pre-existing unmanaged file at dest — typical of a
            // user-created config or a file from another pack.
            fs::write(home.join("dest"), "user content").expect("seed user file");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let err = exec(&directives, &ctx).expect_err("must refuse");
            assert!(err.to_string().contains("refusing to overwrite"));
            assert_eq!(
                fs::read_to_string(home.join("dest")).expect("read"),
                "user content",
                "user file must be untouched"
            );
        });
    }

    #[test]
    fn json_merge_reverse_preserves_unrelated_sibling_keys() {
        // Security review scenario: pack merges
        // `enabledPlugins.nono` into a settings file that already
        // contains other plugins. On uninstall only the leaf we wrote
        // is removed; the user's siblings stay.
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("patch.json"),
                r#"{ "enabledPlugins": { "nono": true } }"#,
            )
            .expect("write patch");
            let target = home.join("settings.json");
            fs::write(
                &target,
                r#"{ "enabledPlugins": { "user-plugin": true, "another": false } }"#,
            )
            .expect("seed");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonMerge {
                file: "$HOME/settings.json".to_string(),
                patch: "patch.json".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("install");
            rev(&report.records);

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v["enabledPlugins"]["user-plugin"], true);
            assert_eq!(v["enabledPlugins"]["another"], false);
            assert!(
                v["enabledPlugins"].get("nono").is_none(),
                "only our leaf should be gone"
            );
        });
    }

    #[test]
    fn json_array_append_reverse_restores_user_owned_entry() {
        // Security review scenario: user already has an entry at the
        // same dedup key. Pack replaces it on install. Uninstall must
        // restore the user's original.
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "shared", "value": "from-pack" }]"#,
            )
            .expect("write entries");
            let target = home.join("hooks.json");
            fs::write(
                &target,
                r#"{ "hooks": { "PostToolUse": [
                    { "name": "shared", "value": "user-original" }
                ] } }"#,
            )
            .expect("seed");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("install");
            // Mid-install state: pack version wins.
            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(v["hooks"]["PostToolUse"][0]["value"], "from-pack");

            rev(&report.records);

            let v2: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                v2["hooks"]["PostToolUse"][0]["value"], "user-original",
                "user's original entry must be restored"
            );
        });
    }

    #[test]
    fn reverse_collects_failures_instead_of_swallowing() {
        // Synthesise a record that points at a path on a read-only
        // parent; reverse_one will succeed for missing files (idempotent)
        // so we instead use a content-mismatch scenario for WriteFile,
        // which is detectable: install writes file, user replaces it,
        // reverse should NOT delete (success) — but if we record a bad
        // sha256 manually, reversal still succeeds (mismatch → leave
        // alone). The cleanest failure injection is a JsonMerge against
        // a malformed JSON file — read fails, reverse_one returns Err.
        with_fake_home(|home| {
            let target = home.join("broken.json");
            fs::write(&target, "{not valid json").expect("seed broken");

            let records = vec![WiringRecord::JsonMerge {
                file: target.to_string_lossy().into_owned(),
                leaves: vec![JsonLeaf {
                    path: vec!["k".to_string()],
                    installed_value: Value::Bool(true),
                    prior_value: None,
                }],
                created_parents: Vec::new(),
            }];
            let failures = reverse(&records);
            assert_eq!(failures.len(), 1, "broken JSON must surface as failure");
            assert!(
                failures[0].record_summary.contains("json_merge"),
                "summary should identify the directive"
            );
        });
    }

    #[test]
    fn write_file_force_recovery_accepts_identical_unmanaged_file() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "from-pack").expect("seed source");
            fs::write(home.join("dest"), "from-pack").expect("seed matching dest");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let report = execute_with_options(
                &directives,
                &ctx,
                &HashMap::new(),
                ExecuteOptions {
                    allow_unmanaged_identical_write_files: true,
                },
            )
            .expect("identical unmanaged file should be adopted during force recovery");

            assert!(
                !report.changed,
                "identical destination should not be rewritten"
            );
            assert_eq!(report.records.len(), 1);
            assert_eq!(
                fs::read_to_string(home.join("dest")).expect("read"),
                "from-pack"
            );
        });
    }

    #[test]
    fn write_file_force_recovery_refuses_mismatched_unmanaged_file() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "from-pack").expect("seed source");
            fs::write(home.join("dest"), "user content").expect("seed user file");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let err = execute_with_options(
                &directives,
                &ctx,
                &HashMap::new(),
                ExecuteOptions {
                    allow_unmanaged_identical_write_files: true,
                },
            )
            .expect_err("mismatched unmanaged file must still be refused");

            assert!(err.to_string().contains("refusing to overwrite"));
            assert_eq!(
                fs::read_to_string(home.join("dest")).expect("read"),
                "user content"
            );
        });
    }

    #[test]
    fn write_file_refuses_to_overwrite_edited_file_on_repull() {
        // Security review (round 2): re-pull must NOT clobber a file
        // the user has edited since the previous install. The
        // owned-files map carries the prior hash; mismatch refuses.
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "from-pack-v2").expect("seed v2");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];

            // Simulate prior install having written "from-pack-v1".
            fs::write(home.join("dest"), "from-pack-v1").expect("seed prior");
            let prior_sha = hash_bytes(b"from-pack-v1");

            // User edits the file post-install.
            fs::write(home.join("dest"), "user edited").expect("user edit");

            // Re-pull: caller passes prior hash. Mismatch must refuse.
            let mut owned: HashMap<PathBuf, String> = HashMap::new();
            owned.insert(home.join("dest"), prior_sha);
            let err = execute(&directives, &ctx, &owned).expect_err("must refuse");
            assert!(
                err.to_string().contains("sha256 mismatch") || err.to_string().contains("edited"),
                "error must mention edit/mismatch: {err}"
            );
            assert_eq!(
                fs::read_to_string(home.join("dest")).expect("read"),
                "user edited",
                "user edit must be preserved",
            );
        });
    }

    #[test]
    fn json_array_append_reverse_leaves_user_edit_alone() {
        // Security review (round 2): if the user edits the entry
        // after install, reverse must NOT delete it. AppendedEntry
        // carries `installed`, and reverse only acts when current
        // entry equals installed.
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("entries.json"),
                r#"[{ "name": "nono", "value": "from-pack" }]"#,
            )
            .expect("write entries");

            let target = home.join("hooks.json");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::JsonArrayAppend {
                file: "$HOME/hooks.json".to_string(),
                path: "hooks.PostToolUse".to_string(),
                patch_entries: "entries.json".to_string(),
                key_field: "name".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("install");

            // User edits the entry post-install (e.g. customised
            // a flag on the hook).
            let mut doc: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            doc["hooks"]["PostToolUse"][0]["value"] = Value::String("user-customised".to_string());
            fs::write(&target, serde_json::to_string_pretty(&doc).expect("ser"))
                .expect("write user edit");

            rev(&report.records);

            let v: Value =
                serde_json::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            // The entry stays — reverse refused to touch a user edit.
            assert_eq!(
                v["hooks"]["PostToolUse"][0]["value"], "user-customised",
                "user-edited entry must be preserved",
            );
        });
    }

    #[test]
    fn write_file_reverse_leaves_modified_file_alone() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("file"), "from-pack").expect("seed source");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::WriteFile {
                source: "file".to_string(),
                dest: "$HOME/dest".to_string(),
            }];
            let r1 = exec(&directives, &ctx).expect("install");
            // User edits the file post-install.
            fs::write(home.join("dest"), "user edited").expect("user edit");
            rev(&r1.records);
            assert!(home.join("dest").exists(), "modified file must be kept");
            assert_eq!(
                fs::read_to_string(home.join("dest")).expect("read"),
                "user edited",
            );
        });
    }

    #[test]
    fn yaml_merge_and_strip_round_trip() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(
                pack.join("patch.yaml"),
                "plugins:\n  enabled:\n    - nono-sandbox\n",
            )
            .expect("write patch");
            // Seed existing YAML with an unrelated key.
            let target = home.join("config.yaml");
            fs::write(&target, "level: info\n").expect("seed target");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::YamlMerge {
                file: "$HOME/config.yaml".to_string(),
                patch: "patch.yaml".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("execute");
            assert!(report.changed);

            let after: yaml::Value =
                yaml::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(after["level"], yaml::Value::String("info".to_string()));
            assert!(after["plugins"]["enabled"].is_sequence());

            rev(&report.records);
            let restored: yaml::Value =
                yaml::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(restored["level"], yaml::Value::String("info".to_string()));
            assert!(
                restored.get("plugins").is_none(),
                "merged keys gone after reverse"
            );
        });
    }

    #[test]
    fn yaml_merge_is_idempotent() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("patch.yaml"), "foo:\n  bar: true\n").expect("write patch");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::YamlMerge {
                file: "$HOME/config.yaml".to_string(),
                patch: "patch.yaml".to_string(),
            }];
            let _ = exec(&directives, &ctx).expect("first");
            let r2 = exec(&directives, &ctx).expect("second");
            assert!(!r2.changed, "second run must be no-op");
        });
    }

    #[test]
    fn yaml_merge_preserves_sibling_keys_on_reverse() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("patch.yaml"), "plugins:\n  nono: true\n").expect("write patch");
            let target = home.join("config.yaml");
            fs::write(&target, "plugins:\n  user-plugin: true\n").expect("seed");

            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::YamlMerge {
                file: "$HOME/config.yaml".to_string(),
                patch: "patch.yaml".to_string(),
            }];
            let report = exec(&directives, &ctx).expect("install");
            rev(&report.records);

            let restored: yaml::Value =
                yaml::from_str(&fs::read_to_string(&target).expect("read")).expect("parse");
            assert_eq!(
                restored["plugins"]["user-plugin"],
                yaml::Value::Bool(true),
                "sibling key must survive removal"
            );
            assert!(
                restored["plugins"].get("nono").is_none(),
                "only our leaf should be gone"
            );
        });
    }

    #[test]
    fn yaml_merge_rejects_non_string_keys() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            // YAML allows integer keys; we must reject them.
            fs::write(pack.join("patch.yaml"), "123: bad\n").expect("write patch");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::YamlMerge {
                file: "$HOME/config.yaml".to_string(),
                patch: "patch.yaml".to_string(),
            }];
            let err = exec(&directives, &ctx).expect_err("must reject non-string keys");
            assert!(
                err.to_string().contains("mapping key must be a string"),
                "error must mention key type: {err}"
            );
        });
    }

    #[test]
    fn yaml_merge_rejects_custom_tags() {
        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("patch.yaml"), "key: !MyTag value\n").expect("write patch");
            let ctx = ctx_in(home, pack);
            let directives = vec![WiringDirective::YamlMerge {
                file: "$HOME/config.yaml".to_string(),
                patch: "patch.yaml".to_string(),
            }];
            let err = exec(&directives, &ctx).expect_err("must reject custom tags");
            assert!(
                err.to_string().contains("custom YAML tags"),
                "error must mention tags: {err}"
            );
        });
    }

    #[test]
    fn yaml_reverse_collects_failures_instead_of_swallowing() {
        // Mirror of `reverse_collects_failures_instead_of_swallowing` for
        // `YamlMerge`: inject a malformed YAML target file so that
        // `restore_yaml_leaves` → `read_yaml` returns an error. The
        // `reverse` function must surface the error rather than silently
        // skipping it, so the caller knows the rollback is incomplete and
        // the file was not left in a misformatted state.
        with_fake_home(|home| {
            let target = home.join("broken.yaml");
            fs::write(&target, "key: [unclosed").expect("seed broken");

            let records = vec![WiringRecord::YamlMerge {
                file: target.to_string_lossy().into_owned(),
                leaves: vec![JsonLeaf {
                    path: vec!["k".to_string()],
                    installed_value: Value::Bool(true),
                    prior_value: None,
                }],
                created_parents: Vec::new(),
            }];
            let failures = reverse(&records);
            assert_eq!(failures.len(), 1, "broken YAML must surface as failure");
            assert!(
                failures[0].record_summary.contains("yaml_merge"),
                "summary should identify the directive: {}",
                failures[0].record_summary
            );
        });
    }

    #[test]
    fn wiring_when_filters_directives_before_execution() {
        let current = crate::platform::current_os_name();
        let other = if current == "linux" { "macos" } else { "linux" };
        let json = format!(
            r#"[
                {{
                    "type": "write_file",
                    "source": "match.txt",
                    "dest": "$HOME/match.txt",
                    "when": "{current}"
                }},
                {{
                    "type": "write_file",
                    "source": "skip.txt",
                    "dest": "$HOME/skip.txt",
                    "when": "{other}"
                }}
            ]"#
        );
        let directives: Vec<WiringDirective> = serde_json::from_str(&json).expect("parse wiring");
        assert!(matches!(directives[1], WiringDirective::Skipped));

        with_fake_home(|home| {
            let pack = home.join("pack");
            fs::create_dir_all(&pack).expect("mkdir pack");
            fs::write(pack.join("match.txt"), "match").expect("write match");
            fs::write(pack.join("skip.txt"), "skip").expect("write skip");
            let ctx = ctx_in(home, pack);
            let report = exec(&directives, &ctx).expect("execute");

            assert!(home.join("match.txt").exists());
            assert!(!home.join("skip.txt").exists());
            assert_eq!(report.records.len(), 1);
        });
    }
}
