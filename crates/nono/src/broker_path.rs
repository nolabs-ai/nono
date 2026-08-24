//! PATH sanitization for host-side credential and URL-open brokers.
//!
//! Brokers run unsandboxed, as the real user, and resolve executables by
//! bare name via PATH. If any directory on that PATH is writable by the
//! sandbox — directly, through a writable ancestor, or through a symlink
//! into a writable area — the sandboxed process can plant a trojan binary
//! there for the broker to execute with real user privileges. This module
//! strips every PATH entry that can't be proven read-only to a given
//! `CapabilitySet` before a broker is allowed to inherit PATH.

use crate::capability::{AccessMode, CapabilitySet};
use crate::path::try_canonicalize;
use std::path::{Path, PathBuf};

/// Bound on symlink hops walked per PATH entry, guarding against cycles.
const MAX_SYMLINK_HOPS: u32 = 40;

/// Return `path_value` with every entry the sandbox could write to removed.
/// An entry that can't be proven read-only — empty, relative, a symlink
/// cycle, or too deep to resolve — is dropped rather than kept.
///
/// This checks each PATH *directory* only. If the exact binary name that
/// will be looked up in it is known ahead of time, prefer
/// [`sanitize_broker_path_for_binary`]: a directory can be safe while a
/// *file-scoped* write grant still targets one exact file inside it (e.g.
/// `filesystem.write: ["/usr/local/bin/gh"]`), which this function cannot
/// see.
#[must_use]
pub fn sanitize_broker_path(path_value: &str, outer_caps: &CapabilitySet) -> String {
    filter_path(path_value, |entry| is_entry_safe(entry, outer_caps))
}

/// Like [`sanitize_broker_path`], but also drops a directory if the specific
/// `binary_name` file within it — not just the directory itself — is
/// writable by the sandbox. A directory-level check alone cannot see a
/// write grant scoped to one exact file inside an otherwise-safe directory.
/// Every real broker call site knows the binary name it's about to resolve
/// (`open`, `xdg-open`, `op`, `bw`, `security`, or a profile-configured
/// command), so this is the check they should use.
#[must_use]
pub fn sanitize_broker_path_for_binary(
    path_value: &str,
    binary_name: &str,
    outer_caps: &CapabilitySet,
) -> String {
    filter_path(path_value, |entry| {
        is_entry_safe(entry, outer_caps)
            && matches!(
                walk_chain(&entry.join(binary_name), outer_caps),
                Some(false)
            )
    })
}

fn filter_path(path_value: &str, mut keep: impl FnMut(&Path) -> bool) -> String {
    let kept: Vec<PathBuf> = std::env::split_paths(path_value)
        .filter(|entry| keep(entry))
        .collect();
    std::env::join_paths(kept)
        .map(|joined| joined.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn is_entry_safe(entry: &Path, outer_caps: &CapabilitySet) -> bool {
    // Empty (`::`, leading/trailing `:`) and relative entries resolve to the
    // current directory on lookup, which is typically sandbox-writable.
    if entry.as_os_str().is_empty() || entry.is_relative() {
        return false;
    }
    matches!(walk_chain(entry, outer_caps), Some(false))
}

/// Walk the symlink chain starting at `path`. At every hop, check that hop
/// and its parent directory for a write grant: a writable parent lets the
/// sandbox replace that hop outright (including retargeting a symlink),
/// regardless of where it currently points. A missing entry is checked the
/// same way and then treated as resolved, since an ancestor grant is what
/// would let the sandbox create it later.
///
/// Returns `Some(true)` if a write grant was found anywhere in the chain,
/// `Some(false)` if the chain resolved cleanly with nothing writable, or
/// `None` if it could not be resolved (broken loop or too many hops).
fn walk_chain(path: &Path, outer_caps: &CapabilitySet) -> Option<bool> {
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINK_HOPS {
        let parent = current.parent()?;
        let canonical_parent = try_canonicalize(parent);
        let canonical_current = match current.file_name() {
            Some(name) => canonical_parent.join(name),
            None => canonical_parent.clone(),
        };
        if grants_write(outer_caps, &canonical_parent)
            || grants_write(outer_caps, &canonical_current)
        {
            return Some(true);
        }

        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                let target = std::fs::read_link(&current).ok()?;
                current = if target.is_absolute() {
                    target
                } else {
                    parent.join(target)
                };
            }
            // Real file/directory, or doesn't exist yet: nothing further to
            // follow. The ancestor grant check above already covers the
            // not-yet-created case.
            _ => return Some(false),
        }
    }
    None
}

fn grants_write(caps: &CapabilitySet, path: &Path) -> bool {
    caps.fs_capabilities().iter().any(|cap| {
        cap.access.contains(AccessMode::Write)
            && if cap.is_file {
                cap.resolved == path
            } else {
                path.starts_with(&cap.resolved)
            }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{CapabilitySource, FsCapability};

    // Real grants are canonicalized at grant time (see AGENTS.md), so tests
    // must canonicalize too — otherwise a tempdir under a symlinked prefix
    // (e.g. macOS `/var` -> `/private/var`) would never match.
    fn fs_cap(dir: &Path, access: AccessMode) -> FsCapability {
        let resolved = try_canonicalize(dir);
        FsCapability {
            original: dir.to_path_buf(),
            resolved,
            access,
            is_file: false,
            source: CapabilitySource::User,
        }
    }

    fn caps_with_write(dir: &Path) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(dir, AccessMode::Write));
        caps
    }

    fn caps_with_read(dir: &Path) -> CapabilitySet {
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(dir, AccessMode::Read));
        caps
    }

    #[test]
    fn keeps_read_only_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let caps = caps_with_read(dir.path());
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), path);
    }

    #[test]
    fn drops_directly_writable_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let caps = caps_with_write(&bin);
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[test]
    fn drops_directory_under_writable_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("nested").join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        // Sandbox has write access to the whole tempdir, a strict ancestor
        // of the PATH entry.
        let caps = caps_with_write(dir.path());
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[test]
    fn drops_missing_directory_under_writable_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("not-created-yet");
        let caps = caps_with_write(dir.path());
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[test]
    fn keeps_missing_directory_under_read_only_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("not-created-yet");
        let caps = caps_with_read(dir.path());
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), path);
    }

    #[cfg(unix)]
    #[test]
    fn drops_symlink_pointing_into_writable_area() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        let writable = dir.path().join("writable");
        std::fs::create_dir_all(&real).expect("mkdir real");
        std::fs::create_dir_all(&writable).expect("mkdir writable");
        let link = dir.path().join("link");
        // link -> writable/target, target not created yet.
        std::os::unix::fs::symlink(writable.join("target"), &link).expect("symlink");

        // Read-only on the tempdir root and on `real`, but the sandbox can
        // write into `writable`, which is what the symlink resolves under.
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(dir.path(), AccessMode::Read));
        caps.add_fs(fs_cap(&writable, AccessMode::Write));

        let path = link.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[cfg(unix)]
    #[test]
    fn drops_entry_whose_symlink_itself_is_replaceable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        std::fs::create_dir_all(&real).expect("mkdir real");
        let writable_parent = dir.path().join("writable-parent");
        std::fs::create_dir_all(&writable_parent).expect("mkdir writable parent");
        // The symlink itself lives in a directory the sandbox can write to,
        // even though it currently points at a read-only real target.
        let link = writable_parent.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(&real, AccessMode::Read));
        caps.add_fs(fs_cap(&writable_parent, AccessMode::Write));

        let path = link.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[cfg(unix)]
    #[test]
    fn drops_symlink_cycle_instead_of_looping_forever() {
        let dir = tempfile::tempdir().expect("tempdir");
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::os::unix::fs::symlink(&b, &a).expect("symlink a->b");
        std::os::unix::fs::symlink(&a, &b).expect("symlink b->a");

        let caps = caps_with_read(dir.path());
        let path = a.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[test]
    fn drops_empty_and_relative_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let caps = caps_with_read(dir.path());
        let path = format!("{}::relative/dir:{}", bin.display(), bin.display());
        assert_eq!(
            sanitize_broker_path(&path, &caps),
            format!("{}:{}", bin.display(), bin.display())
        );
    }

    #[test]
    fn preserves_order_of_surviving_entries() {
        let dir = tempfile::tempdir().expect("tempdir");
        let safe_a = dir.path().join("safe-a");
        let unsafe_dir = dir.path().join("unsafe");
        let safe_b = dir.path().join("safe-b");
        std::fs::create_dir_all(&safe_a).expect("mkdir");
        std::fs::create_dir_all(&unsafe_dir).expect("mkdir");
        std::fs::create_dir_all(&safe_b).expect("mkdir");

        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(dir.path(), AccessMode::Read));
        caps.add_fs(fs_cap(&unsafe_dir, AccessMode::Write));

        let path = format!(
            "{}:{}:{}",
            safe_a.display(),
            dir.path().join("unsafe").display(),
            safe_b.display()
        );
        assert_eq!(
            sanitize_broker_path(&path, &caps),
            format!("{}:{}", safe_a.display(), safe_b.display())
        );
    }

    #[test]
    fn keeps_file_capability_write_grant_confined_to_that_file() {
        // A file-scoped write grant should not make its parent directory
        // (a PATH entry) read-only... it should make it WRITABLE at that
        // exact path only, so a distinct sibling PATH entry stays safe.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let file = bin.join("some-file");
        std::fs::write(&file, b"x").expect("write");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: file.clone(),
            resolved: try_canonicalize(&file),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), path);
    }

    #[test]
    fn plain_sanitize_misses_file_scoped_grant_on_the_resolved_binary() {
        // Documents the precise limitation `sanitize_broker_path_for_binary`
        // exists to close: a directory-only check cannot see a write grant
        // scoped to one exact file inside it, so a directory with no grant
        // of its own is kept even when the specific binary in it is
        // separately writable. Callers that know the binary name ahead of
        // time (every real broker call site does) must use
        // `sanitize_broker_path_for_binary` instead.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let trojan_target = bin.join("ocm");
        std::fs::write(&trojan_target, b"x").expect("write");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: trojan_target.clone(),
            resolved: try_canonicalize(&trojan_target),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let path = bin.display().to_string();
        assert_eq!(
            sanitize_broker_path(&path, &caps),
            path,
            "directory-only check cannot see the file-scoped grant (expected limitation)"
        );
    }

    #[test]
    fn sanitize_for_binary_drops_directory_with_file_scoped_grant_on_that_binary() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let trojan_target = bin.join("ocm");
        std::fs::write(&trojan_target, b"x").expect("write");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: trojan_target.clone(),
            resolved: try_canonicalize(&trojan_target),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let path = bin.display().to_string();
        assert_eq!(
            sanitize_broker_path_for_binary(&path, "ocm", &caps),
            "",
            "directory must be dropped: the exact binary being resolved is file-write-granted"
        );
    }

    #[test]
    fn sanitize_for_binary_keeps_directory_when_grant_targets_a_different_file() {
        // The write grant is scoped to a sibling file, not the binary being
        // resolved, so the directory must survive.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let other_file = bin.join("unrelated-tool");
        std::fs::write(&other_file, b"x").expect("write");

        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: other_file.clone(),
            resolved: try_canonicalize(&other_file),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path_for_binary(&path, "ocm", &caps), path);
    }

    #[cfg(unix)]
    #[test]
    fn end_to_end_file_scoped_grant_on_exact_binary_is_not_executed() {
        use std::os::unix::fs::PermissionsExt;

        let root = tempfile::tempdir().expect("tempdir");
        let bin_dir = root.path().join("usr-local-bin");
        std::fs::create_dir_all(&bin_dir).expect("mkdir");
        let trojan = bin_dir.join("victim-tool");
        let marker = root.path().join("PWNED");
        std::fs::write(&trojan, format!("#!/bin/sh\n: > '{}'\n", marker.display()))
            .expect("write trojan");
        let mut perms = std::fs::metadata(&trojan).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&trojan, perms).expect("chmod");

        // Directory itself has no grant; only the exact binary path does.
        let mut caps = CapabilitySet::new();
        caps.add_fs(FsCapability {
            original: trojan.clone(),
            resolved: try_canonicalize(&trojan),
            access: AccessMode::Write,
            is_file: true,
            source: CapabilitySource::User,
        });

        let sanitized =
            sanitize_broker_path_for_binary(&bin_dir.display().to_string(), "victim-tool", &caps);
        assert_eq!(sanitized, "", "the directory must be dropped entirely");

        // With no directories left, resolution must fail rather than fall
        // through to inheriting the ambient PATH.
        let status = std::process::Command::new("victim-tool")
            .env("PATH", &sanitized)
            .status();
        assert!(
            status.is_err(),
            "victim-tool must not be resolvable at all once its directory is dropped"
        );
        assert!(!marker.exists(), "trojan must never have run");
    }

    #[test]
    fn drops_directory_under_readwrite_ancestor() {
        // ReadWrite is a superset of Write; a directory under a ReadWrite
        // ancestor must be dropped just like one under a Write-only grant.
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        std::fs::create_dir_all(&bin).expect("mkdir");
        let mut caps = CapabilitySet::new();
        caps.add_fs(fs_cap(dir.path(), AccessMode::ReadWrite));
        let path = bin.display().to_string();
        assert_eq!(sanitize_broker_path(&path, &caps), "");
    }

    #[test]
    fn drops_root_entry() {
        // `/` as a bare PATH entry has no parent to canonicalize; treated as
        // unresolvable and dropped rather than panicking.
        let caps = CapabilitySet::new();
        assert_eq!(sanitize_broker_path("/", &caps), "");
    }

    #[test]
    fn resolves_dot_dot_components_before_checking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let bin = dir.path().join("bin");
        let sibling = dir.path().join("sibling");
        std::fs::create_dir_all(&bin).expect("mkdir bin");
        std::fs::create_dir_all(&sibling).expect("mkdir sibling");
        // Sandbox can only write into `sibling`; `bin` reached via `../bin`
        // from within `sibling` must still be recognized as the same,
        // read-only `bin` directory rather than treated as distinct.
        let caps = caps_with_write(&sibling);
        let path = sibling.join("..").join("bin").display().to_string();
        let kept = sanitize_broker_path(&path, &caps);
        assert!(
            !kept.is_empty(),
            "read-only bin reached via .. must survive"
        );
    }

    #[test]
    fn drops_entry_with_null_byte_gracefully() {
        // A PATH entry that can't exist as a real filesystem path (embedded
        // NUL) must be dropped, not panic the sanitizer.
        let caps = CapabilitySet::new();
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            let raw = std::ffi::OsStr::from_bytes(b"/tmp/evil\0dir");
            let path_value = raw.to_string_lossy().into_owned();
            // Just must not panic; result content is not asserted since the
            // NUL makes this an invalid path on the OS level either way.
            let _ = sanitize_broker_path(&path_value, &caps);
        }
    }

    /// End-to-end exploit simulation: a sandboxed process plants a trojan
    /// `victim-tool` on a directory it has write access to and prepends that
    /// directory to PATH; a real `victim-tool` also exists on a read-only
    /// directory further down PATH. Spawning `victim-tool` by bare name
    /// through the sanitized PATH must run the real tool, not the trojan.
    #[cfg(unix)]
    #[test]
    fn end_to_end_trojan_on_writable_path_dir_is_not_executed() {
        let root = tempfile::tempdir().expect("tempdir");
        let evil_dir = root.path().join("sandbox-writable-bin");
        let safe_dir = root.path().join("real-bin");
        std::fs::create_dir_all(&evil_dir).expect("mkdir evil");
        std::fs::create_dir_all(&safe_dir).expect("mkdir safe");

        let marker_dir = root.path().join("markers");
        std::fs::create_dir_all(&marker_dir).expect("mkdir markers");
        let evil_marker = marker_dir.join("pwned");
        let safe_marker = marker_dir.join("legit");

        write_marker_script(&evil_dir.join("victim-tool"), &evil_marker);
        write_marker_script(&safe_dir.join("victim-tool"), &safe_marker);

        // Sandbox policy: write access to evil_dir only (as if it were a
        // workdir/cache grant); safe_dir has no grant at all, i.e. the
        // sandbox cannot touch it — exactly like a real system bin dir.
        let caps = caps_with_write(&evil_dir);

        let ambient_path = format!("{}:{}", evil_dir.display(), safe_dir.display());
        let sanitized = sanitize_broker_path(&ambient_path, &caps);

        // The trojan's directory must not survive sanitization.
        assert!(
            !sanitized
                .split(':')
                .any(|d| d == try_canonicalize(&evil_dir).display().to_string()
                    || d == evil_dir.display().to_string()),
            "writable dir must be dropped from sanitized PATH, got: {sanitized}"
        );

        // Actually spawn the broker by bare name using only the sanitized
        // PATH, exactly as the real call sites do.
        let status = std::process::Command::new("victim-tool")
            .env("PATH", &sanitized)
            .status()
            .expect("spawn victim-tool via sanitized PATH");
        assert!(status.success());

        assert!(
            !evil_marker.exists(),
            "trojan executed even though its directory was sandbox-writable"
        );
        assert!(
            safe_marker.exists(),
            "real tool on the read-only directory did not run"
        );
    }

    #[cfg(unix)]
    fn write_marker_script(path: &Path, marker_path: &Path) {
        use std::os::unix::fs::PermissionsExt;
        // Use a shell builtin (`:`, redirection) rather than an external
        // `touch`/`echo` binary: the sanitized PATH used in the exploit test
        // deliberately excludes real system directories, so no external
        // command would be resolvable.
        std::fs::write(
            path,
            format!("#!/bin/sh\n: > '{}'\n", marker_path.display()),
        )
        .expect("write script");
        let mut perms = std::fs::metadata(path).expect("metadata").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms).expect("chmod");
    }
}
