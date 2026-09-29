//! Path utilities shared across nono library and CLI.

use std::collections::HashSet;
use std::path::{Component, Path, PathBuf};

/// Canonicalize a path using an ancestor-walk fallback.
///
/// Unlike `std::fs::canonicalize`, this never returns an error for
/// non-existent paths. When the full path cannot be canonicalized (e.g. a
/// path component doesn't exist yet), it walks up to find the longest
/// existing ancestor, canonicalizes that, and re-appends the remaining
/// components.
///
/// This correctly handles macOS symlinks such as `/tmp` → `/private/tmp`
/// even when the leaf path does not exist yet.
pub fn try_canonicalize(path: &Path) -> PathBuf {
    if let Ok(canonical) = path.canonicalize() {
        return canonical;
    }
    try_canonicalize_ancestor_walk(path)
}

/// Ancestor-walk canonicalization, skipping the initial `canonicalize()` attempt.
///
/// Use this when `std::fs::canonicalize` has already been tried and failed,
/// to avoid a redundant syscall.
pub(crate) fn try_canonicalize_ancestor_walk(path: &Path) -> PathBuf {
    let mut remaining = Vec::new();
    let mut current = path.to_path_buf();
    loop {
        if let Ok(canonical) = current.canonicalize() {
            let mut result = canonical;
            for component in remaining.iter().rev() {
                result = result.join(component);
            }
            return result;
        }

        match current.file_name() {
            Some(name) => {
                remaining.push(name.to_os_string());
                if !current.pop() {
                    break;
                }
            }
            None => break,
        }
    }

    path.to_path_buf()
}

/// Matches typical OS `ELOOP`/`MAXSYMLINKS` limits, so a cycle truncates
/// instead of looping forever.
const MAX_SYMLINK_HOPS: usize = 40;

/// Intermediate hops need their own sandbox grant, since
/// [`try_canonicalize`] only ever sees the original and resolved endpoints.
pub fn collect_symlink_hops(path: &Path) -> Vec<PathBuf> {
    let mut hops = Vec::new();
    let mut seen = HashSet::new();
    let mut depth = 0usize;
    resolve_hops(path, &mut hops, &mut seen, &mut depth);
    hops
}

/// `path` need not be absolute on entry, since a symlink target can be
/// relative to its own parent directory.
fn resolve_hops(
    path: &Path,
    hops: &mut Vec<PathBuf>,
    seen: &mut HashSet<PathBuf>,
    depth: &mut usize,
) -> PathBuf {
    let mut result = PathBuf::new();

    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => {
                result.push(component.as_os_str());
            }
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(segment) => {
                result.push(segment);

                if *depth >= MAX_SYMLINK_HOPS {
                    continue;
                }

                let Ok(metadata) = std::fs::symlink_metadata(&result) else {
                    continue;
                };
                if !metadata.file_type().is_symlink() {
                    continue;
                }

                *depth += 1;
                if !seen.insert(result.clone()) {
                    continue;
                }
                hops.push(result.clone());

                let Ok(target) = std::fs::read_link(&result) else {
                    continue;
                };
                let target = if target.is_absolute() {
                    target
                } else {
                    result
                        .parent()
                        .map(|parent| parent.join(&target))
                        .unwrap_or(target)
                };

                result = resolve_hops(&target, hops, seen, depth);
            }
        }
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn existing_path_canonicalizes() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonicalize");
        assert_eq!(try_canonicalize(dir.path()), canonical);
    }

    #[test]
    fn nonexistent_leaf_uses_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let nonexistent = dir.path().join("does_not_exist");
        let result = try_canonicalize(&nonexistent);
        assert_eq!(result, canonical_dir.join("does_not_exist"));
    }

    #[test]
    fn nonexistent_nested_uses_deepest_ancestor() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let nonexistent = dir.path().join("a").join("b").join("c");
        let result = try_canonicalize(&nonexistent);
        assert_eq!(result, canonical_dir.join("a").join("b").join("c"));
    }

    #[test]
    fn existing_symlink_resolves_through() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real_file = dir.path().join("real.txt");
        fs::write(&real_file, "hello").expect("write file");
        let link = dir.path().join("link.txt");
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real_file, &link).expect("symlink");
        #[cfg(unix)]
        {
            let result = try_canonicalize(&link);
            assert_eq!(result, real_file.canonicalize().expect("canonicalize"));
        }
    }

    #[cfg(unix)]
    #[test]
    fn collect_symlink_hops_empty_for_plain_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let real_file = canonical_dir.join("real.txt");
        fs::write(&real_file, "hello").expect("write file");
        assert!(collect_symlink_hops(&real_file).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn collect_symlink_hops_single_hop_leaf_symlink() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let real_file = canonical_dir.join("real.txt");
        fs::write(&real_file, "hello").expect("write file");
        let link = canonical_dir.join("link.txt");
        std::os::unix::fs::symlink(&real_file, &link).expect("symlink");

        let hops = collect_symlink_hops(&link);
        assert_eq!(hops, vec![link]);
    }

    /// A symlinked leaf through a symlinked directory component:
    /// `.gitconfig -> hosts/current/gitconfig -> hosts/mymac/gitconfig`.
    #[cfg(unix)]
    #[test]
    fn collect_symlink_hops_multi_hop_through_symlinked_directory() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");

        let hosts = canonical_dir.join("hosts");
        let mymac = hosts.join("mymac");
        fs::create_dir_all(&mymac).expect("mkdir mymac");
        let real_gitconfig = mymac.join("gitconfig");
        fs::write(&real_gitconfig, "[user]\n").expect("write gitconfig");

        let current = hosts.join("current");
        std::os::unix::fs::symlink(&mymac, &current).expect("symlink dir");

        let gitconfig_link = canonical_dir.join(".gitconfig");
        std::os::unix::fs::symlink(current.join("gitconfig"), &gitconfig_link)
            .expect("symlink leaf");

        let hops = collect_symlink_hops(&gitconfig_link);
        assert_eq!(hops, vec![gitconfig_link.clone(), current]);

        // The fully resolved target is unaffected -- std canonicalization
        // still collapses the whole chain in one shot.
        assert_eq!(
            try_canonicalize(&gitconfig_link),
            real_gitconfig.canonicalize().expect("canonicalize")
        );
    }

    #[cfg(unix)]
    #[test]
    fn collect_symlink_hops_cycle_truncates_instead_of_looping() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");
        let a = canonical_dir.join("a");
        let b = canonical_dir.join("b");
        std::os::unix::fs::symlink(&b, &a).expect("symlink a->b");
        std::os::unix::fs::symlink(&a, &b).expect("symlink b->a");

        let hops = collect_symlink_hops(&a);
        // Must terminate (this test itself is the proof); depth-bounded, so
        // only ever sees the two distinct literal hop paths.
        assert!(hops.len() <= MAX_SYMLINK_HOPS);
        assert!(hops.contains(&a));
        assert!(hops.contains(&b));
    }

    #[cfg(unix)]
    #[test]
    fn collect_symlink_hops_nonexistent_final_target_keeps_existing_hops() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical_dir = dir.path().canonicalize().expect("canonicalize");

        let hosts = canonical_dir.join("hosts");
        let mymac = hosts.join("mymac");
        fs::create_dir_all(&mymac).expect("mkdir mymac");
        // Note: no `gitconfig` file written under mymac -- final target
        // does not exist, but the directory symlink hop is still real.

        let current = hosts.join("current");
        std::os::unix::fs::symlink(&mymac, &current).expect("symlink dir");

        let gitconfig_link = canonical_dir.join(".gitconfig");
        std::os::unix::fs::symlink(current.join("gitconfig"), &gitconfig_link)
            .expect("symlink leaf");

        let hops = collect_symlink_hops(&gitconfig_link);
        assert_eq!(hops, vec![gitconfig_link, current]);
    }
}
