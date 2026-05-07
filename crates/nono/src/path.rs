//! Path utilities shared across nono library and CLI.

use std::path::{Path, PathBuf};

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
}
