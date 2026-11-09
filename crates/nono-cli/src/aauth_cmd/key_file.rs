//! Atomic owner-only key writes anchored to an open parent directory.

use nono::{NonoError, Result};
use std::io::Write;
use std::path::Path;

pub(super) fn store(path: &Path, bytes: &[u8], force: bool) -> Result<()> {
    use nix::fcntl::{AtFlags, OFlag, open, openat, renameat};
    use nix::sys::stat::{Mode, SFlag, fstat, fstatat};
    use nix::unistd::{UnlinkatFlags, linkat, unlinkat};
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    let failure = |error| {
        NonoError::KeystoreAccess(format!(
            "failed to store aauth key '{}': {error}",
            path.display()
        ))
    };
    let parent = path
        .parent()
        .ok_or_else(|| failure("missing parent directory".to_string()))?;
    let name = path
        .file_name()
        .ok_or_else(|| failure("missing filename".to_string()))?;
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(parent)
        .map_err(|e| failure(e.to_string()))?;
    let parent = parent.canonicalize().map_err(|e| failure(e.to_string()))?;
    let flags = OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC;
    let mut directory =
        open(Path::new("/"), flags, Mode::empty()).map_err(|e| failure(e.to_string()))?;
    // Walk the canonical parent without following components introduced by
    // concurrent renames. Each subsequent operation is relative to a pinned fd.
    for component in parent.components() {
        if let std::path::Component::Normal(name) = component {
            directory = openat(&directory, name, flags, Mode::empty())
                .map_err(|e| failure(e.to_string()))?;
        }
    }
    let metadata = fstat(&directory).map_err(|e| failure(e.to_string()))?;
    if metadata.st_uid != nix::unistd::geteuid().as_raw() || metadata.st_mode & 0o022 != 0 {
        return Err(failure(
            "key directory must be owned by the current user and not writable by group/others"
                .to_string(),
        ));
    }
    match fstatat(&directory, name, AtFlags::AT_SYMLINK_NOFOLLOW) {
        Ok(metadata) => {
            if SFlag::from_bits_truncate(metadata.st_mode) != SFlag::S_IFREG {
                return Err(failure(
                    "destination must be a regular file, not a symlink".to_string(),
                ));
            }
            if !force {
                return Err(failure(
                    "key already exists (use --force to replace it)".to_string(),
                ));
            }
        }
        Err(nix::errno::Errno::ENOENT) => {}
        Err(error) => return Err(failure(error.to_string())),
    }
    let temporary = format!(".nono-aauth-{}", uuid::Uuid::now_v7());
    let fd = openat(
        &directory,
        temporary.as_str(),
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|e| failure(e.to_string()))?;
    let result: Result<()> = (|| {
        let mut file = std::fs::File::from(fd);
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| failure(e.to_string()))?;
        file.write_all(bytes).map_err(|e| failure(e.to_string()))?;
        file.sync_all().map_err(|e| failure(e.to_string()))?;
        if force {
            // renameat replaces a directory entry atomically. Even if an
            // attacker swaps the destination to a symlink, its target is untouched.
            renameat(&directory, temporary.as_str(), &directory, name)
                .map_err(|e| failure(e.to_string()))?;
        } else {
            // linkat atomically refuses every existing destination, including
            // dangling symlinks created after the earlier diagnostic check.
            linkat(
                &directory,
                temporary.as_str(),
                &directory,
                name,
                AtFlags::empty(),
            )
            .map_err(|e| failure(e.to_string()))?;
        }
        Ok(())
    })();
    // A successful rename already removed the temporary name.
    let cleanup = unlinkat(&directory, temporary.as_str(), UnlinkatFlags::NoRemoveDir);
    result?;
    if let Err(error) = cleanup
        && error != nix::errno::Errno::ENOENT
    {
        return Err(failure(error.to_string()));
    }
    std::fs::File::from(directory)
        .sync_all()
        .map_err(|e| failure(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

    fn private_directory() -> tempfile::TempDir {
        tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir()
            .expect("private tempdir")
    }

    #[test]
    fn concurrent_creation_has_one_winner_and_no_partial_or_temporary_files() {
        let root = private_directory();
        let path = root.path().join("identity.pem");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let threads: Vec<_> = (0..8)
            .map(|n| {
                let barrier = barrier.clone();
                let path = path.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store(&path, format!("complete key {n}").as_bytes(), false).is_ok()
                })
            })
            .collect();
        let winners = threads
            .into_iter()
            .map(|thread| thread.join().expect("join"))
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
        assert!(
            std::fs::read_to_string(&path)
                .expect("read")
                .starts_with("complete key ")
        );
        assert_eq!(std::fs::read_dir(root.path()).expect("list").count(), 1);
        assert_eq!(path.metadata().expect("metadata").mode() & 0o777, 0o600);
    }

    #[test]
    fn refuses_live_and_dangling_symlinks_even_with_force() {
        for exists in [false, true] {
            for force in [false, true] {
                let root = private_directory();
                let target = root.path().join("target");
                if exists {
                    std::fs::write(&target, b"untouched").expect("write target");
                }
                let path = root.path().join("key");
                symlink(&target, &path).expect("symlink");
                assert!(store(&path, b"new secret", force).is_err());
                assert!(path.is_symlink());
                if exists {
                    assert_eq!(std::fs::read(&target).expect("read"), b"untouched");
                } else {
                    assert!(!target.exists());
                }
            }
        }
    }

    #[test]
    fn force_replaces_inode_without_modifying_existing_hardlinks() {
        let root = private_directory();
        let path = root.path().join("key");
        store(&path, b"old secret", false).expect("create");
        let alias = root.path().join("old-key-alias");
        std::fs::hard_link(&path, &alias).expect("hard link");
        assert!(store(&path, b"must not write", false).is_err());
        store(&path, b"replacement secret", true).expect("replace");
        assert_eq!(std::fs::read(&alias).expect("old inode"), b"old secret");
        assert_eq!(
            std::fs::read(&path).expect("new inode"),
            b"replacement secret"
        );
        assert_ne!(
            path.metadata().expect("metadata").ino(),
            alias.metadata().expect("metadata").ino()
        );
    }

    #[test]
    fn creates_private_directories_and_rejects_shared_writable_directory() {
        let root = private_directory();
        let directory = root.path().join("keys");
        store(&directory.join("key"), b"secret", false).expect("create private directory");
        assert_eq!(
            directory.metadata().expect("metadata").mode() & 0o777,
            0o700
        );
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o777))
            .expect("chmod");
        assert!(store(&directory.join("other-key"), b"secret", false).is_err());
        assert!(!directory.join("other-key").exists());
    }
}
