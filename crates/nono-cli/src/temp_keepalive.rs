//! Keep session-lifetime temp artifacts alive against the OS temp reaper.
//!
//! nono writes several files it holds for the whole session into the OS
//! temporary directory (`std::env::temp_dir()`, and `/private/tmp` for the
//! macOS command-mediation runtime): the capability manifest exposed as
//! `NONO_CAP_FILE`, the URL-open listener socket and its browser shim, and the
//! command-mediation runtime directory (mediation sockets and shim binaries). These
//! are only accessed on demand, so a session that sits idle stops refreshing
//! their access time.
//!
//! [`PreparedTempKeepalive`] pins each root (and each directory below it) by
//! file descriptor before the sandboxed child can execute. [`TempKeepalive`]
//! then spawns one background thread after `fork()` and periodically refreshes
//! those descriptors and their direct children. Descriptor-relative refreshes
//! cannot be redirected through a renamed directory or an intermediate
//! symlink. The refresh is strictly best-effort: it never grants or widens a
//! capability, and any error is logged at debug and ignored.

use std::ffi::{OsStr, OsString};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

use nix::dir::Dir;
use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::{Mode, SFlag, UtimensatFlags, fstat, futimens, utimensat};
use nix::sys::time::TimeSpec;
use tracing::debug;

const REFRESH_INTERVAL: Duration = Duration::from_secs(60 * 60);

const OPEN_ROOT_FLAGS: OFlag = OFlag::O_RDONLY
    .union(OFlag::O_CLOEXEC)
    .union(OFlag::O_NOFOLLOW);
const OPEN_DIR_FLAGS: OFlag = OPEN_ROOT_FLAGS.union(OFlag::O_DIRECTORY);

enum RefreshTarget {
    /// A root file or pinned directory.
    Descriptor { fd: Arc<OwnedFd>, display: PathBuf },
    /// A direct child of a pinned directory. `name` is exactly one component,
    /// so `NoFollowSymlink` protects the complete lookup.
    DirectChild {
        parent: Arc<OwnedFd>,
        name: OsString,
        display: PathBuf,
    },
}

impl RefreshTarget {
    fn refresh(&self) {
        let result = match self {
            Self::Descriptor { fd, .. } => {
                futimens(fd.as_ref(), &TimeSpec::UTIME_NOW, &TimeSpec::UTIME_NOW)
            }
            Self::DirectChild { parent, name, .. } => utimensat(
                parent.as_ref(),
                Path::new(name),
                &TimeSpec::UTIME_NOW,
                &TimeSpec::UTIME_NOW,
                UtimensatFlags::NoFollowSymlink,
            ),
        };
        if let Err(error) = result {
            debug!("temp keepalive touch {}: {error}", self.display().display());
        }
    }

    fn display(&self) -> &Path {
        match self {
            Self::Descriptor { display, .. } | Self::DirectChild { display, .. } => display,
        }
    }
}

/// Session artifacts resolved to stable descriptors before the child can run.
///
/// Preparing does not create a thread, so it is safe before `fork()`. Starting
/// consumes this value and moves the descriptors into the keepalive thread.
pub(crate) struct PreparedTempKeepalive {
    targets: Vec<RefreshTarget>,
}

impl PreparedTempKeepalive {
    /// Spawn the keepalive thread. Must be called in the parent after `fork()`.
    pub(crate) fn start(self) -> TempKeepalive {
        if self.targets.is_empty() {
            return TempKeepalive {
                stop: None,
                handle: None,
            };
        }
        let (tx, rx) = mpsc::channel::<()>();
        let spawned = std::thread::Builder::new()
            .name("nono-temp-keepalive".to_string())
            .spawn(move || {
                while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(REFRESH_INTERVAL) {
                    refresh_all(&self.targets);
                }
            });
        match spawned {
            Ok(handle) => TempKeepalive {
                stop: Some(tx),
                handle: Some(handle),
            },
            Err(error) => {
                debug!("temp keepalive thread not started: {error}");
                TempKeepalive {
                    stop: None,
                    handle: None,
                }
            }
        }
    }
}

/// A running keepalive. Dropping it stops and joins the thread before teardown.
pub(crate) struct TempKeepalive {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl TempKeepalive {
    /// Pin `paths` without starting a thread.
    ///
    /// Directory roots are opened with `O_NOFOLLOW`, recursively enumerated
    /// through descriptor-relative lookups, and represented by one descriptor
    /// per directory plus one basename per direct child. Missing or unsafe
    /// roots are skipped because the keepalive is best-effort.
    pub(crate) fn prepare(paths: Vec<PathBuf>) -> PreparedTempKeepalive {
        let mut targets = Vec::new();
        for path in paths {
            prepare_root(&path, &mut targets);
        }
        PreparedTempKeepalive { targets }
    }
}

impl Drop for TempKeepalive {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn prepare_root(path: &Path, targets: &mut Vec<RefreshTarget>) {
    let fd = match open(path, OPEN_ROOT_FLAGS, Mode::empty()) {
        Ok(fd) => Arc::new(fd),
        Err(error) => {
            debug!("temp keepalive cannot pin {}: {error}", path.display());
            return;
        }
    };
    let is_dir = fstat(fd.as_ref())
        .map(|stat| SFlag::from_bits_truncate(stat.st_mode).contains(SFlag::S_IFDIR))
        .unwrap_or(false);
    targets.push(RefreshTarget::Descriptor {
        fd: Arc::clone(&fd),
        display: path.to_path_buf(),
    });
    if is_dir {
        prepare_directory(fd, path, targets);
    }
}

fn prepare_directory(
    directory: Arc<OwnedFd>,
    display_path: &Path,
    targets: &mut Vec<RefreshTarget>,
) {
    let scan_fd = match directory.as_ref().try_clone() {
        Ok(fd) => fd,
        Err(error) => {
            debug!(
                "temp keepalive cannot duplicate directory {}: {error}",
                display_path.display()
            );
            return;
        }
    };
    let mut entries = match Dir::from_fd(scan_fd) {
        Ok(entries) => entries,
        Err(error) => {
            debug!(
                "temp keepalive cannot enumerate directory {}: {error}",
                display_path.display()
            );
            return;
        }
    };

    for entry in entries.iter() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                debug!(
                    "temp keepalive enumeration under {}: {error}",
                    display_path.display()
                );
                continue;
            }
        };
        let name_bytes = entry.file_name().to_bytes();
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }
        let name = OsStr::from_bytes(name_bytes);
        let child_display = display_path.join(name);

        match openat(
            directory.as_ref(),
            entry.file_name(),
            OPEN_DIR_FLAGS,
            Mode::empty(),
        ) {
            Ok(child_dir) => {
                let child_dir = Arc::new(child_dir);
                targets.push(RefreshTarget::Descriptor {
                    fd: Arc::clone(&child_dir),
                    display: child_display.clone(),
                });
                prepare_directory(child_dir, &child_display, targets);
            }
            Err(_) => targets.push(RefreshTarget::DirectChild {
                parent: Arc::clone(&directory),
                name: name.to_os_string(),
                display: child_display,
            }),
        }
    }
}

fn refresh_all(targets: &[RefreshTarget]) {
    for target in targets {
        target.refresh();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::fcntl::AT_FDCWD;
    use std::time::{Duration, SystemTime};

    fn backdate(path: &Path) {
        let past = SystemTime::now() - Duration::from_secs(7 * 24 * 60 * 60);
        let ts = TimeSpec::from_duration(
            past.duration_since(SystemTime::UNIX_EPOCH)
                .expect("epoch is in the past"),
        );
        utimensat(AT_FDCWD, path, &ts, &ts, UtimensatFlags::NoFollowSymlink)
            .expect("backdate via utimensat");
    }

    fn mtime(path: &Path) -> SystemTime {
        std::fs::symlink_metadata(path)
            .expect("metadata")
            .modified()
            .expect("mtime")
    }

    #[test]
    fn refresh_touches_file_and_directory_contents() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("leaf.sock");
        std::fs::write(&file, b"x").expect("write leaf");
        let nested_dir = dir.path().join("shims");
        std::fs::create_dir(&nested_dir).expect("mkdir nested");
        let nested_file = nested_dir.join("git");
        std::fs::write(&nested_file, b"y").expect("write nested");

        let prepared = TempKeepalive::prepare(vec![dir.path().to_path_buf()]);
        for path in [
            dir.path(),
            file.as_path(),
            nested_dir.as_path(),
            nested_file.as_path(),
        ] {
            backdate(path);
        }
        let before = mtime(&nested_file);

        refresh_all(&prepared.targets);

        assert!(
            mtime(&nested_file) > before,
            "nested file mtime should advance after refresh"
        );
    }

    #[test]
    fn refresh_uses_pinned_directories_after_path_replacement() {
        let container = tempfile::tempdir().expect("container");
        let root = container.path().join("session");
        std::fs::create_dir(&root).expect("create session");
        let original_leaf = root.join("leaf");
        std::fs::write(&original_leaf, b"original").expect("write original leaf");
        let prepared = TempKeepalive::prepare(vec![root.clone()]);

        let pinned_root = container.path().join("pinned-session");
        std::fs::rename(&root, &pinned_root).expect("rename original root");
        let outside = container.path().join("outside");
        std::fs::create_dir(&outside).expect("create outside");
        let outside_leaf = outside.join("leaf");
        std::fs::write(&outside_leaf, b"outside").expect("write outside leaf");
        std::os::unix::fs::symlink(&outside, &root).expect("replace root with symlink");
        backdate(&outside_leaf);
        let outside_before = mtime(&outside_leaf);

        refresh_all(&prepared.targets);

        assert_eq!(
            mtime(&outside_leaf),
            outside_before,
            "replacement symlink must not redirect the refresh"
        );
        assert!(
            mtime(&pinned_root.join("leaf")) > outside_before,
            "the pinned original tree should still be refreshed"
        );
    }

    #[test]
    fn prepare_handles_missing_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let prepared = TempKeepalive::prepare(vec![dir.path().join("gone.json")]);
        assert!(prepared.targets.is_empty());
    }

    #[test]
    fn empty_paths_spawns_no_thread() {
        let keepalive = TempKeepalive::prepare(Vec::new()).start();
        assert!(keepalive.handle.is_none());
        drop(keepalive);
    }

    #[test]
    fn drop_stops_the_thread_promptly() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join(".nono-test.json");
        std::fs::write(&file, b"{}").expect("write");
        let keepalive = TempKeepalive::prepare(vec![file]).start();
        let start = std::time::Instant::now();
        drop(keepalive);
        assert!(
            start.elapsed() < REFRESH_INTERVAL,
            "drop should not wait out the refresh interval"
        );
    }
}
