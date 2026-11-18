//! Watch a sandbox's mount namespace for masks that the host removes
//! (NEP-0004, Phase 2).
//!
//! A mask is a mount on a host dentry. When a host process unlinks, renames
//! over, or removes that dentry, the kernel detaches every mount on it in
//! every mount namespace. A daemon or socket-unit restart therefore removes
//! the mask over its socket, and the recreated socket becomes reachable from
//! the sandbox. The same happens when the host unmounts and remounts a path
//! a mask covers, such as `/run/user/<uid>` at logout and login.
//!
//! [`MountMaskWatch`] pins the sandbox's mount namespace, records which mounts
//! sit at or above each masked path once the masks are in place, and reports
//! when that set changes. The sandboxed process holds no capabilities in that
//! namespace, so only the host can change it. The caller decides what to do;
//! [`MountMaskWatch::terminate_sandbox`] kills every process in the sandbox's
//! user namespace and in any user namespace nested below it.

use super::linux_mount_mask::PreparedMountMask;
use crate::error::{NonoError, Result};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

/// `NS_GET_PARENT` from `linux/nsfs.h`: `_IO(0xb7, 0x2)`.
///
/// Typed as `libc::Ioctl` because the request type is `c_ulong` on glibc but
/// `c_int` on musl.
const NS_GET_PARENT: libc::Ioctl = 0xb702;
/// User namespaces nest at most 32 deep.
const MAX_USERNS_DEPTH: usize = 33;
/// Rounds of scanning and killing before giving up on a forking sandbox.
const MAX_KILL_ROUNDS: usize = 64;

/// One mount, as identified by `/proc/<pid>/mountinfo`.
type MountKey = (u64, String);

/// Watches a sandbox's mount namespace for masks the host removes.
#[derive(Debug)]
pub struct MountMaskWatch {
    /// `/proc/<pid>/mountinfo` opened while the sandbox was still trusted.
    /// The open file keeps reading the namespace it was opened in, even if
    /// the process later enters another one.
    mountinfo: File,
    /// The sandbox's user namespace.
    userns: OwnedFd,
    /// For each masked path, the mounts at or above it once masks were applied.
    expected: Vec<(PathBuf, BTreeSet<MountKey>)>,
}

impl MountMaskWatch {
    /// Pin the mount and user namespaces of `pid` and record the mounts that
    /// cover each path `plan` masks.
    ///
    /// Call it after the child has applied `plan` and before it runs any
    /// untrusted code, so the recorded state is the one nono created.
    ///
    /// # Errors
    ///
    /// Returns an error if the namespaces cannot be opened, the mount table
    /// cannot be read, or a masked path has no mount in it.
    pub fn attach(pid: libc::pid_t, plan: &PreparedMountMask) -> Result<Self> {
        let mut mountinfo = File::open(format!("/proc/{pid}/mountinfo")).map_err(|error| {
            NonoError::SandboxInit(format!("cannot open the sandbox mount table: {error}"))
        })?;
        let userns: OwnedFd = File::open(format!("/proc/{pid}/ns/user"))
            .map_err(|error| {
                NonoError::SandboxInit(format!("cannot open the sandbox user namespace: {error}"))
            })?
            .into();
        let table = read_table(&mut mountinfo)?;
        let mut expected = Vec::new();
        for path in plan.masked_paths() {
            let covering = covering_mounts(&table, path);
            // The mask itself is a mount at exactly this path.
            if !table.iter().any(|(point, _)| point == path) {
                return Err(NonoError::SandboxInit(format!(
                    "mount mask over {} is not in the sandbox mount table",
                    path.display()
                )));
            }
            expected.push((path.to_path_buf(), covering));
        }
        Ok(Self {
            mountinfo,
            userns,
            expected,
        })
    }

    /// The descriptor to poll: it reports `POLLPRI` when the namespace's
    /// mount table changes.
    #[must_use]
    pub fn poll_fd(&self) -> RawFd {
        self.mountinfo.as_raw_fd()
    }

    /// Wait up to `timeout_ms` for the mount table to change.
    ///
    /// # Errors
    ///
    /// Returns an error if `poll(2)` fails for a reason other than a signal.
    pub fn wait(&self, timeout_ms: i32) -> Result<bool> {
        let mut pfd = libc::pollfd {
            fd: self.poll_fd(),
            events: libc::POLLPRI,
            revents: 0,
        };
        // SAFETY: `pfd` is a live stack value and the count is 1.
        let ready = unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                return Ok(false);
            }
            return Err(NonoError::SandboxInit(format!(
                "cannot watch the sandbox mount table: {error}"
            )));
        }
        Ok(ready > 0)
    }

    /// Re-read the mount table and return the first masked path whose
    /// covering mounts changed since [`attach`](Self::attach), or `None`.
    ///
    /// # Errors
    ///
    /// Returns an error if the mount table cannot be read. Callers should
    /// treat that as a lost mask.
    pub fn removed_mask(&mut self) -> Result<Option<PathBuf>> {
        let table = read_table(&mut self.mountinfo)?;
        Ok(self
            .expected
            .iter()
            .find(|(path, expected)| covering_mounts(&table, path) != *expected)
            .map(|(path, _)| path.clone()))
    }

    /// Kill every process in the sandbox's user namespace, or in a user
    /// namespace nested below it, and return how many were signalled.
    ///
    /// Processes are found by namespace, not by process id or ancestry, so a
    /// process that reparented or started a new session is still found, and
    /// an unrelated process cannot be hit by id reuse.
    ///
    /// # Errors
    ///
    /// Returns an error if `/proc` cannot be listed, or if processes are still
    /// being created after repeated rounds.
    pub fn terminate_sandbox(&self) -> Result<usize> {
        let target = identity(self.userns.as_raw_fd())?;
        let mut total = 0_usize;
        for _ in 0..MAX_KILL_ROUNDS {
            let killed = kill_round(target)?;
            if killed == 0 {
                return Ok(total);
            }
            total = total.saturating_add(killed);
        }
        Err(NonoError::SandboxInit(
            "sandbox processes kept appearing while being terminated".to_string(),
        ))
    }
}

fn read_table(file: &mut File) -> Result<Vec<(PathBuf, MountKey)>> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        NonoError::SandboxInit(format!("cannot read the sandbox mount table: {error}"))
    })?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw).map_err(|error| {
        NonoError::SandboxInit(format!("cannot read the sandbox mount table: {error}"))
    })?;
    Ok(parse_mountinfo(&raw))
}

/// Parse `mountinfo` into (mount point, (mount id, device)) entries.
fn parse_mountinfo(raw: &[u8]) -> Vec<(PathBuf, MountKey)> {
    raw.split(|byte| *byte == b'\n')
        .filter_map(|line| {
            let mut fields = line.split(|byte| *byte == b' ');
            let id = std::str::from_utf8(fields.next()?).ok()?.parse().ok()?;
            let _parent = fields.next()?;
            let device = String::from_utf8_lossy(fields.next()?).into_owned();
            let _root = fields.next()?;
            let point = unescape(fields.next()?);
            Some((point, (id, device)))
        })
        .collect()
}

/// Undo the kernel's octal escaping of space, tab, newline and backslash.
fn unescape(field: &[u8]) -> PathBuf {
    let mut out = Vec::with_capacity(field.len());
    let mut index = 0;
    while index < field.len() {
        let octal = field.get(index + 1..index + 4).filter(|digits| {
            field[index] == b'\\' && digits.iter().all(|d| (b'0'..=b'7').contains(d))
        });
        match octal {
            Some(digits) => {
                let value = digits
                    .iter()
                    .fold(0_u32, |acc, digit| acc * 8 + u32::from(digit - b'0'));
                out.push(u8::try_from(value).unwrap_or(b'?'));
                index += 4;
            }
            None => {
                out.push(field[index]);
                index += 1;
            }
        }
    }
    PathBuf::from(std::ffi::OsStr::from_bytes(&out))
}

/// Mounts whose mount point is `path` or one of its ancestors. A mask is lost
/// if its own mount goes, and hidden if a new mount lands at or above it.
fn covering_mounts(table: &[(PathBuf, MountKey)], path: &Path) -> BTreeSet<MountKey> {
    table
        .iter()
        .filter(|(point, _)| path.starts_with(point))
        .map(|(_, key)| key.clone())
        .collect()
}

fn identity(fd: RawFd) -> Result<(u64, u64)> {
    // SAFETY: zeroed stat is valid storage for the kernel to fill.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is live stack storage and `fd` is open.
    if unsafe { libc::fstat(fd, &mut stat) } < 0 {
        return Err(NonoError::SandboxInit(format!(
            "cannot identify the sandbox user namespace: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok((stat.st_dev, stat.st_ino))
}

/// Whether the user namespace `fd` is `target` or nested below it. Consumes
/// `fd`.
fn within_userns(fd: OwnedFd, target: (u64, u64)) -> bool {
    let mut current = fd;
    for _ in 0..MAX_USERNS_DEPTH {
        match identity(current.as_raw_fd()) {
            Ok(id) if id == target => return true,
            Ok(_) => {}
            Err(_) => return false,
        }
        // SAFETY: NS_GET_PARENT takes no argument and returns a new fd.
        let parent = unsafe { libc::ioctl(current.as_raw_fd(), NS_GET_PARENT) };
        if parent < 0 {
            // EPERM at the top of the caller's namespace tree.
            return false;
        }
        // SAFETY: the ioctl returned a fresh descriptor that we now own.
        current = unsafe { OwnedFd::from_raw_fd(parent) };
    }
    false
}

fn kill_round(target: (u64, u64)) -> Result<usize> {
    let entries = std::fs::read_dir("/proc")
        .map_err(|error| NonoError::SandboxInit(format!("cannot list processes: {error}")))?;
    // SAFETY: getpid takes no arguments and cannot fail.
    let own = unsafe { libc::getpid() };
    let mut killed = 0;
    for entry in entries.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|name| name.parse::<libc::pid_t>().ok())
        else {
            continue;
        };
        if pid == own {
            continue;
        }
        // Pin the process first, so the namespace check and the signal
        // refer to the same process even if the id is reused.
        // SAFETY: scalar arguments.
        let pidfd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
        if pidfd < 0 {
            continue;
        }
        // SAFETY: pidfd_open returned a fresh descriptor that we now own.
        let pidfd = unsafe { OwnedFd::from_raw_fd(pidfd as RawFd) };
        let Ok(userns) = File::open(format!("/proc/{pid}/ns/user")) else {
            continue;
        };
        // The pidfd was opened first: if `pid` now names a different process,
        // the original has exited and the signal below fails with ESRCH.
        if !within_userns(userns.into(), target) {
            continue;
        }
        // SAFETY: scalar arguments; a null siginfo sends a plain SIGKILL.
        let sent = unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        };
        if sent == 0 {
            killed += 1;
        }
    }
    Ok(killed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"22 1 0:21 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
        30 22 0:25 / /run rw,nosuid shared:5 - tmpfs tmpfs rw\n\
        41 30 0:40 / /run/user/1000 rw,nosuid shared:20 - tmpfs tmpfs rw\n\
        90 41 0:90 / /run/user/1000 rw,nosuid - tmpfs tmpfs rw\n\
        91 30 0:5 /null /run/docker.sock ro,nosuid - devtmpfs devtmpfs rw\n\
        92 22 0:91 / /mnt/with\\040space rw - tmpfs tmpfs rw\n";

    #[test]
    fn parses_mount_points_and_escapes() {
        let table = parse_mountinfo(SAMPLE);
        assert_eq!(table.len(), 6);
        assert_eq!(
            table[3],
            (PathBuf::from("/run/user/1000"), (90, "0:90".into()))
        );
        assert_eq!(table[5].0, PathBuf::from("/mnt/with space"));
    }

    #[test]
    fn covering_mounts_include_ancestors_and_stacked_mounts() {
        let table = parse_mountinfo(SAMPLE);
        let covering = covering_mounts(&table, Path::new("/run/user/1000"));
        let ids: Vec<u64> = covering.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![22, 30, 41, 90]);
        // A sibling path is not an ancestor.
        let docker = covering_mounts(&table, Path::new("/run/docker.sock"));
        assert!(docker.iter().all(|(id, _)| *id != 41 && *id != 90));
    }

    #[test]
    fn a_detached_mask_changes_the_covering_set() {
        let before = covering_mounts(&parse_mountinfo(SAMPLE), Path::new("/run/docker.sock"));
        let detached: Vec<u8> = SAMPLE
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.starts_with(b"91 "))
            .flat_map(|line| line.iter().copied().chain(std::iter::once(b'\n')))
            .collect();
        let after = covering_mounts(&parse_mountinfo(&detached), Path::new("/run/docker.sock"));
        assert_ne!(before, after);
    }
}
