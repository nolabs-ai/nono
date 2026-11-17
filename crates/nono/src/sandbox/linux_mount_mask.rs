//! Opt-in Linux mount masking mechanism (NEP-0004, Phase 2).
//!
//! This module is mechanism only. The caller supplies the paths to mask and
//! the paths to re-bind through the masks; this library never decides which
//! host endpoints are masked. Those decisions belong to the CLI.
//!
//! A mask hides a host path inside the child's private mount namespace:
//!
//! - a directory is covered by an empty, private `tmpfs`;
//! - any other file type (sockets included) is covered by a read-only,
//!   `nodev` bind of `/dev/null`, so a pathname `connect(2)` reaches a device
//!   node that is not a socket and fails.
//!
//! A re-bind makes a host path that lies beneath a directory mask visible
//! again at its original location, by bind-mounting the original inode onto a
//! mount point created inside the mask's `tmpfs`.
//!
//! Preparation ([`PreparedMountMask::prepare`]) runs in the parent and may
//! allocate. It validates every path, records the inode it must still be when
//! the child opens it, orders the operations, and drops operations that would
//! have no effect. Application ([`PreparedMountMask::apply_raw`]) runs in the
//! namespaced child before Landlock is applied. It uses raw syscalls only and
//! never allocates, so it is safe in a `clone(2)` child of a multi-threaded
//! parent.
//!
//! Every host path is opened by descriptor with `openat2(RESOLVE_NO_SYMLINKS)`
//! and checked against the device and inode the parent recorded, and every
//! mount is attached to a descriptor with `move_mount(2)`. No mount syscall
//! takes a path that could be swapped between check and use.

use super::linux::raw_errno;
use crate::error::{NonoError, Result};
use std::cell::Cell;
use std::ffi::CString;
use std::os::fd::RawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

const FSOPEN_CLOEXEC: libc::c_uint = 0x1;
const FSCONFIG_SET_STRING: libc::c_uint = 1;
const FSCONFIG_CMD_CREATE: libc::c_uint = 6;
const FSMOUNT_CLOEXEC: libc::c_uint = 0x1;
const MOUNT_ATTR_RDONLY: u64 = 0x1;
const MOUNT_ATTR_NOSUID: u64 = 0x2;
const MOUNT_ATTR_NODEV: u64 = 0x4;
const MOUNT_ATTR_NOEXEC: u64 = 0x8;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
const MOVE_MOUNT_T_EMPTY_PATH: libc::c_uint = 0x40;
const OPEN_TREE_CLONE: libc::c_uint = 0x1;
const OPEN_TREE_CLOEXEC: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
const AT_EMPTY_PATH: libc::c_uint = libc::AT_EMPTY_PATH as libc::c_uint;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const MS_PRIVATE: u64 = 1 << 18;
/// Mode of directories created inside a mask's tmpfs to hold re-bind mount
/// points. Their contents are the re-bound host inodes, which keep their own
/// permissions.
const MOUNTPOINT_DIR_MODE: libc::mode_t = 0o755;
const MOUNTPOINT_FILE_MODE: libc::mode_t = 0o600;
/// Upper bound on operations, so failure records can carry an index in u16.
const MAX_OPERATIONS: usize = 4096;

/// `struct mount_attr` for `mount_setattr(2)`.
#[repr(C)]
struct RawMountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

/// `struct open_how` for `openat2(2)`.
#[repr(C)]
struct RawOpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

/// A path to mask in the child's mount namespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountMask {
    path: PathBuf,
    tmpfs_mode: u32,
    tmpfs_size: Option<u64>,
    tmpfs_inodes: Option<u64>,
}

impl MountMask {
    /// Mask `path`. A directory is covered by an empty tmpfs with mode 0700;
    /// any other file type by an inert, read-only `/dev/null` bind.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            tmpfs_mode: 0o700,
            tmpfs_size: None,
            tmpfs_inodes: None,
        }
    }

    /// Set the permission bits of the tmpfs that covers a directory mask.
    /// Ignored for non-directory masks. Only the low 12 bits are used.
    #[must_use]
    pub fn tmpfs_mode(mut self, mode: u32) -> Self {
        self.tmpfs_mode = mode & 0o7777;
        self
    }

    /// Limit the tmpfs that covers a directory mask to `size` bytes and
    /// `inodes` inodes. Without a limit the kernel default applies (half of
    /// RAM). Ignored for non-directory masks. Zero means "kernel default".
    #[must_use]
    pub fn tmpfs_limits(mut self, size: u64, inodes: u64) -> Self {
        self.tmpfs_size = (size > 0).then_some(size);
        self.tmpfs_inodes = (inodes > 0).then_some(inodes);
        self
    }

    /// The masked path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

/// Why a requested mask or re-bind is not part of the prepared plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MountSkipReason {
    /// The path does not exist on the host, so there is nothing to mask or
    /// re-bind. A path created after preparation is not masked.
    Missing,
    /// A parent directory denies search permission to the caller, so the path
    /// cannot be reached by path from the sandbox either.
    Inaccessible,
    /// A re-bind exactly at a directory mask would undo the mask. The mask is
    /// kept; only paths strictly beneath a directory mask are re-bound.
    ReplacesDirectoryMask,
}

/// A requested mask or re-bind that the prepared plan does not apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedMount {
    /// The requested path.
    pub path: PathBuf,
    /// Whether it was requested as a mask (`true`) or a re-bind (`false`).
    pub is_mask: bool,
    /// Why it is not applied.
    pub reason: MountSkipReason,
}

/// The step of [`PreparedMountMask::apply_raw`] that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MountMaskStep {
    /// Opening a mask target, re-bind source, or `/dev/null` by descriptor.
    Open,
    /// The opened inode is not the one recorded at preparation, or `/dev/null`
    /// is not the null device.
    Verify,
    /// Creating the tmpfs that covers a directory mask.
    CreateTmpfs,
    /// Creating a re-bind mount point inside a mask's tmpfs.
    CreateMountPoint,
    /// Cloning the source mount tree for a bind.
    CloneTree,
    /// Setting mount attributes or propagation.
    SetAttributes,
    /// Attaching the new mount over its target.
    Attach,
}

impl MountMaskStep {
    /// Stable wire code, for passing a failure across a process boundary.
    #[must_use]
    pub fn code(self) -> u8 {
        match self {
            Self::Open => 1,
            Self::Verify => 2,
            Self::CreateTmpfs => 3,
            Self::CreateMountPoint => 4,
            Self::CloneTree => 5,
            Self::SetAttributes => 6,
            Self::Attach => 7,
        }
    }

    /// Inverse of [`code`](Self::code).
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Some(match code {
            1 => Self::Open,
            2 => Self::Verify,
            3 => Self::CreateTmpfs,
            4 => Self::CreateMountPoint,
            5 => Self::CloneTree,
            6 => Self::SetAttributes,
            7 => Self::Attach,
            _ => return None,
        })
    }

    /// A short description of the step, for diagnostics.
    #[must_use]
    pub fn describe(self) -> &'static str {
        match self {
            Self::Open => "opening the path by descriptor",
            Self::Verify => "verifying the opened inode",
            Self::CreateTmpfs => "creating the masking tmpfs",
            Self::CreateMountPoint => "creating the re-bind mount point",
            Self::CloneTree => "cloning the mount to bind",
            Self::SetAttributes => "setting mount attributes",
            Self::Attach => "attaching the mount",
        }
    }
}

/// Fixed-size error from [`PreparedMountMask::apply_raw`]. Owns no heap data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawMountMaskError {
    step: MountMaskStep,
    operation: u16,
    errno: i32,
}

impl RawMountMaskError {
    /// Rebuild an error from its parts, for example after receiving them from
    /// the child.
    #[must_use]
    pub fn new(step: MountMaskStep, operation: u16, errno: i32) -> Self {
        Self {
            step,
            operation,
            errno,
        }
    }

    /// The failed step.
    #[must_use]
    pub fn step(self) -> MountMaskStep {
        self.step
    }

    /// Index of the failed operation; see [`PreparedMountMask::operation_path`].
    #[must_use]
    pub fn operation(self) -> u16 {
        self.operation
    }

    /// The errno the step reported.
    #[must_use]
    pub fn errno(self) -> i32 {
        self.errno
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Identity {
    dev: u64,
    ino: u64,
    is_dir: bool,
}

#[derive(Debug)]
enum OperationKind {
    /// tmpfs over a directory, with its `mode=`, `size=` and `nr_inodes=`
    /// values.
    MaskDirectory {
        mode: CString,
        size: Option<CString>,
        inodes: Option<CString>,
    },
    /// Inert `/dev/null` bind over a non-directory.
    MaskFile,
    /// Bind the host inode at `target` back over a mask. `base` indexes the
    /// directory mask it lies beneath; `components` lead from that mask's
    /// root to `target`. `slot` indexes the pre-opened source descriptors.
    Rebind {
        base: usize,
        components: Vec<CString>,
        slot: usize,
    },
}

#[derive(Debug)]
struct Operation {
    path: PathBuf,
    target: CString,
    identity: Identity,
    kind: OperationKind,
}

/// A validated, ordered set of mount masks and re-binds, ready to apply in a
/// namespaced child without allocation.
///
/// Operations are ordered so that a path is masked before anything beneath it
/// is re-bound, and a re-bind happens before anything beneath it is masked.
#[derive(Debug)]
pub struct PreparedMountMask {
    operations: Vec<Operation>,
    /// Re-bind sources opened by the child before any mask is mounted. The
    /// child writes its own copy of these cells; the parent never reads them.
    sources: Vec<Cell<RawFd>>,
    skipped: Vec<SkippedMount>,
}

impl PreparedMountMask {
    /// Validate and order `masks` and `rebinds`.
    ///
    /// Every path must be absolute and canonical (no symlinks, `.` or `..`).
    /// Paths that do not exist are skipped and reported. A re-bind is applied
    /// only where a mask hides it: strictly beneath a directory mask, or
    /// exactly at a non-directory mask (which the re-bind then replaces).
    /// Masks that an earlier mask already hides, and re-binds of paths that
    /// stay visible anyway, are dropped because they would have no effect.
    ///
    /// # Errors
    ///
    /// Returns an error for a relative or non-canonical path, a path that
    /// cannot be inspected for a reason other than not existing, or a plan
    /// with more operations than can be reported.
    pub fn prepare(masks: &[MountMask], rebinds: &[PathBuf]) -> Result<Self> {
        let mut skipped = Vec::new();
        let mut mask_entries: Vec<(PathBuf, &MountMask, Identity)> = Vec::new();
        for mask in masks {
            if mask.path.parent().is_none() {
                return Err(NonoError::SandboxInit(
                    "the filesystem root cannot be masked".to_string(),
                ));
            }
            let identity = match inspect(&mask.path)? {
                Ok(identity) => identity,
                Err(reason) => {
                    skipped.push(SkippedMount {
                        path: mask.path.clone(),
                        is_mask: true,
                        reason,
                    });
                    continue;
                }
            };
            if !mask_entries.iter().any(|(path, ..)| *path == mask.path) {
                mask_entries.push((mask.path.clone(), mask, identity));
            }
        }
        let mut rebind_entries: Vec<(PathBuf, Identity)> = Vec::new();
        for path in rebinds {
            let identity = match inspect(path)? {
                Ok(identity) => identity,
                Err(reason) => {
                    skipped.push(SkippedMount {
                        path: path.clone(),
                        is_mask: false,
                        reason,
                    });
                    continue;
                }
            };
            let replaces_directory_mask = mask_entries
                .iter()
                .any(|(mask, _, mask_identity)| mask == path && mask_identity.is_dir);
            if replaces_directory_mask {
                skipped.push(SkippedMount {
                    path: path.clone(),
                    is_mask: false,
                    reason: MountSkipReason::ReplacesDirectoryMask,
                });
                continue;
            }
            if !rebind_entries.iter().any(|(existing, _)| existing == path) {
                rebind_entries.push((path.clone(), identity));
            }
        }
        // A re-bind exactly at a non-directory mask replaces it: drop the mask
        // and let the re-bind be judged against the masks above it.
        mask_entries.retain(|(mask, ..)| !rebind_entries.iter().any(|(path, _)| path == mask));

        // Masks before re-binds at equal depth; shallower paths first.
        let mut planned: Vec<(PathBuf, Identity, Option<&MountMask>)> = mask_entries
            .into_iter()
            .map(|(path, mask, identity)| (path, identity, Some(mask)))
            .chain(
                rebind_entries
                    .into_iter()
                    .map(|(path, identity)| (path, identity, None)),
            )
            .collect();
        planned.sort_by(|a, b| {
            let depth = |path: &Path| path.components().count();
            depth(&a.0)
                .cmp(&depth(&b.0))
                .then_with(|| b.2.is_some().cmp(&a.2.is_some()))
                .then_with(|| a.0.cmp(&b.0))
        });

        let mut operations: Vec<Operation> = Vec::new();
        let mut sources = Vec::new();
        for (path, identity, mask) in planned {
            // The deepest operation already applied at or above this path
            // decides what the child sees here.
            let covering = operations
                .iter()
                .enumerate()
                .filter(|(_, op)| path.starts_with(&op.path))
                .max_by_key(|(_, op)| op.path.components().count());
            let hidden_by = covering.and_then(|(index, op)| match op.kind {
                OperationKind::MaskDirectory { .. } | OperationKind::MaskFile => Some(index),
                OperationKind::Rebind { .. } => None,
            });
            let target = c_path(&path)?;
            match mask {
                Some(mask) => {
                    if hidden_by.is_some() {
                        continue;
                    }
                    let kind = if identity.is_dir {
                        let option = |value: String| {
                            CString::new(value).map_err(|_| {
                                NonoError::SandboxInit("invalid tmpfs option".to_string())
                            })
                        };
                        OperationKind::MaskDirectory {
                            mode: option(format!("{:o}", mask.tmpfs_mode))?,
                            size: mask.tmpfs_size.map(|v| option(v.to_string())).transpose()?,
                            inodes: mask
                                .tmpfs_inodes
                                .map(|v| option(v.to_string()))
                                .transpose()?,
                        }
                    } else {
                        OperationKind::MaskFile
                    };
                    operations.push(Operation {
                        path,
                        target,
                        identity,
                        kind,
                    });
                }
                None => {
                    let Some(base) = hidden_by else {
                        continue;
                    };
                    let base_path = &operations[base].path;
                    if !matches!(operations[base].kind, OperationKind::MaskDirectory { .. })
                        || *base_path == path
                    {
                        continue;
                    }
                    let components = relative_components(base_path, &path)?;
                    operations.push(Operation {
                        path,
                        target,
                        identity,
                        kind: OperationKind::Rebind {
                            base,
                            components,
                            slot: sources.len(),
                        },
                    });
                    sources.push(Cell::new(-1));
                }
            }
        }
        if operations.len() > MAX_OPERATIONS {
            return Err(NonoError::SandboxInit(format!(
                "mount mask plan has {} operations; at most {MAX_OPERATIONS} are supported",
                operations.len()
            )));
        }
        Ok(Self {
            operations,
            sources,
            skipped,
        })
    }

    /// Whether the plan applies nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Paths the plan masks, in application order.
    pub fn masked_paths(&self) -> impl Iterator<Item = &Path> {
        self.operations
            .iter()
            .filter(|op| !matches!(op.kind, OperationKind::Rebind { .. }))
            .map(|op| op.path.as_path())
    }

    /// Paths the plan re-binds through a mask, in application order.
    pub fn rebound_paths(&self) -> impl Iterator<Item = &Path> {
        self.operations
            .iter()
            .filter(|op| matches!(op.kind, OperationKind::Rebind { .. }))
            .map(|op| op.path.as_path())
    }

    /// Requested masks and re-binds the plan does not apply, with reasons.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedMount] {
        &self.skipped
    }

    /// The path of the operation at `index`, as reported by
    /// [`RawMountMaskError::operation`].
    #[must_use]
    pub fn operation_path(&self, index: u16) -> Option<&Path> {
        self.operations
            .get(usize::from(index))
            .map(|op| op.path.as_path())
    }

    /// Whether the operation at `index` is a re-bind (rather than a mask).
    #[must_use]
    pub fn operation_is_rebind(&self, index: u16) -> bool {
        self.operations
            .get(usize::from(index))
            .is_some_and(|op| matches!(op.kind, OperationKind::Rebind { .. }))
    }

    /// Apply the plan in the calling (child) process.
    ///
    /// The caller must be single-threaded, must have unshared a mount
    /// namespace owned by a user namespace in which it holds `CAP_SYS_ADMIN`,
    /// and its uid and gid must already be mapped (re-bind mount points are
    /// created as files in a tmpfs). Run it before any untrusted code and
    /// before Landlock is applied: Landlock forbids mount changes.
    ///
    /// Uses raw syscalls only and never allocates. On error some mounts may
    /// already be in place; the launch must be abandoned.
    ///
    /// # Errors
    ///
    /// Returns the failed step, the operation index and the errno.
    pub fn apply_raw(&self) -> std::result::Result<(), RawMountMaskError> {
        // Open every re-bind source before anything is masked: once a mask is
        // in place the source is no longer reachable by path.
        for (index, op) in self.operations.iter().enumerate() {
            if let OperationKind::Rebind { slot, .. } = op.kind {
                let fail = |step, errno| RawMountMaskError::new(step, index as u16, errno);
                let fd = open_verified(&op.target, op.identity).map_err(|(s, e)| fail(s, e))?;
                if let Some(cell) = self.sources.get(slot) {
                    cell.set(fd);
                } else {
                    close(fd);
                    return Err(fail(MountMaskStep::Open, libc::EINVAL));
                }
            }
        }
        let result = self.apply_operations();
        for cell in &self.sources {
            if cell.get() >= 0 {
                close(cell.get());
                cell.set(-1);
            }
        }
        result
    }

    fn apply_operations(&self) -> std::result::Result<(), RawMountMaskError> {
        let mut null_fd: RawFd = -1;
        let mut result = Ok(());
        for (index, op) in self.operations.iter().enumerate() {
            let step = match &op.kind {
                OperationKind::MaskDirectory { mode, size, inodes } => {
                    mask_directory(op, mode, size.as_ref(), inodes.as_ref())
                }
                OperationKind::MaskFile => {
                    if null_fd < 0 {
                        match open_null() {
                            Ok(fd) => null_fd = fd,
                            Err(error) => {
                                result =
                                    Err(RawMountMaskError::new(error.0, index as u16, error.1));
                                break;
                            }
                        }
                    }
                    mask_file(op, null_fd)
                }
                OperationKind::Rebind {
                    base,
                    components,
                    slot,
                } => match (self.operations.get(*base), self.sources.get(*slot)) {
                    (Some(base), Some(source)) => rebind(
                        &base.target,
                        base.identity,
                        components,
                        source.get(),
                        op.identity.is_dir,
                    ),
                    _ => Err((MountMaskStep::Open, libc::EINVAL)),
                },
            };
            if let Err((step, errno)) = step {
                result = Err(RawMountMaskError::new(step, index as u16, errno));
                break;
            }
        }
        if null_fd >= 0 {
            close(null_fd);
        }
        result
    }
}

/// Probe-only: create (but do not attach) a tmpfs, proving the caller may
/// mount in its current mount namespace.
pub(crate) fn probe_tmpfs_raw() -> std::result::Result<(), i32> {
    let fs = fsopen_tmpfs()?;
    let created = fsconfig_create(fs);
    let mount = created.and_then(|()| fsmount(fs, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV));
    close(fs);
    let mount = mount?;
    close(mount);
    Ok(())
}

fn inspect(path: &Path) -> Result<std::result::Result<Identity, MountSkipReason>> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return Err(NonoError::SandboxInit(format!(
            "mount mask path must be absolute and normalized: {}",
            path.display()
        )));
    }
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Err(MountSkipReason::Missing));
        }
        // The sandbox runs with the caller's uid and no capabilities over the
        // host, so a path the caller cannot reach is unreachable there too.
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            return Ok(Err(MountSkipReason::Inaccessible));
        }
        Err(error) => {
            return Err(NonoError::SandboxInit(format!(
                "cannot inspect mount mask path {}: {error}",
                path.display()
            )));
        }
    };
    let canonical = std::fs::canonicalize(path).map_err(|error| {
        NonoError::SandboxInit(format!(
            "cannot resolve mount mask path {}: {error}",
            path.display()
        ))
    })?;
    if canonical != path || metadata.file_type().is_symlink() {
        return Err(NonoError::SandboxInit(format!(
            "mount mask path must be canonical (no symlinks): {} resolves to {}",
            path.display(),
            canonical.display()
        )));
    }
    Ok(Ok(Identity {
        dev: metadata.dev(),
        ino: metadata.ino(),
        is_dir: metadata.is_dir(),
    }))
}

fn c_path(path: &Path) -> Result<CString> {
    CString::new(path.as_os_str().as_bytes()).map_err(|_| {
        NonoError::SandboxInit(format!(
            "mount mask path contains a NUL byte: {}",
            path.display()
        ))
    })
}

fn relative_components(base: &Path, path: &Path) -> Result<Vec<CString>> {
    let relative = path.strip_prefix(base).map_err(|_| {
        NonoError::SandboxInit(format!(
            "re-bind {} is not beneath mask {}",
            path.display(),
            base.display()
        ))
    })?;
    relative
        .components()
        .map(|component| match component {
            Component::Normal(name) => CString::new(name.as_bytes()).map_err(|_| {
                NonoError::SandboxInit(format!(
                    "re-bind path contains a NUL byte: {}",
                    path.display()
                ))
            }),
            _ => Err(NonoError::SandboxInit(format!(
                "re-bind path is not normalized: {}",
                path.display()
            ))),
        })
        .collect()
}

type StepResult<T> = std::result::Result<T, (MountMaskStep, i32)>;

fn close(fd: RawFd) {
    // SAFETY: closes a descriptor this module opened and still owns.
    unsafe {
        libc::syscall(libc::SYS_close, fd);
    }
}

fn openat2(dirfd: RawFd, path: &CString, flags: libc::c_int) -> StepResult<RawFd> {
    let how = RawOpenHow {
        flags: (flags | libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path` is NUL-terminated and `how` is a live stack value of the
    // size passed.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            dirfd,
            path.as_ptr(),
            &how as *const RawOpenHow,
            std::mem::size_of::<RawOpenHow>(),
        )
    };
    if fd < 0 {
        Err((MountMaskStep::Open, raw_errno()))
    } else {
        Ok(fd as RawFd)
    }
}

fn fstat(fd: RawFd) -> StepResult<libc::stat> {
    // SAFETY: zeroed stat is valid storage for the kernel to fill.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `stat` is live stack storage; `fd` is open.
    if unsafe { libc::syscall(libc::SYS_fstat, fd, &mut stat as *mut libc::stat) } < 0 {
        return Err((MountMaskStep::Verify, raw_errno()));
    }
    Ok(stat)
}

/// Open a host path by descriptor and prove it is the inode recorded at
/// preparation.
fn open_verified(path: &CString, identity: Identity) -> StepResult<RawFd> {
    let fd = openat2(libc::AT_FDCWD, path, 0)?;
    let verified = fstat(fd).and_then(|stat| {
        let is_dir = stat.st_mode & libc::S_IFMT == libc::S_IFDIR;
        if stat.st_dev == identity.dev && stat.st_ino == identity.ino && is_dir == identity.is_dir {
            Ok(())
        } else {
            Err((MountMaskStep::Verify, libc::ESTALE))
        }
    });
    match verified {
        Ok(()) => Ok(fd),
        Err(error) => {
            close(fd);
            Err(error)
        }
    }
}

fn open_null() -> StepResult<RawFd> {
    let path = c"/dev/null";
    let how = RawOpenHow {
        flags: (libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW) as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: static NUL-terminated path and a live stack open_how.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path.as_ptr(),
            &how as *const RawOpenHow,
            std::mem::size_of::<RawOpenHow>(),
        )
    };
    if fd < 0 {
        return Err((MountMaskStep::Open, raw_errno()));
    }
    let fd = fd as RawFd;
    let is_null = fstat(fd).map(|stat| {
        stat.st_mode & libc::S_IFMT == libc::S_IFCHR && stat.st_rdev == libc::makedev(1, 3)
    });
    match is_null {
        Ok(true) => Ok(fd),
        Ok(false) => {
            close(fd);
            Err((MountMaskStep::Verify, libc::ENODEV))
        }
        Err(error) => {
            close(fd);
            Err(error)
        }
    }
}

fn fsopen_tmpfs() -> std::result::Result<RawFd, i32> {
    // SAFETY: static NUL-terminated filesystem name; scalar flags.
    let fd = unsafe { libc::syscall(libc::SYS_fsopen, c"tmpfs".as_ptr(), FSOPEN_CLOEXEC) };
    if fd < 0 {
        Err(raw_errno())
    } else {
        Ok(fd as RawFd)
    }
}

fn fsconfig_create(fs: RawFd) -> std::result::Result<(), i32> {
    // SAFETY: scalar arguments; null key/value are required for CMD_CREATE.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs,
            FSCONFIG_CMD_CREATE,
            std::ptr::null::<libc::c_char>(),
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if rc < 0 { Err(raw_errno()) } else { Ok(()) }
}

fn fsmount(fs: RawFd, attributes: u64) -> std::result::Result<RawFd, i32> {
    // SAFETY: scalar arguments.
    let fd = unsafe { libc::syscall(libc::SYS_fsmount, fs, FSMOUNT_CLOEXEC, attributes) };
    if fd < 0 {
        Err(raw_errno())
    } else {
        Ok(fd as RawFd)
    }
}

fn attach(mount: RawFd, target: RawFd) -> StepResult<()> {
    // SAFETY: empty static paths with *_EMPTY_PATH flags; both fds are open.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_move_mount,
            mount,
            c"".as_ptr(),
            target,
            c"".as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH | MOVE_MOUNT_T_EMPTY_PATH,
        )
    };
    if rc < 0 {
        Err((MountMaskStep::Attach, raw_errno()))
    } else {
        Ok(())
    }
}

fn set_attributes(tree: RawFd, attr_set: u64, recursive: bool) -> StepResult<()> {
    let attr = RawMountAttr {
        attr_set,
        attr_clr: 0,
        propagation: MS_PRIVATE,
        userns_fd: 0,
    };
    let flags = AT_EMPTY_PATH | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: empty static path with AT_EMPTY_PATH; `attr` is a live stack
    // value of the size passed.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_mount_setattr,
            tree,
            c"".as_ptr(),
            flags,
            &attr as *const RawMountAttr,
            std::mem::size_of::<RawMountAttr>(),
        )
    };
    if rc < 0 {
        Err((MountMaskStep::SetAttributes, raw_errno()))
    } else {
        Ok(())
    }
}

fn clone_tree(source: RawFd, recursive: bool) -> StepResult<RawFd> {
    let flags = OPEN_TREE_CLONE
        | OPEN_TREE_CLOEXEC
        | AT_EMPTY_PATH
        | if recursive { AT_RECURSIVE } else { 0 };
    // SAFETY: empty static path with AT_EMPTY_PATH; `source` is open.
    let fd = unsafe { libc::syscall(libc::SYS_open_tree, source, c"".as_ptr(), flags) };
    if fd < 0 {
        Err((MountMaskStep::CloneTree, raw_errno()))
    } else {
        Ok(fd as RawFd)
    }
}

fn fsconfig_string(
    fs: RawFd,
    key: &std::ffi::CStr,
    value: Option<&CString>,
) -> std::result::Result<(), i32> {
    let Some(value) = value else {
        return Ok(());
    };
    // SAFETY: NUL-terminated key and value that outlive the call; scalar fd.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_fsconfig,
            fs,
            FSCONFIG_SET_STRING,
            key.as_ptr(),
            value.as_ptr(),
            0,
        )
    };
    if rc < 0 { Err(raw_errno()) } else { Ok(()) }
}

fn mask_directory(
    op: &Operation,
    mode: &CString,
    size: Option<&CString>,
    inodes: Option<&CString>,
) -> StepResult<()> {
    let target = open_verified(&op.target, op.identity)?;
    let result = (|| {
        let fs = fsopen_tmpfs().map_err(|e| (MountMaskStep::CreateTmpfs, e))?;
        let mounted = fsconfig_string(fs, c"mode", Some(mode))
            .and_then(|()| fsconfig_string(fs, c"size", size))
            .and_then(|()| fsconfig_string(fs, c"nr_inodes", inodes))
            .and_then(|()| fsconfig_create(fs))
            .and_then(|()| fsmount(fs, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV));
        close(fs);
        let mount = mounted.map_err(|e| (MountMaskStep::CreateTmpfs, e))?;
        let attached = set_attributes(mount, 0, false).and_then(|()| attach(mount, target));
        close(mount);
        attached
    })();
    close(target);
    result
}

fn mask_file(op: &Operation, null_fd: RawFd) -> StepResult<()> {
    let target = open_verified(&op.target, op.identity)?;
    let result = clone_tree(null_fd, false).and_then(|tree| {
        let attached = set_attributes(
            tree,
            MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
            false,
        )
        .and_then(|()| attach(tree, target));
        close(tree);
        attached
    });
    close(target);
    result
}

/// Create the mount point for a re-bind inside the base mask's tmpfs and bind
/// the pre-opened source over it.
fn rebind(
    base_target: &CString,
    base_identity: Identity,
    components: &[CString],
    source: RawFd,
    is_dir: bool,
) -> StepResult<()> {
    let Some((leaf, parents)) = components.split_last() else {
        return Err((MountMaskStep::CreateMountPoint, libc::EINVAL));
    };
    if source < 0 {
        return Err((MountMaskStep::Open, libc::EBADF));
    }
    // The base path must now resolve to the tmpfs this plan mounted over it,
    // never to the host directory beneath: a fresh tmpfs has its own device.
    let mut dir = openat2(libc::AT_FDCWD, base_target, libc::O_DIRECTORY)?;
    match fstat(dir) {
        Ok(stat) if stat.st_dev != base_identity.dev => {}
        Ok(_) => {
            close(dir);
            return Err((MountMaskStep::Verify, libc::EXDEV));
        }
        Err(error) => {
            close(dir);
            return Err(error);
        }
    }
    for name in parents {
        let next = make_directory(dir, name).and_then(|()| openat2(dir, name, libc::O_DIRECTORY));
        close(dir);
        dir = next?;
    }
    let created = if is_dir {
        make_directory(dir, leaf)
    } else {
        make_file(dir, leaf)
    };
    let target = created.and_then(|()| openat2(dir, leaf, 0));
    close(dir);
    let target = target?;
    let result = clone_tree(source, true).and_then(|tree| {
        let attached = set_attributes(tree, 0, true).and_then(|()| attach(tree, target));
        close(tree);
        attached
    });
    close(target);
    result
}

fn make_directory(dir: RawFd, name: &CString) -> StepResult<()> {
    // SAFETY: NUL-terminated name owned by the plan; scalar fd and mode.
    let rc = unsafe { libc::syscall(libc::SYS_mkdirat, dir, name.as_ptr(), MOUNTPOINT_DIR_MODE) };
    if rc < 0 && raw_errno() != libc::EEXIST {
        return Err((MountMaskStep::CreateMountPoint, raw_errno()));
    }
    Ok(())
}

fn make_file(dir: RawFd, name: &CString) -> StepResult<()> {
    // SAFETY: NUL-terminated name owned by the plan; scalar fd, flags, mode.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat,
            dir,
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            MOUNTPOINT_FILE_MODE,
        )
    };
    if fd < 0 {
        return Err((MountMaskStep::CreateMountPoint, raw_errno()));
    }
    close(fd as RawFd);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        // tempdir() may sit under a symlinked TMPDIR; plans need canonical paths.
        let canonical = std::fs::canonicalize(dir.path()).expect("canonical");
        assert_eq!(canonical, dir.path(), "test tempdir must be canonical");
        dir
    }

    #[test]
    fn rejects_relative_and_non_canonical_paths() {
        assert!(PreparedMountMask::prepare(&[MountMask::new("relative")], &[]).is_err());
        assert!(PreparedMountMask::prepare(&[MountMask::new("/tmp/../etc")], &[]).is_err());
        let base = dir();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(base.path(), &link).expect("symlink");
        let error = PreparedMountMask::prepare(&[MountMask::new(&link)], &[]).expect_err("link");
        assert!(error.to_string().contains("canonical"), "{error}");
    }

    #[test]
    fn the_root_cannot_be_masked() {
        let error = PreparedMountMask::prepare(&[MountMask::new("/")], &[]).expect_err("root");
        assert!(error.to_string().contains("root"), "{error}");
    }

    #[test]
    fn tmpfs_limits_are_carried_and_zero_means_default() {
        let mask = MountMask::new("/x").tmpfs_limits(1 << 20, 0);
        assert_eq!(mask.tmpfs_size, Some(1 << 20));
        assert_eq!(mask.tmpfs_inodes, None);
    }

    #[test]
    fn missing_paths_are_skipped_and_reported() {
        let base = dir();
        let missing = base.path().join("missing.sock");
        let plan = PreparedMountMask::prepare(
            &[MountMask::new(&missing)],
            &[base.path().join("missing-grant")],
        )
        .expect("plan");
        assert!(plan.is_empty());
        assert_eq!(plan.skipped().len(), 2);
        assert!(
            plan.skipped()
                .iter()
                .all(|s| s.reason == MountSkipReason::Missing)
        );
    }

    #[test]
    fn rebind_at_directory_mask_is_refused() {
        let base = dir();
        let plan =
            PreparedMountMask::prepare(&[MountMask::new(base.path())], &[base.path().into()])
                .expect("plan");
        assert_eq!(plan.masked_paths().count(), 1);
        assert_eq!(plan.rebound_paths().count(), 0);
        assert_eq!(
            plan.skipped()[0].reason,
            MountSkipReason::ReplacesDirectoryMask
        );
    }

    #[test]
    fn rebinds_only_paths_a_mask_hides() {
        let base = dir();
        let masked = base.path().join("runtime");
        let granted = masked.join("app").join("agent.sock");
        let visible = base.path().join("elsewhere");
        std::fs::create_dir_all(granted.parent().expect("parent")).expect("mkdir");
        std::fs::write(&granted, b"").expect("file");
        std::fs::create_dir(&visible).expect("mkdir");
        let plan = PreparedMountMask::prepare(
            &[MountMask::new(&masked)],
            &[granted.clone(), visible.clone()],
        )
        .expect("plan");
        assert_eq!(
            plan.masked_paths().collect::<Vec<_>>(),
            vec![masked.as_path()]
        );
        assert_eq!(
            plan.rebound_paths().collect::<Vec<_>>(),
            vec![granted.as_path()]
        );
    }

    #[test]
    fn nested_masks_and_rebinds_are_ordered_and_pruned() {
        let base = dir();
        let outer = base.path().join("outer");
        let granted = outer.join("granted");
        let inner_mask = granted.join("secret");
        let hidden_mask = outer.join("hidden");
        for path in [&inner_mask, &hidden_mask] {
            std::fs::create_dir_all(path).expect("mkdir");
        }
        let plan = PreparedMountMask::prepare(
            &[
                MountMask::new(&inner_mask),
                MountMask::new(&hidden_mask),
                MountMask::new(&outer),
            ],
            std::slice::from_ref(&granted),
        )
        .expect("plan");
        // hidden_mask lies under outer's tmpfs with nothing re-bound: dropped.
        assert_eq!(
            plan.masked_paths().collect::<Vec<_>>(),
            vec![outer.as_path(), inner_mask.as_path()]
        );
        assert_eq!(
            plan.rebound_paths().collect::<Vec<_>>(),
            vec![granted.as_path()]
        );
        assert_eq!(plan.operation_path(0), Some(outer.as_path()));
        assert_eq!(plan.operation_path(1), Some(granted.as_path()));
        assert!(plan.operation_is_rebind(1));
        assert_eq!(plan.operation_path(2), Some(inner_mask.as_path()));
    }

    #[test]
    fn rebind_replaces_a_file_mask() {
        let base = dir();
        let socket = base.path().join("agent.sock");
        std::fs::write(&socket, b"").expect("file");
        let plan =
            PreparedMountMask::prepare(&[MountMask::new(&socket)], std::slice::from_ref(&socket))
                .expect("plan");
        // Not under any directory mask, so the host file stays visible as is.
        assert!(plan.is_empty());
    }

    #[test]
    fn step_codes_round_trip() {
        for step in [
            MountMaskStep::Open,
            MountMaskStep::Verify,
            MountMaskStep::CreateTmpfs,
            MountMaskStep::CreateMountPoint,
            MountMaskStep::CloneTree,
            MountMaskStep::SetAttributes,
            MountMaskStep::Attach,
        ] {
            assert_eq!(MountMaskStep::from_code(step.code()), Some(step));
        }
        assert_eq!(MountMaskStep::from_code(0), None);
    }
}
