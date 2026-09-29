//! Registry of supervisor children that a supervisor thread waits on itself.
//!
//! The Linux supervisor is a child subreaper and drains reparented orphans with
//! a wildcard wait. A wildcard wait would also consume the exit status of
//! children that other supervisor threads spawned and are about to wait on
//! (command-mediation launches, supervisor credential sources), making their
//! `wait()` fail with `ECHILD`. Children spawned through [`spawn`] are
//! registered before the registry lock is released, and the orphan reaper
//! leaves registered children to their owner.

use std::collections::BTreeSet;
use std::ops::{Deref, DerefMut};
use std::process::{Child, Command, Output};
use std::sync::{Mutex, MutexGuard, PoisonError};

static OWNED: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

/// Lock the registry. Holding the guard prevents a concurrent [`spawn`] from
/// producing an unregistered child.
pub(crate) fn lock() -> MutexGuard<'static, BTreeSet<u32>> {
    // The set holds plain pids; a panic while it was held cannot leave it in
    // a state worse than a stale entry, so recover rather than fail.
    OWNED.lock().unwrap_or_else(PoisonError::into_inner)
}

/// A child whose exit status belongs to the thread holding this handle.
///
/// The pid stays registered until the handle is dropped, so drop it only
/// after the owner has waited (or has given up on the child, in which case
/// the orphan reaper collects it).
#[derive(Debug)]
pub(crate) struct OwnedChild {
    child: Child,
    _registration: Registration,
}

/// Removes a pid from the registry when dropped.
#[derive(Debug)]
struct Registration(u32);

impl Drop for Registration {
    fn drop(&mut self) {
        lock().remove(&self.0);
    }
}

/// Spawn `command` and register the child before any wildcard reaper can
/// observe it.
pub(crate) fn spawn(command: &mut Command) -> std::io::Result<OwnedChild> {
    let mut owned = lock();
    let child = command.spawn()?;
    let pid = child.id();
    owned.insert(pid);
    Ok(OwnedChild {
        child,
        _registration: Registration(pid),
    })
}

impl OwnedChild {
    /// [`Child::wait_with_output`], keeping the pid registered until the
    /// child has been reaped.
    pub(crate) fn wait_with_output(self) -> std::io::Result<Output> {
        let Self {
            child,
            _registration,
        } = self;
        child.wait_with_output()
    }
}

impl Deref for OwnedChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.child
    }
}

impl DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.child
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spawned_child_is_registered_until_dropped() {
        let mut child = spawn(&mut Command::new("true")).expect("spawn true");
        let pid = child.id();
        assert!(lock().contains(&pid));
        child.wait().expect("owner reaps its child");
        assert!(lock().contains(&pid), "registered until the handle drops");
        drop(child);
        assert!(!lock().contains(&pid));
    }
}
