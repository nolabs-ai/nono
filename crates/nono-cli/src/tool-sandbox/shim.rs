//! Session-local broker discovery for copies of the nono executable.
//!
//! These paths only select a broker. The broker must still authenticate the
//! shim, its peer process and session ancestry, and authorize the command.

use nono::{NonoError, Result};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

pub(crate) struct Shim {
    pub(crate) exe: PathBuf,
    runtime_dir: PathBuf,
}

impl Shim {
    pub(crate) fn current() -> Result<Option<Self>> {
        let exe = std::env::current_exe().map_err(|err| {
            NonoError::SandboxInit(format!(
                "tool-sandbox failed to locate current executable: {err}"
            ))
        })?;
        Ok(Self::from_exe(exe))
    }

    fn from_exe(exe: PathBuf) -> Option<Self> {
        let runtime_dir = runtime_dir_for_shim(&exe)?.to_path_buf();
        Some(Self { exe, runtime_dir })
    }

    pub(crate) fn is_url_open(&self) -> bool {
        self.exe.file_name() == Some(OsStr::new(super::url_shim::URL_OPEN_SHIM_NAME))
    }

    pub(crate) fn socket_path(&self) -> PathBuf {
        self.runtime_dir.join(if self.is_url_open() {
            "url.sock"
        } else {
            "supervisor.sock"
        })
    }
}

fn runtime_dir_for_shim(exe: &Path) -> Option<&Path> {
    let shims_dir = exe.parent()?;
    if shims_dir.file_name() != Some(OsStr::new("shims")) {
        return None;
    }
    let runtime_dir = shims_dir.parent()?;
    let name = runtime_dir.file_name()?.to_str()?;
    name.starts_with("nono-tool-sandbox-")
        .then_some(runtime_dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovers_session_sockets_without_requiring_them_to_exist() {
        for root in ["/tmp", "/private/tmp", "/custom/runtime"] {
            let runtime = Path::new(root).join("nono-tool-sandbox-abc123");
            for (name, socket) in [("git", "supervisor.sock"), ("open", "url.sock")] {
                let exe = runtime.join("shims").join(name);
                let shim = Shim::from_exe(exe.clone()).expect("shim layout");
                assert_eq!(shim.exe, exe);
                assert_eq!(shim.socket_path(), runtime.join(socket));
            }
        }
    }

    #[test]
    fn rejects_paths_outside_the_session_shim_layout() {
        for path in [
            "/usr/local/bin/nono",
            "/tmp/notshim/git",
            "/tmp/nono-tool-sandbox-abc123/git",
            "/tmp/other/shims/git",
            "/tmp/nono-tool-sandbox-abc123/shims-extra/git",
            "/tmp/nono-tool-sandbox-abc123/shims/nested/git",
            "/tmp/nono-tool-sandboxish/shims/git",
        ] {
            assert!(Shim::from_exe(PathBuf::from(path)).is_none(), "{path}");
        }
    }
}
