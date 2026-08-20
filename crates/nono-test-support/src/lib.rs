//! Shared scaffolding for the `nono-cli` integration tests.
//!
//! [`NonoTest`] owns a tempdir holding an isolated `HOME`, `$XDG_STATE_HOME`
//! and workspace, and hands out builders for the real `nono` binary under a
//! hermetic environment.
//!
//! Subcommands are typed: see [`cli`] for the builders.

pub mod cli;

pub use cli::{
    Argv, Completed, KeyRef, Profile, Rollback, RunMode, Sandboxed, Sandboxing, WrapMode,
};

use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// An isolated environment for one integration test.
pub struct NonoTest {
    tmp: tempfile::TempDir,
    bin: PathBuf,
    home: PathBuf,
    state: PathBuf,
    workspace: PathBuf,
}

impl NonoTest {
    /// Builds the tempdir tree. `bin` is `CARGO_BIN_EXE_nono` and `manifest_dir`
    /// is `CARGO_MANIFEST_DIR`, both read at the call site — see [`nono_test!`].
    pub fn new(bin: &str, manifest_dir: &str, prefix: &str) -> Self {
        // Tempdirs must stay under <manifest_dir>/target/test-artifacts. Under
        // Docker Desktop the repo bind mount is gRPC-FUSE, where Landlock
        // grants are accepted but silently unenforced; Linux verification
        // overlays a native volume at exactly `crates/nono-cli/target`, so
        // relocating this root would quietly void every Linux deny assertion.
        let temp_root = PathBuf::from(manifest_dir)
            .join("target")
            .join("test-artifacts");
        fs::create_dir_all(&temp_root).expect("cargo owns target/ and it is writable");
        let tmp = tempfile::Builder::new()
            .prefix(&format!("nono-{prefix}-it-"))
            .tempdir_in(&temp_root)
            .expect("temp root was created directly above");

        let home = tmp.path().join("home");
        // State is a sibling of home rather than <home>/.local/state:
        // `protected_paths` rejects capability grants that overlap
        // $XDG_STATE_HOME/nono, so a test granting $HOME would otherwise fail
        // for a reason that has nothing to do with what it exercises.
        let state = tmp.path().join("state");
        let workspace = tmp.path().join("workspace");
        fs::create_dir_all(home.join(".config")).expect("tmp is a fresh dir this test owns");
        fs::create_dir_all(&state).expect("tmp is a fresh dir this test owns");
        fs::create_dir_all(&workspace).expect("tmp is a fresh dir this test owns");

        Self {
            tmp,
            bin: PathBuf::from(bin),
            home,
            state,
            workspace,
        }
    }

    /// The tempdir root, for siblings of home/state/workspace.
    pub fn root(&self) -> &Path {
        self.tmp.path()
    }

    pub fn home(&self) -> &Path {
        &self.home
    }

    /// `$XDG_STATE_HOME` for runs launched through [`NonoTest::cmd`].
    pub fn state(&self) -> &Path {
        &self.state
    }

    /// The default working directory for [`NonoTest::cmd`].
    pub fn workspace(&self) -> &Path {
        &self.workspace
    }

    /// `nono run`
    pub fn run(&self) -> Sandboxed<'_, RunMode> {
        Sandboxed::new(self)
    }

    /// `nono wrap`
    pub fn wrap(&self) -> Sandboxed<'_, WrapMode> {
        Sandboxed::new(self)
    }

    pub fn trust(&self) -> cli::Trust<'_> {
        cli::Trust::new(self)
    }

    pub fn audit(&self) -> cli::Audit<'_> {
        cli::Audit::new(self)
    }

    pub fn rollback(&self) -> cli::RollbackCmd<'_> {
        cli::RollbackCmd::new(self)
    }

    pub fn credential(&self) -> cli::Credential<'_> {
        cli::Credential::new(self)
    }

    /// A hermetic `nono` invocation for a test that drives the process itself
    /// — a pty, a signal — instead of collecting output through a builder.
    pub fn command(&self) -> Command {
        self.hermetic_command()
    }

    /// A `nono` invocation with a hermetic environment and no arguments.
    fn hermetic_command(&self) -> Command {
        let mut cmd = Command::new(&self.bin);

        // Fail secure: strip the whole `NONO_*` / `XDG_*` namespace.
        for (key, _) in std::env::vars_os() {
            if is_scrubbable(&key) {
                cmd.env_remove(&key);
            }
        }

        cmd.env("HOME", &self.home)
            .env("XDG_CONFIG_HOME", self.home.join(".config"))
            .env("XDG_STATE_HOME", &self.state)
            .env("NONO_NO_SAVE_PROMPT", "1")
            // Set unconditionally rather than preserved through the scrub
            // above: no test may depend on the developer's environment to keep
            // the background network update check off.
            .env("NONO_NO_UPDATE_CHECK", "1")
            .current_dir(&self.workspace);
        cmd
    }

    /// Writes `<home>/<name>.json` and returns a handle for `--profile`.
    pub fn write_profile(&self, name: &str, json: &str) -> Profile {
        let path = self.home.join(format!("{name}.json"));
        fs::write(&path, json).expect("home is a fresh dir this test owns");
        Profile::new(path)
    }

    /// Where the CLI stores audit sessions under this test's state dir.
    pub fn audit_root(&self) -> PathBuf {
        self.state.join("nono").join("audit")
    }
}

fn is_scrubbable(key: &OsStr) -> bool {
    let name = key.to_string_lossy();
    name.starts_with("NONO_") || name.starts_with("XDG_")
}

/// Constructs a [`NonoTest`] from the calling crate's compile-time environment.
///
/// `CARGO_BIN_EXE_nono` is defined only while compiling test targets of the
/// package that declares the binary, and `CARGO_MANIFEST_DIR` inside this crate
/// would point at `crates/nono-test-support`. `macro_rules!` expands in the
/// calling crate, so both `env!`s read `nono-cli`'s environment.
#[macro_export]
macro_rules! nono_test {
    ($prefix:expr) => {
        $crate::NonoTest::new(
            env!("CARGO_BIN_EXE_nono"),
            env!("CARGO_MANIFEST_DIR"),
            $prefix,
        )
    };
}
