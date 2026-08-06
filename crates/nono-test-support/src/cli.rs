//! Typed builders over the `nono` command line.
//!
//! Every subcommand the integration tests drive is a method on [`NonoTest`]
//! returning a builder.

use std::ffi::{OsStr, OsString};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::process::Output;

use crate::NonoTest;

/// The argv handed to the sandboxed child, i.e. everything after `--`.
#[derive(Clone, Debug)]
pub struct Argv {
    program: OsString,
    args: Vec<OsString>,
}

impl Argv {
    pub fn new(program: impl AsRef<OsStr>) -> Self {
        Self {
            program: program.as_ref().to_owned(),
            args: Vec::new(),
        }
    }

    #[must_use]
    pub fn arg(mut self, arg: impl AsRef<OsStr>) -> Self {
        self.args.push(arg.as_ref().to_owned());
        self
    }
}

impl From<&str> for Argv {
    fn from(program: &str) -> Self {
        Self::new(program)
    }
}

/// A profile written by [`NonoTest::write_profile`], passed to `--profile`.
#[derive(Clone, Debug)]
pub struct Profile {
    path: PathBuf,
}

impl Profile {
    pub(crate) fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

/// A `file://<path>` signing-key reference.
#[derive(Clone, Debug)]
pub struct KeyRef {
    uri: String,
    file: PathBuf,
}

impl KeyRef {
    pub fn file(path: impl AsRef<Path>) -> Self {
        let path = path.as_ref().to_path_buf();
        Self {
            uri: format!("file://{}", path.display()),
            file: path,
        }
    }

    pub fn private_key_path(&self) -> &Path {
        &self.file
    }

    /// Where `trust keygen` writes the verifying half, alongside the private key.
    pub fn public_key_path(&self) -> PathBuf {
        let mut path = self.file.clone().into_os_string();
        path.push(".pub");
        PathBuf::from(path)
    }

    fn as_str(&self) -> &str {
        &self.uri
    }
}

/// The flags clap gates behind `--rollback`.
#[derive(Debug, Default)]
pub struct Rollback {
    no_prompt: bool,
    dest: Option<PathBuf>,
}

impl Rollback {
    pub fn new() -> Self {
        Self::default()
    }

    /// `--rollback-dest <PATH>`
    #[must_use]
    pub fn dest(mut self, dir: impl AsRef<Path>) -> Self {
        self.dest = Some(dir.as_ref().to_path_buf());
        self
    }

    /// `--no-rollback-prompt`
    #[must_use]
    pub fn no_prompt(mut self) -> Self {
        self.no_prompt = true;
        self
    }
}

mod sealed {
    pub trait Sealed {}
}

/// A subcommand that sandboxes a child process.
pub trait Sandboxing: sealed::Sealed {
    const SUBCOMMAND: &'static str;
}

/// `nono run` — supervised, owns the rollback and audit-signing flags.
#[derive(Debug)]
pub struct RunMode;

impl Sandboxing for RunMode {
    const SUBCOMMAND: &'static str = "run";
}

impl sealed::Sealed for RunMode {}

/// `nono wrap` — direct exec. Takes `WrapSandboxArgs`, which has no rollback.
#[derive(Debug)]
pub struct WrapMode;

impl Sandboxing for WrapMode {
    const SUBCOMMAND: &'static str = "wrap";
}

impl sealed::Sealed for WrapMode {}

/// Builder for `nono run` / `nono wrap`.
#[must_use = "a dropped builder never spawns nono, so the test asserts nothing"]
pub struct Sandboxed<'t, M: Sandboxing> {
    inner: Invocation<'t>,
    _mode: PhantomData<M>,
}

impl<'t, M: Sandboxing> Sandboxed<'t, M> {
    /// `--allow <PATH>`, repeatable.
    pub fn allow(mut self, path: impl AsRef<Path>) -> Self {
        self.inner.opt("--allow", path.as_ref());
        self
    }

    pub fn allow_cwd(mut self) -> Self {
        self.inner.flag("--allow-cwd");
        self
    }

    pub fn block_net(mut self) -> Self {
        self.inner.flag("--block-net");
        self
    }

    pub fn config(mut self, path: impl AsRef<Path>) -> Self {
        self.inner.opt("--config", path.as_ref());
        self
    }

    pub fn dry_run(mut self) -> Self {
        self.inner.flag("--dry-run");
        self
    }

    /// Environment for the `nono` process, on top of the hermetic set.
    pub fn env(mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) -> Self {
        self.inner.env(key, value);
        self
    }

    /// The directory `nono` is launched from. Defaults to the workspace.
    pub fn launch_dir(mut self, dir: impl AsRef<Path>) -> Self {
        self.inner.launch_dir(dir);
        self
    }

    pub fn profile(mut self, profile: &Profile) -> Self {
        self.inner.opt("--profile", profile.path());
        self
    }

    pub fn profile_name(mut self, name: &str) -> Self {
        self.inner.opt("--profile", name);
        self
    }

    pub fn workdir(mut self, dir: impl AsRef<Path>) -> Self {
        self.inner.opt("--workdir", dir.as_ref());
        self
    }

    #[must_use = "a Completed that is dropped asserts nothing about the run"]
    pub fn exec(mut self, argv: impl Into<Argv>) -> Completed {
        let argv = argv.into();
        self.inner.raw("--");
        self.inner.raw(&argv.program);
        for arg in &argv.args {
            self.inner.raw(arg);
        }
        self.inner.finish()
    }

    pub(crate) fn new(t: &'t NonoTest) -> Self {
        Self {
            inner: Invocation::new(t, &[M::SUBCOMMAND]),
            _mode: PhantomData,
        }
    }
}

impl Sandboxed<'_, RunMode> {
    /// `--audit-sign-key`. `run`-only, same reason as [`Self::rollback`].
    pub fn audit_sign_key(mut self, key: &KeyRef) -> Self {
        self.inner.opt("--audit-sign-key", key.as_str());
        self
    }

    /// `--no-rollback`. Mutually exclusive with [`Self::rollback`].
    pub fn no_rollback(mut self) -> Self {
        self.inner.flag("--no-rollback");
        self
    }

    pub fn rollback(mut self, rollback: Rollback) -> Self {
        self.inner.flag("--rollback");
        if rollback.no_prompt {
            self.inner.flag("--no-rollback-prompt");
        }
        if let Some(dest) = &rollback.dest {
            self.inner.opt("--rollback-dest", dest);
        }
        self
    }
}

/// `nono trust <…>`
pub struct Trust<'t> {
    t: &'t NonoTest,
}

impl<'t> Trust<'t> {
    pub fn keygen(self, key: &KeyRef) -> Keygen<'t> {
        let mut inner = Invocation::new(self.t, &["trust", "keygen"]);
        inner.opt("--keyref", key.as_str());
        Keygen { inner }
    }

    pub(crate) fn new(t: &'t NonoTest) -> Self {
        Self { t }
    }
}

#[must_use = "a dropped builder never spawns nono, so the test asserts nothing"]
pub struct Keygen<'t> {
    inner: Invocation<'t>,
}

impl Keygen<'_> {
    pub fn force(mut self) -> Self {
        self.inner.flag("--force");
        self
    }

    #[must_use = "a Completed that is dropped asserts nothing about the run"]
    pub fn output(self) -> Completed {
        self.inner.finish()
    }
}

/// `nono audit <…>`
pub struct Audit<'t> {
    t: &'t NonoTest,
}

impl<'t> Audit<'t> {
    /// `session_id` is positional and required, so it is a parameter rather
    /// than an optional builder method.
    pub fn verify(self, session_id: &str) -> AuditVerify<'t> {
        AuditVerify {
            inner: Invocation::new(self.t, &["audit", "verify", session_id]),
        }
    }

    pub(crate) fn new(t: &'t NonoTest) -> Self {
        Self { t }
    }
}

#[must_use = "a dropped builder never spawns nono, so the test asserts nothing"]
pub struct AuditVerify<'t> {
    inner: Invocation<'t>,
}

impl AuditVerify<'_> {
    pub fn public_key_file(mut self, path: impl AsRef<Path>) -> Self {
        self.inner.opt("--public-key-file", path.as_ref());
        self
    }

    /// Adds `--json` and parses stdout. Panics unless the command succeeded, so
    /// callers never parse the output of a failed run.
    pub fn json(mut self) -> serde_json::Value {
        self.inner.flag("--json");
        self.inner.finish().json()
    }
}

/// `nono rollback <…>`
pub struct RollbackCmd<'t> {
    t: &'t NonoTest,
}

impl<'t> RollbackCmd<'t> {
    pub fn cleanup(self) -> RollbackCleanup<'t> {
        RollbackCleanup {
            inner: Invocation::new(self.t, &["rollback", "cleanup"]),
        }
    }

    pub fn list(self) -> RollbackList<'t> {
        RollbackList {
            inner: Invocation::new(self.t, &["rollback", "list"]),
        }
    }

    pub(crate) fn new(t: &'t NonoTest) -> Self {
        Self { t }
    }
}

#[must_use = "a dropped builder never spawns nono, so the test asserts nothing"]
pub struct RollbackList<'t> {
    inner: Invocation<'t>,
}

impl RollbackList<'_> {
    pub fn json(mut self) -> serde_json::Value {
        self.inner.flag("--json");
        self.inner.finish().json()
    }

    #[must_use = "a Completed that is dropped asserts nothing about the run"]
    pub fn output(self) -> Completed {
        self.inner.finish()
    }
}

#[must_use = "a dropped builder never spawns nono, so the test asserts nothing"]
pub struct RollbackCleanup<'t> {
    inner: Invocation<'t>,
}

impl RollbackCleanup<'_> {
    pub fn dry_run(mut self) -> Self {
        self.inner.flag("--dry-run");
        self
    }

    #[must_use = "a Completed that is dropped asserts nothing about the run"]
    pub fn output(self) -> Completed {
        self.inner.finish()
    }
}

/// Accumulates argv/env for one `nono` invocation.
struct Invocation<'t> {
    t: &'t NonoTest,
    args: Vec<OsString>,
    envs: Vec<(OsString, OsString)>,
    launch_dir: Option<PathBuf>,
}

impl<'t> Invocation<'t> {
    fn new(t: &'t NonoTest, subcommand: &[&str]) -> Self {
        Self {
            t,
            args: subcommand.iter().map(OsString::from).collect(),
            envs: Vec::new(),
            launch_dir: None,
        }
    }

    fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
        self.envs
            .push((key.as_ref().to_owned(), value.as_ref().to_owned()));
    }

    fn flag(&mut self, flag: &str) {
        self.raw(flag);
    }

    fn launch_dir(&mut self, dir: impl AsRef<Path>) {
        self.launch_dir = Some(dir.as_ref().to_path_buf());
    }

    fn opt(&mut self, flag: &str, value: impl AsRef<OsStr>) {
        self.raw(flag);
        self.raw(value);
    }

    fn raw(&mut self, arg: impl AsRef<OsStr>) {
        self.args.push(arg.as_ref().to_owned());
    }

    fn finish(self) -> Completed {
        let mut cmd = self.t.hermetic_command();
        cmd.args(&self.args);
        for (key, value) in &self.envs {
            cmd.env(key, value);
        }
        if let Some(dir) = &self.launch_dir {
            cmd.current_dir(dir);
        }
        let output = cmd
            .output()
            .expect("cargo builds CARGO_BIN_EXE_nono before running this test binary");
        Completed {
            output,
            invocation: render(&self.args),
        }
    }
}

fn render(args: &[OsString]) -> String {
    let rendered: Vec<String> = args
        .iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect();
    format!("nono {}", rendered.join(" "))
}

/// A finished `nono` invocation.
pub struct Completed {
    output: Output,
    invocation: String,
}

impl Completed {
    /// A signalled child has no code, so `Option` inequality also catches the
    /// crash that `assert_failure` would wave through.
    pub fn assert_exit_code(self, code: i32, why: &str) -> Self {
        assert_eq!(
            self.output.status.code(),
            Some(code),
            "{}",
            self.context(&format!("expected exit {code}: {why}"))
        );
        self
    }

    pub fn assert_failure(self, why: &str) -> Self {
        assert!(
            !self.output.status.success(),
            "{}",
            self.context(&format!("expected failure: {why}"))
        );
        self
    }

    pub fn assert_stderr_contains(self, needle: &str) -> Self {
        assert!(
            self.stderr().contains(needle),
            "{}",
            self.context(&format!("stderr should contain {needle:?}"))
        );
        self
    }

    pub fn assert_stderr_lacks(self, needle: &str) -> Self {
        assert!(
            !self.stderr().contains(needle),
            "{}",
            self.context(&format!("stderr must not contain {needle:?}"))
        );
        self
    }

    pub fn assert_stdout_contains(self, needle: &str) -> Self {
        assert!(
            self.stdout().contains(needle),
            "{}",
            self.context(&format!("stdout should contain {needle:?}"))
        );
        self
    }

    pub fn assert_stdout_lacks(self, needle: &str) -> Self {
        assert!(
            !self.stdout().contains(needle),
            "{}",
            self.context(&format!("stdout must not contain {needle:?}"))
        );
        self
    }

    pub fn assert_success(self, why: &str) -> Self {
        assert!(
            self.output.status.success(),
            "{}",
            self.context(&format!("expected success: {why}"))
        );
        self
    }

    pub fn stderr(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.output.stderr)
    }

    pub fn stdout(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.output.stdout)
    }

    fn context(&self, what: &str) -> String {
        format!(
            "{what}\ncommand: {}\nexit: {:?}\nstdout: {}\nstderr: {}",
            self.invocation,
            self.output.status.code(),
            self.stdout(),
            self.stderr(),
        )
    }

    /// Parses stdout as JSON, requiring success first: a non-zero exit means
    /// stdout holds no document, and the parse error would hide the real cause.
    fn json(self) -> serde_json::Value {
        let this = self.assert_success("a --json command must exit 0 to emit a document");
        serde_json::from_slice(&this.output.stdout).unwrap_or_else(|err| {
            panic!(
                "{}",
                this.context(&format!("stdout is not valid JSON: {err}"))
            );
        })
    }
}
