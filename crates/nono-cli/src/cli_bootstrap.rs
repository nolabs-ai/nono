use crate::cli::{Cli, Commands};
use crate::{config, theme};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriter;

pub(crate) fn init_theme(cli: &Cli) {
    let config_theme = config::user::load_user_config()
        .ok()
        .flatten()
        .and_then(|config| config.ui.theme);

    theme::init(cli.theme.as_deref(), config_theme.as_deref());
}

/// Initialize tracing for an internal re-exec entrypoint (e.g. the command-mediation
/// child launcher), which returns from `main()` before [`init_tracing`] runs and
/// therefore has no subscriber of its own.
///
/// Honors `RUST_LOG` only (forwarded from the parent by `prepare_launcher_command`)
/// and writes to stderr. This is what surfaces the library's
/// `debug!("Generated Seatbelt profile…")` for a brokered child under
/// `RUST_LOG=debug`. It is a no-op when `RUST_LOG` is unset or empty, so normal
/// runs stay silent. Errors from a double-init are swallowed: the launcher only
/// ever calls this once, but `try_init` keeps it defensive.
pub(crate) fn init_internal_entrypoint_tracing() {
    let Some(filter) = std::env::var_os("RUST_LOG") else {
        return;
    };
    if filter.is_empty() {
        return;
    }
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
        )
        .with_target(false)
        .with_writer(io::stderr)
        .try_init();
}

pub(crate) fn init_tracing(cli: &Cli) {
    // Resolve the log file filter before RUST_LOG is exported below. Under
    // `--silent` the export is "off", which must not reach the log file.
    let file_filter = tracing_filter(cli, true);

    // Export the resolved CLI verbosity into RUST_LOG (unless already set) so it
    // propagates to internal re-exec subprocesses — notably the command-mediation
    // child launcher, which forwards RUST_LOG and inits its own subscriber. This
    // makes `-vv` surface the brokered child's generated Seatbelt profile too,
    // not just the parent's logs.
    if let Some(level) = cli_log_override(cli)
        && std::env::var_os("RUST_LOG").is_none()
    {
        // SAFETY: called during single-threaded CLI bootstrap, before any
        // threads are spawned (same contract as copy_legacy_env_var).
        #[allow(clippy::disallowed_methods)]
        unsafe {
            std::env::set_var("RUST_LOG", level)
        };
    }
    match cli.log_file.as_deref() {
        Some(path) => match SharedFileMakeWriter::new(path) {
            Ok(writer) => {
                tracing_subscriber::fmt()
                    .with_env_filter(file_filter)
                    .with_target(false)
                    .with_ansi(false)
                    .with_writer(writer)
                    .init();
            }
            Err(err) => {
                eprintln!(
                    "nono: failed to open log file {}: {}; falling back to stderr",
                    path.display(),
                    err
                );
                tracing_subscriber::fmt()
                    .with_env_filter(tracing_filter(cli, false))
                    .with_target(false)
                    .with_writer(io::stderr)
                    .init();
            }
        },
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_filter(cli, false))
                .with_target(false)
                .with_writer(io::stderr)
                .init();
        }
    }
}

// `--silent` only mutes terminal output. An explicit log file keeps the
// verbosity / RUST_LOG filter.
fn tracing_filter(cli: &Cli, to_file: bool) -> EnvFilter {
    let level = if to_file {
        cli_verbosity_level(cli)
    } else {
        cli_log_override(cli)
    };
    level.map(EnvFilter::new).unwrap_or_else(|| {
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
    })
}

fn cli_log_override(cli: &Cli) -> Option<&'static str> {
    if cli.silent {
        return Some("off");
    }
    cli_verbosity_level(cli)
}

fn cli_verbosity_level(cli: &Cli) -> Option<&'static str> {
    match cli_verbosity(cli) {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    }
}

fn cli_verbosity(cli: &Cli) -> u8 {
    match &cli.command {
        Commands::Run(args) => args.sandbox.verbose,
        Commands::Shell(args) => args.sandbox.verbose,
        Commands::Wrap(args) => args.sandbox.verbose,
        Commands::Setup(args) => args.verbose,
        Commands::Proxy(args) => args.verbose,
        Commands::Why(_)
        | Commands::Rollback(_)
        | Commands::Trust(_)
        | Commands::Audit(_)
        | Commands::Platform(_)
        | Commands::Connect(_)
        | Commands::Pull(_)
        | Commands::Remove(_)
        | Commands::Update(_)
        | Commands::Search(_)
        | Commands::List(_)
        | Commands::Ps(_)
        | Commands::Stop(_)
        | Commands::Detach(_)
        | Commands::Attach(_)
        | Commands::Logs(_)
        | Commands::Inspect(_)
        | Commands::Session(_)
        | Commands::Profile(_)
        | Commands::Pin(_)
        | Commands::Unpin(_)
        | Commands::Outdated(_)
        | Commands::OpenUrlHelper(_)
        | Commands::PackUpdateHintHelper(_)
        | Commands::Completions(_) => 0,
    }
}

#[derive(Clone)]
struct SharedFileMakeWriter {
    file: Arc<Mutex<File>>,
}

struct SharedFileWriter {
    file: Arc<Mutex<File>>,
}

impl SharedFileMakeWriter {
    fn new(path: &Path) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file: Arc::new(Mutex::new(file)),
        })
    }
}

impl<'a> MakeWriter<'a> for SharedFileMakeWriter {
    type Writer = SharedFileWriter;

    fn make_writer(&'a self) -> Self::Writer {
        SharedFileWriter {
            file: Arc::clone(&self.file),
        }
    }
}

impl Write for SharedFileWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file mutex poisoned"))?;
        guard.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut guard = self
            .file
            .lock()
            .map_err(|_| io::Error::other("log file mutex poisoned"))?;
        guard.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::{SharedFileMakeWriter, tracing_filter};
    use crate::cli::Cli;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};
    use clap::Parser;
    use std::io::{Read, Write};
    use tracing_subscriber::fmt::writer::MakeWriter;

    #[test]
    fn silent_mutes_stderr_filter_but_not_log_file_filter() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvVarGuard::set_all(&[("RUST_LOG", "nono_proxy::audit=info")]);

        let cli = Cli::parse_from([
            "nono",
            "--silent",
            "--log-file",
            "/tmp/nono.log",
            "run",
            "--allow",
            ".",
            "echo",
            "hi",
        ]);
        assert_eq!(tracing_filter(&cli, false).to_string(), "off");
        assert_eq!(
            tracing_filter(&cli, true).to_string(),
            "nono_proxy::audit=info"
        );

        env.remove("RUST_LOG");
        assert_eq!(tracing_filter(&cli, false).to_string(), "off");
        assert_eq!(tracing_filter(&cli, true).to_string(), "warn");

        let cli = Cli::parse_from([
            "nono",
            "--silent",
            "--log-file",
            "/tmp/nono.log",
            "run",
            "-vv",
            "--allow",
            ".",
            "echo",
            "hi",
        ]);
        assert_eq!(tracing_filter(&cli, false).to_string(), "off");
        assert_eq!(tracing_filter(&cli, true).to_string(), "debug");
    }

    #[test]
    fn shared_file_make_writer_appends_output() {
        let temp_dir = tempfile::tempdir().expect("tempdir");
        let log_path = temp_dir.path().join("nono.log");
        let writer = SharedFileMakeWriter::new(&log_path).expect("create writer");

        let mut first = writer.make_writer();
        let mut second = writer.make_writer();
        first.write_all(b"first line\n").expect("first write");
        second.write_all(b"second line\n").expect("second write");
        first.flush().expect("first flush");
        second.flush().expect("second flush");

        let mut contents = String::new();
        std::fs::File::open(&log_path)
            .expect("open log")
            .read_to_string(&mut contents)
            .expect("read log");

        assert!(contents.contains("first line"));
        assert!(contents.contains("second line"));
    }
}
