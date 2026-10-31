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
    // journald wins over `--log-file`/`NONO_LOG_FILE`: the flag names the sink,
    // while a log-file env var is often inherited from a launcher the user is
    // trying to replace.
    if install_journald(cli) {
        return;
    }
    match cli.log_file.as_deref() {
        Some(path) => match SharedFileMakeWriter::new(path) {
            Ok(writer) => init_file_tracing(file_filter, writer),
            Err(err) => {
                eprintln!(
                    "nono: failed to open log file {}: {}; falling back to stderr",
                    path.display(),
                    err
                );
                init_stderr_tracing(tracing_filter(cli, false));
            }
        },
        None => init_stderr_tracing(tracing_filter(cli, false)),
    }
}

fn init_file_tracing(filter: EnvFilter, writer: SharedFileMakeWriter) {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_ansi(false)
        .with_writer(writer)
        .init();
}

fn init_stderr_tracing(filter: EnvFilter) {
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_writer(io::stderr)
        .init();
}

/// Syslog identifier so `journalctl -t nono-proxy` selects these records.
#[cfg(target_os = "linux")]
const JOURNALD_SYSLOG_IDENTIFIER: &str = "nono-proxy";

/// Returns `false` when `--log-journald` is unset or the socket is unreachable,
/// so the caller falls through to the file/stderr sink.
#[cfg(target_os = "linux")]
fn install_journald(cli: &Cli) -> bool {
    if !cli.log_journald {
        return false;
    }

    use tracing_subscriber::Layer as _;
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    match tracing_journald::Layer::new() {
        Ok(layer) => {
            tracing_subscriber::registry()
                .with(
                    layer
                        .with_syslog_identifier(JOURNALD_SYSLOG_IDENTIFIER.to_string())
                        .with_filter(journald_filter(cli)),
                )
                .init();
            true
        }
        Err(err) => {
            eprintln!(
                "nono: failed to connect to systemd-journald: {err}; \
                 continuing without journald logging"
            );
            false
        }
    }
}

/// Other targets have no journald socket, so the flag cannot be honored there.
#[cfg(not(target_os = "linux"))]
fn install_journald(cli: &Cli) -> bool {
    if cli.log_journald {
        eprintln!("nono: --log-journald requires Linux with systemd; ignoring");
    }
    false
}

/// Journald is the only sink, so the filter must admit audit records that the
/// stderr default of `warn` would drop: they are `INFO`, and without a
/// `nono_proxy` directive `--log-journald` would miss the events it exists for.
/// The directive replaces a `RUST_LOG` directive for the same target.
#[cfg(target_os = "linux")]
fn journald_filter(cli: &Cli) -> EnvFilter {
    let level = cli_verbosity_level(cli).unwrap_or("info");
    let mut filter = tracing_filter(cli, true);
    // Literal prefix plus a level from `cli_verbosity_level`, so parsing
    // cannot fail.
    if let Ok(directive) = format!("nono_proxy={level}").parse() {
        filter = filter.add_directive(directive);
    }
    filter
}

// `--silent` only mutes terminal output. A log file or the journal keeps the
// verbosity / RUST_LOG filter.
fn tracing_filter(cli: &Cli, non_terminal: bool) -> EnvFilter {
    let level = if non_terminal {
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

    /// Captures what `journald_filter` admits, with the file writer standing in
    /// for the journal.
    #[cfg(target_os = "linux")]
    fn capture_journald_filter(verbosity: u8, f: &dyn Fn()) -> String {
        use tracing_subscriber::Layer as _;
        use tracing_subscriber::layer::SubscriberExt as _;

        let temp_dir = tempfile::tempdir().expect("tempdir");
        let path = temp_dir.path().join("journald.log");
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(SharedFileMakeWriter::new(&path).expect("capture writer"))
                .with_filter(super::journald_filter(&test_cli(verbosity))),
        );
        tracing::subscriber::with_default(subscriber, f);
        let mut contents = String::new();
        std::fs::File::open(&path)
            .expect("open capture")
            .read_to_string(&mut contents)
            .expect("read capture");
        contents
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn journald_filter_floors_proxy_records_at_info() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let env = EnvVarGuard::set_all(&[("RUST_LOG", "")]);
        env.remove("RUST_LOG");

        let default = capture_journald_filter(0, &|| {
            tracing::info!(
                target: nono_proxy::audit::AUDIT_TARGET,
                "proxy request allowed"
            );
            tracing::debug!(
                target: nono_proxy::audit::AUDIT_TARGET,
                "CONNECT request to example.com:443"
            );
            tracing::info!(target: "nono_cli::unrelated", "cli info noise");
            tracing::warn!(target: "nono_cli::unrelated", "cli warning");
        });
        assert!(default.contains("proxy request allowed"), "{default:?}");
        assert!(!default.contains("CONNECT request to"), "{default:?}");
        assert!(!default.contains("cli info noise"), "{default:?}");
        assert!(default.contains("cli warning"), "{default:?}");

        let verbose = capture_journald_filter(2, &|| {
            tracing::debug!(
                target: nono_proxy::audit::AUDIT_TARGET,
                "CONNECT request to example.com:443"
            );
        });
        assert!(verbose.contains("CONNECT request to"), "{verbose:?}");
    }

    /// The floor replaces a `RUST_LOG` directive for the same target, so an
    /// `INFO` audit record survives a stricter environment setting.
    #[cfg(target_os = "linux")]
    #[test]
    fn journald_filter_replaces_rust_log_proxy_directive() {
        let _lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let _env = EnvVarGuard::set_all(&[("RUST_LOG", "nono_proxy=error")]);

        let captured = capture_journald_filter(0, &|| {
            tracing::info!(
                target: nono_proxy::audit::AUDIT_TARGET,
                "proxy request allowed"
            );
            tracing::debug!(
                target: nono_proxy::audit::AUDIT_TARGET,
                "CONNECT request to example.com:443"
            );
        });
        assert!(captured.contains("proxy request allowed"), "{captured:?}");
        assert!(!captured.contains("CONNECT request to"), "{captured:?}");
    }

    /// `Cli` with `args.verbose` set, for filter tests (`0` = default, `1` = `-v`).
    #[cfg(target_os = "linux")]
    fn test_cli(verbosity: u8) -> Cli {
        let mut cli = Cli::parse_from(["nono", "proxy"]);
        if let crate::cli::Commands::Proxy(args) = &mut cli.command {
            args.verbose = verbosity;
        }
        cli
    }
}
