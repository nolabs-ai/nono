use crate::cli::{Cli, Commands};
use crate::{config, theme};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::writer::MakeWriter;

pub(crate) fn normalize_legacy_flag_env_vars() {
    copy_legacy_env_var("NONO_NET_BLOCK", "NONO_BLOCK_NET");
    copy_legacy_env_var("NONO_NET_ALLOW", "NONO_ALLOW_NET");
    copy_legacy_env_var("NONO_ALLOW_PROXY", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_ALLOW", "NONO_ALLOW_DOMAIN");
    copy_legacy_env_var("NONO_PROXY_CREDENTIAL", "NONO_CREDENTIAL");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY", "NONO_UPSTREAM_PROXY");
    copy_legacy_env_var("NONO_EXTERNAL_PROXY_BYPASS", "NONO_UPSTREAM_BYPASS");
}

pub(crate) fn collect_legacy_network_warnings() -> Vec<String> {
    let mut warnings = Vec::new();
    let args: Vec<String> = std::env::args().skip(1).collect();

    // (legacy, replacement, remove_by)
    for (legacy, replacement, remove_by) in [
        (
            "--allow-net",
            Some("network is unrestricted by default"),
            None,
        ),
        (
            "--net-allow",
            Some("network is unrestricted by default"),
            None,
        ),
        ("--allow-proxy", Some("--allow-domain"), None),
        ("--proxy-allow", Some("--allow-domain"), None),
        ("--proxy-credential", Some("--credential"), Some("v1.0.0")),
        ("--allow-bind", Some("--listen-port"), None),
        ("--allow-port", Some("--open-port"), None),
        ("--external-proxy", Some("--upstream-proxy"), None),
        ("--external-proxy-bypass", Some("--upstream-bypass"), None),
        ("--net-block", Some("--block-net"), None),
    ] {
        if args
            .iter()
            .any(|arg| arg == legacy || arg.starts_with(&format!("{legacy}=")))
        {
            let mut message = if let Some(replacement) = replacement {
                format!("Warning: `{legacy}` is deprecated; use `{replacement}` instead.")
            } else {
                format!("Warning: `{legacy}` is deprecated.")
            };
            if let Some(v) = remove_by {
                message.push_str(&format!(" Will be removed in {v}."));
            }
            warnings.push(message);
        }
    }

    // (legacy, replacement, remove_by)
    for (legacy, replacement, remove_by) in [
        ("NONO_NET_BLOCK", "NONO_BLOCK_NET", None),
        ("NONO_NET_ALLOW", "NONO_ALLOW_NET", None),
        ("NONO_ALLOW_PROXY", "NONO_ALLOW_DOMAIN", None),
        ("NONO_PROXY_ALLOW", "NONO_ALLOW_DOMAIN", None),
        ("NONO_PROXY_CREDENTIAL", "NONO_CREDENTIAL", Some("v1.0.0")),
        ("NONO_EXTERNAL_PROXY", "NONO_UPSTREAM_PROXY", None),
        ("NONO_EXTERNAL_PROXY_BYPASS", "NONO_UPSTREAM_BYPASS", None),
    ] {
        if std::env::var_os(legacy).is_some() {
            let mut message =
                format!("Warning: `{legacy}` is deprecated; use `{replacement}` instead.");
            if let Some(v) = remove_by {
                message.push_str(&format!(" Will be removed in {v}."));
            }
            warnings.push(message);
        }
    }

    warnings
}

pub(crate) fn print_legacy_network_warnings(warnings: &[String], silent: bool) {
    if silent {
        return;
    }

    for warning in warnings {
        eprintln!("  [nono] {warning}");
    }
}

pub(crate) fn init_theme(cli: &Cli) {
    let config_theme = config::user::load_user_config()
        .ok()
        .flatten()
        .and_then(|config| config.ui.theme);

    theme::init(cli.theme.as_deref(), config_theme.as_deref());
}

/// Initialize tracing for an internal re-exec entrypoint (e.g. the tool-sandbox
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
    // Export the resolved CLI verbosity into RUST_LOG (unless already set) so it
    // propagates to internal re-exec subprocesses — notably the tool-sandbox
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
                    .with_env_filter(tracing_filter(cli))
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
                    .with_env_filter(tracing_filter(cli))
                    .with_target(false)
                    .init();
            }
        },
        None => {
            tracing_subscriber::fmt()
                .with_env_filter(tracing_filter(cli))
                .with_target(false)
                .init();
        }
    }
}

#[allow(clippy::disallowed_methods)] // Single-threaded at process startup, before any threads.
fn copy_legacy_env_var(old: &str, new: &str) {
    if std::env::var_os(new).is_some() {
        return;
    }

    if let Some(value) = std::env::var_os(old) {
        // SAFETY: called during single-threaded CLI bootstrap, before any
        // threads are spawned.
        unsafe { std::env::set_var(new, value) };
    }
}

fn tracing_filter(cli: &Cli) -> EnvFilter {
    cli_log_override(cli)
        .map(EnvFilter::new)
        .unwrap_or_else(|| {
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"))
        })
}

fn cli_log_override(cli: &Cli) -> Option<&'static str> {
    if cli.silent {
        return Some("off");
    }

    match cli_verbosity(cli) {
        0 => None,
        1 => Some("info"),
        2 => Some("debug"),
        _ => Some("trace"),
    }
}

fn cli_verbosity(cli: &Cli) -> u8 {
    match &cli.command {
        Commands::Learn(args) => args.verbose,
        Commands::Run(args) => args.sandbox.verbose,
        Commands::Shell(args) => args.sandbox.verbose,
        Commands::Wrap(args) => args.sandbox.verbose,
        Commands::Setup(args) => args.verbose,
        Commands::Proxy(args) => args.verbose,
        Commands::Why(_)
        | Commands::Rollback(_)
        | Commands::Trust(_)
        | Commands::Audit(_)
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
        | Commands::Prune(_)
        | Commands::Policy(_)
        | Commands::Profile(_)
        | Commands::Pin(_)
        | Commands::Unpin(_)
        | Commands::Outdated(_)
        | Commands::Pack(_)
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
    use super::SharedFileMakeWriter;
    use std::io::{Read, Write};
    use tracing_subscriber::fmt::writer::MakeWriter;

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
