//! `nono credential` — store and inspect the credentials that
//! `--credential <service>` injects at run time.

use crate::cli::{
    CredentialArgs, CredentialCheckArgs, CredentialCommands, CredentialListArgs, CredentialRmArgs,
    CredentialSetArgs,
};
use crate::network_policy::{self, CredentialDef, NetworkPolicy};
use crate::profile::{self, CustomCredentialDef};
use colored::Colorize;
use nix::libc;
use nix::sys::signal::{self, SigHandler, Signal};
use nono::keystore::DEFAULT_SERVICE;
use nono::{NonoError, Result};
use std::collections::{BTreeSet, HashMap};
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use zeroize::{Zeroize, Zeroizing};

/// Where a service's credential actually comes from at run time.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CredentialSource {
    /// A system keystore entry, which `set` can write.
    Keystore { service: String, account: String },
    /// `keyring://…?decode=go-keyring`: the load path base64-decodes the
    /// stored value, so writing a plain secret here produces something the
    /// proxy cannot parse.
    KeystoreEncoded {
        service: String,
        account: String,
        /// The URI to load.
        reference: String,
    },
    /// An environment variable in the parent process.
    Env { var: String },
    /// A local file read before the sandbox is applied.
    File { path: PathBuf, display: String },
    /// An external secret manager (1Password, Bitwarden, Apple Passwords) or
    /// a supervisor-captured command.
    External {
        manager: &'static str,
        display: String,
    },
    /// OAuth2 client credentials
    OAuth2 {
        client_id: String,
        client_secret: String,
    },
    /// The route authenticates without any stored secret.
    Ambient { mechanism: &'static str },
}

impl CredentialSource {
    fn classify(credential_ref: &str) -> Self {
        if nono::is_env_uri(credential_ref) {
            let var = credential_ref.trim_start_matches("env://").to_string();
            return Self::Env { var };
        }
        if nono::is_file_uri(credential_ref) {
            let path = PathBuf::from(credential_ref.trim_start_matches("file://"));
            return Self::File {
                path,
                display: nono::redact_file_uri(credential_ref),
            };
        }
        if nono::is_op_uri(credential_ref) {
            return Self::External {
                manager: "1password",
                display: nono::redact_op_uri(credential_ref),
            };
        }
        if nono::is_bw_uri(credential_ref) {
            return Self::External {
                manager: "bitwarden",
                display: nono::redact_bw_uri(credential_ref),
            };
        }
        if nono::is_apple_password_uri(credential_ref) {
            return Self::External {
                manager: "apple-passwords",
                display: nono::redact_apple_password_uri(credential_ref),
            };
        }
        if nono::keystore::is_cmd_uri(credential_ref) {
            return Self::External {
                manager: "capture",
                display: credential_ref.to_string(),
            };
        }
        if nono::is_keyring_uri(credential_ref) {
            return match parse_keyring_ref(credential_ref) {
                Some((service, account, decoded)) if decoded => Self::KeystoreEncoded {
                    service,
                    account,
                    reference: credential_ref.to_string(),
                },
                Some((service, account, _)) => Self::Keystore { service, account },
                // An unparseable keyring:// URI is a profile error surfaced by
                // profile validation; report it rather than guessing an account.
                None => Self::External {
                    manager: "keyring",
                    display: nono::redact_keyring_uri(credential_ref),
                },
            };
        }
        Self::Keystore {
            service: DEFAULT_SERVICE.to_string(),
            account: credential_ref.to_string(),
        }
    }

    /// Whether the credential can be loaded right now.
    fn availability(&self, keystore: &mut KeystoreProbe) -> Availability {
        match self {
            Self::Keystore { service, account } => keystore.exists(service, account),
            // Presence is not enough here: the run-time load path also requires
            // the go-keyring prefix, valid base64, and valid UTF-8, so an entry
            // written without that encoding would be reported as available and
            // then fail the run it was meant to unblock.
            Self::KeystoreEncoded { reference, .. } => keystore.loads(reference),
            Self::Env { var } => match std::env::var_os(var) {
                Some(value) if !value.is_empty() => Availability::Available,
                _ => Availability::Missing,
            },
            Self::File { path, .. } => {
                if path.is_file() {
                    Availability::Available
                } else {
                    Availability::Missing
                }
            }
            // Probing an external manager runs its CLI, which can block on a
            // biometric prompt..
            Self::External { .. } => Availability::Unknown,
            Self::OAuth2 {
                client_id,
                client_secret,
            } => Self::classify(client_id)
                .availability(keystore)
                .and(Self::classify(client_secret).availability(keystore)),
            Self::Ambient { .. } => Availability::Unknown,
        }
    }

    /// Single-column rendering for `credential list`.
    fn display(&self) -> String {
        match self {
            Self::Keystore { service, account } => {
                format!("keystore: {}", qualified_account(service, account))
            }
            Self::KeystoreEncoded {
                service, account, ..
            } => format!(
                "keystore: {} (go-keyring encoded)",
                qualified_account(service, account)
            ),
            Self::Env { var } => format!("env: {var}"),
            Self::File { display, .. } => format!("file: {display}"),
            Self::External { manager, display } => format!("{manager}: {display}"),
            Self::OAuth2 { .. } => "oauth2: client_id + client_secret".to_string(),
            Self::Ambient { mechanism } => (*mechanism).to_string(),
        }
    }

    /// Machine-readable form for `credential list --json`.
    fn json(&self) -> serde_json::Value {
        match self {
            Self::Keystore { service, account } => serde_json::json!({
                "kind": "keystore",
                "keystore_service": service,
                "account": account,
            }),
            Self::KeystoreEncoded {
                service, account, ..
            } => serde_json::json!({
                "kind": "keystore",
                "keystore_service": service,
                "account": account,
                "decode": "go-keyring",
            }),
            Self::Env { var } => serde_json::json!({ "kind": "env", "env_var": var }),
            Self::File { display, .. } => serde_json::json!({ "kind": "file", "ref": display }),
            Self::External { manager, display } => serde_json::json!({
                "kind": "external",
                "manager": manager,
                "ref": display,
            }),
            Self::OAuth2 { .. } => serde_json::json!({ "kind": "oauth2" }),
            Self::Ambient { mechanism } => {
                serde_json::json!({ "kind": "ambient", "mechanism": mechanism })
            }
        }
    }
}

/// Whether a credential can be loaded.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Availability {
    Available,
    Missing,
    /// The source cannot be probed without invoking an external manager.
    Unknown,
    /// The keystore stopped answering, so this entry was never asked about.
    NotProbed,
    /// The probe itself failed.
    Error(String),
}

impl Availability {
    /// Combine two halves of a composite credential.
    fn and(self, other: Self) -> Self {
        match (self, other) {
            (Self::Error(e), _) | (_, Self::Error(e)) => Self::Error(e),
            (Self::Missing, _) | (_, Self::Missing) => Self::Missing,
            (Self::NotProbed, _) | (_, Self::NotProbed) => Self::NotProbed,
            (Self::Unknown, _) | (_, Self::Unknown) => Self::Unknown,
            (Self::Available, Self::Available) => Self::Available,
        }
    }

    fn cell(&self) -> String {
        match self {
            Self::Available => format!("{} available", "✓".green()),
            Self::Missing => format!("{} not set", "✗".red()),
            Self::Unknown => "- unknown".to_string(),
            Self::NotProbed => "- not probed".to_string(),
            Self::Error(_) => format!("{} error", "!".yellow()),
        }
    }

    fn json(&self) -> serde_json::Value {
        match self {
            Self::Available => serde_json::json!("available"),
            Self::Missing => serde_json::json!("not_set"),
            Self::Unknown => serde_json::json!("unknown"),
            Self::NotProbed => serde_json::json!("not_probed"),
            Self::Error(message) => serde_json::json!({ "status": "error", "error": message }),
        }
    }
}

/// Serial keystore probing for `credential list`.
///
/// A locked or absent keystore makes every probe wait out
/// `NONO_KEYRING_TIMEOUT_SECS` (120 s by default), so probing on after the
/// first such failure would multiply that wait by the number of services. The
/// first failure is reported and the rest are left unprobed. A failure local
/// to one entry — a value that is not go-keyring encoded — says nothing about
/// the keystore, so it does not stop the sweep.
#[derive(Default)]
struct KeystoreProbe {
    keystore_unavailable: bool,
}

impl KeystoreProbe {
    /// Whether an entry exists, without reading it through a decoder.
    fn exists(&mut self, service: &str, account: &str) -> Availability {
        if self.keystore_unavailable {
            return Availability::NotProbed;
        }
        let existence = nono::secret_exists(service, account).map(|exists| {
            if exists {
                Availability::Available
            } else {
                Availability::Missing
            }
        });
        self.record(existence)
    }

    /// Whether a reference loads, decoding included.
    fn loads(&mut self, credential_ref: &str) -> Availability {
        if self.keystore_unavailable {
            return Availability::NotProbed;
        }
        let load = nono::load_secret_by_ref(DEFAULT_SERVICE, credential_ref).map(|secret| {
            drop(secret);
            Availability::Available
        });
        self.record(load)
    }

    fn record(&mut self, result: Result<Availability>) -> Availability {
        match result {
            Ok(availability) => availability,
            Err(NonoError::SecretNotFound(_)) => Availability::Missing,
            Err(e) => {
                if matches!(e, NonoError::KeystoreAccess(_)) {
                    self.keystore_unavailable = true;
                }
                Availability::Error(e.to_string())
            }
        }
    }
}

/// Where a service definition came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Origin {
    BuiltIn,
    Profile,
}

impl Origin {
    fn label(self) -> &'static str {
        match self {
            Self::BuiltIn => "built-in",
            Self::Profile => "profile",
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedService {
    name: String,
    origin: Origin,
    source: CredentialSource,
    /// Raw credential references to load when verifying the service.
    references: Vec<String>,
}

/// The built-in network policy plus any profile-defined custom credentials.
struct ServiceCatalog {
    policy: NetworkPolicy,
    custom: HashMap<String, CustomCredentialDef>,
}

impl ServiceCatalog {
    fn load(profile_name: Option<&str>) -> Result<Self> {
        let policy = network_policy::load_network_policy(
            crate::config::embedded::embedded_network_policy_json(),
        )?;
        let custom = match profile_name {
            Some(name) => profile::load_profile(name)?.network.custom_credentials,
            None => HashMap::new(),
        };
        Ok(Self { policy, custom })
    }

    /// Every service the catalog knows about
    fn all(&self) -> Vec<ResolvedService> {
        self.names()
            .into_iter()
            .filter_map(|name| self.resolve(name).ok())
            .collect()
    }

    /// Every known service name, deduplicated.
    fn names(&self) -> BTreeSet<&str> {
        self.policy
            .credentials
            .keys()
            .chain(self.custom.keys())
            .map(String::as_str)
            .collect()
    }

    /// Resolve one service name, preferring the profile's definition.
    fn resolve(&self, name: &str) -> Result<ResolvedService> {
        if let Some(cred) = self.custom.get(name) {
            return Ok(custom_service(name, cred));
        }
        if let Some(cred) = self.policy.credentials.get(name) {
            return Ok(builtin_service(name, cred));
        }

        let available: Vec<&str> = self.names().into_iter().collect();
        Err(NonoError::ConfigParse(format!(
            "Unknown credential service '{}'. Available: {}. \
             Pass --profile <name> to include a profile's own services, or \
             --account <name> to address a keystore entry directly.",
            name,
            available.join(", ")
        )))
    }
}

/// A keystore entry a write can target.
struct KeystoreTarget {
    service: String,
    account: String,
}

impl KeystoreTarget {
    fn label(&self) -> String {
        account_label(&self.service, &self.account)
    }
}

/// The `local_flags` the active [`EchoGuard`] saved, for the signal handler to
/// put back. Signal handlers cannot read instance data, so this is the only
/// place the pre-prompt echo setting can live.
static SAVED_LOCAL_FLAGS: AtomicU64 = AtomicU64::new(0);

/// Whether an [`EchoGuard`] currently has echo turned off.
static ECHO_DISABLED: AtomicBool = AtomicBool::new(false);

/// The `local_flags` bits the guard clears.
const ECHO_FLAGS: libc::tcflag_t = libc::ECHO | libc::ECHONL;

/// Signals that would otherwise kill the process at the prompt, leaving the
/// user's shell with echo off.
const ECHO_RESTORING_SIGNALS: [Signal; 4] = [
    Signal::SIGINT,
    Signal::SIGQUIT,
    Signal::SIGTERM,
    Signal::SIGHUP,
];

/// Put echo back, then die the way the signal says to.
///
/// `Drop` alone cannot cover this: a default-disposition SIGINT terminates the
/// process without unwinding, so Ctrl-C at the prompt would hand the shell
/// back with ECHO still cleared.
extern "C" fn restore_echo_and_reraise(sig: libc::c_int) {
    if ECHO_DISABLED.swap(false, Ordering::SeqCst) {
        let saved = SAVED_LOCAL_FLAGS.load(Ordering::SeqCst) as libc::tcflag_t;
        // SAFETY: `current` is filled in by tcgetattr before it is read, and
        // both calls name the real stdin descriptor. tcgetattr, tcsetattr,
        // signal, and raise are all async-signal-safe, so they are legal here.
        unsafe {
            let mut current: libc::termios = std::mem::zeroed();
            if libc::tcgetattr(libc::STDIN_FILENO, &mut current) == 0 {
                current.c_lflag = (current.c_lflag & !ECHO_FLAGS) | (saved & ECHO_FLAGS);
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &current);
            }
        }
    }
    // SAFETY: restoring the default disposition and re-raising exits with the
    // status the caller expects from the signal rather than a plain success.
    unsafe {
        libc::signal(sig, libc::SIG_DFL);
        libc::raise(sig);
    }
}

/// Restore terminal echo when the secret prompt ends, however it ends.
struct EchoGuard {
    saved: nix::sys::termios::Termios,
    /// Handlers displaced by [`ECHO_RESTORING_SIGNALS`], in install order.
    previous: Vec<(Signal, SigHandler)>,
}

impl EchoGuard {
    /// Turn off echo on the controlling terminal.
    fn disable() -> Result<Self> {
        use nix::sys::termios;

        let failed = |err: nix::Error| {
            NonoError::ActionRequired(format!(
                "nono: cannot disable terminal echo ({err}); \
                 pipe the secret on stdin instead"
            ))
        };

        let stdin = std::io::stdin();
        let saved = termios::tcgetattr(&stdin).map_err(failed)?;

        let mut quiet = saved.clone();
        quiet.local_flags.remove(termios::LocalFlags::ECHO);
        quiet.local_flags.remove(termios::LocalFlags::ECHONL);
        // TCSAFLUSH discards anything typed before the prompt appeared: those
        // keystrokes were echoed by the terminal, so accepting them here would
        // store a secret the user already saw on screen.
        termios::tcsetattr(&stdin, termios::SetArg::TCSAFLUSH, &quiet).map_err(failed)?;

        // Publish the restore data before a handler can run on it.
        SAVED_LOCAL_FLAGS.store(saved.local_flags.bits() as u64, Ordering::SeqCst);
        ECHO_DISABLED.store(true, Ordering::SeqCst);

        let mut previous = Vec::with_capacity(ECHO_RESTORING_SIGNALS.len());
        for signal in ECHO_RESTORING_SIGNALS {
            // SAFETY: the handler only calls async-signal-safe functions.
            match unsafe { signal::signal(signal, SigHandler::Handler(restore_echo_and_reraise)) } {
                Ok(handler) => previous.push((signal, handler)),
                // A signal that cannot be caught still leaves the guard's Drop
                // path, which covers every non-fatal exit.
                Err(e) => tracing::debug!("cannot catch {signal:?} at the secret prompt: {e}"),
            }
        }

        Ok(Self { saved, previous })
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = nix::sys::termios::tcsetattr(
            std::io::stdin(),
            nix::sys::termios::SetArg::TCSANOW,
            &self.saved,
        );
        // Cleared only after the terminal is back, so a signal arriving in
        // between still restores echo instead of skipping it.
        ECHO_DISABLED.store(false, Ordering::SeqCst);

        for (signal, handler) in self.previous.drain(..) {
            // SAFETY: restoring a disposition the process itself installed.
            let _ = unsafe { nix::sys::signal::signal(signal, handler) };
        }
    }
}

pub(crate) fn run_credential(args: CredentialArgs) -> Result<()> {
    match args.command {
        CredentialCommands::Set(args) => run_set(args),
        CredentialCommands::List(args) => run_list(args),
        CredentialCommands::Remove(args) => run_remove(args),
        CredentialCommands::Check(args) => run_check(args),
    }
}

fn run_set(args: CredentialSetArgs) -> Result<()> {
    let catalog = ServiceCatalog::load(args.profile.as_deref())?;
    let target = resolve_target(
        &catalog,
        args.service.as_deref(),
        args.account.as_deref(),
        true,
    )?;

    let secret = read_secret(&format!("Secret for {}: ", target.label()))?;
    nono::store_secret(&target.service, &target.account, secret.as_str())?;

    println!("{} stored {}", "✓".green(), target.label());

    if let (Some(service), None) = (args.service.as_deref(), args.account.as_deref()) {
        println!("  nono run --credential {service} -- <command>");
    }
    Ok(())
}

fn run_list(args: CredentialListArgs) -> Result<()> {
    let catalog = ServiceCatalog::load(args.profile.as_deref())?;
    let mut keystore = KeystoreProbe::default();
    let rows: Vec<(ResolvedService, Availability)> = catalog
        .all()
        .into_iter()
        .map(|service| {
            let availability = service.source.availability(&mut keystore);
            (service, availability)
        })
        .collect();

    if args.json {
        let payload: Vec<serde_json::Value> = rows
            .iter()
            .map(|(service, availability)| {
                serde_json::json!({
                    "service": service.name,
                    "origin": service.origin.label(),
                    "source": service.source.json(),
                    "display": service.source.display(),
                    "status": availability.json(),
                })
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|e| NonoError::ConfigParse(format!(
                "failed to serialize credential list: {e}"
            )))?
        );
        return Ok(());
    }

    if rows.is_empty() {
        println!("No credential services defined.");
        return Ok(());
    }

    let name_width = column_width(rows.iter().map(|(s, _)| s.name.len()), "SERVICE".len());
    let origin_width = column_width(
        rows.iter().map(|(s, _)| s.origin.label().len()),
        "ORIGIN".len(),
    );
    let source_width = column_width(
        rows.iter().map(|(s, _)| s.source.display().len()),
        "SOURCE".len(),
    );

    println!(
        "{:<name_width$}  {:<origin_width$}  {:<source_width$}  STATUS",
        "SERVICE", "ORIGIN", "SOURCE"
    );
    for (service, availability) in &rows {
        println!(
            "{:<name_width$}  {:<origin_width$}  {:<source_width$}  {}",
            service.name,
            service.origin.label(),
            service.source.display(),
            availability.cell()
        );
    }

    for (service, availability) in &rows {
        if let Availability::Error(message) = availability {
            eprintln!("{}: {}: {}", "warning".yellow(), service.name, message);
        }
    }

    Ok(())
}

fn run_remove(args: CredentialRmArgs) -> Result<()> {
    let catalog = ServiceCatalog::load(args.profile.as_deref())?;
    let target = resolve_target(
        &catalog,
        args.service.as_deref(),
        args.account.as_deref(),
        false,
    )?;

    if !args.yes && !confirm(&format!("Remove {}?", target.label()))? {
        return Err(NonoError::Cancelled(
            "nono: credential removal cancelled".to_string(),
        ));
    }

    if nono::delete_secret(&target.service, &target.account)? {
        println!("{} removed {}", "✓".green(), target.label());
    } else {
        println!("No credential stored for {}", target.label());
    }
    Ok(())
}

fn run_check(args: CredentialCheckArgs) -> Result<()> {
    let catalog = ServiceCatalog::load(args.profile.as_deref())?;

    let (label, references) = match args.account.as_deref() {
        Some(account) => {
            validate_account(account)?;
            (
                account_label(DEFAULT_SERVICE, account),
                vec![account.to_string()],
            )
        }
        None => {
            let name = args.service.as_deref().ok_or_else(|| {
                NonoError::ConfigParse("a service name or --account is required".to_string())
            })?;
            let service = catalog.resolve(name)?;
            if service.references.is_empty() {
                return Err(NonoError::ActionRequired(format!(
                    "nono: service '{}' has no stored credential to check ({}).",
                    service.name,
                    service.source.display()
                )));
            }
            (
                format!("'{}' ({})", service.name, service.source.display()),
                service.references,
            )
        }
    };

    for credential_ref in &references {
        drop(nono::load_secret_by_ref(DEFAULT_SERVICE, credential_ref)?);
    }

    println!("{} {label} loads", "✓".green());
    Ok(())
}

/// Render a keystore entry as the user should think about it.
fn account_label(service: &str, account: &str) -> String {
    if service == DEFAULT_SERVICE {
        format!("keystore account '{account}'")
    } else {
        format!("keystore account '{account}' (service '{service}')")
    }
}

/// Width for a left-aligned column, never narrower than its header.
fn column_width(widths: impl Iterator<Item = usize>, header: usize) -> usize {
    widths.fold(header, usize::max)
}

/// Explain why a service's credential cannot be written to the keystore, and
/// what to do instead.
fn declined_write_error(service: &ResolvedService) -> NonoError {
    let name = &service.name;
    let mut lines = match &service.source {
        CredentialSource::Keystore { .. } => {
            return NonoError::ConfigParse(format!(
                "service '{name}' is keystore-backed; this is a bug in the decline path"
            ));
        }
        CredentialSource::KeystoreEncoded {
            service: keystore_service,
            account,
            ..
        } => vec![
            format!(
                "service '{name}' reads {} with ?decode=go-keyring.",
                account_label(keystore_service, account)
            ),
            "nono cannot write that encoding. Store the value with the tool that owns it, \
             or drop ?decode from credential_key to use a plain keystore entry."
                .to_string(),
        ],
        CredentialSource::Env { var } => vec![
            format!("service '{name}' reads environment variable {var}, not the keystore."),
            format!("Export it before running nono: export {var}=<secret>"),
        ],
        CredentialSource::File { display, .. } => vec![
            format!("service '{name}' reads {display}."),
            "Write the secret to that file (mode 0600) instead.".to_string(),
        ],
        CredentialSource::External { manager, display } => vec![
            format!("service '{name}' is backed by {manager} ({display})."),
            format!("Store the secret in {manager}; a keystore entry would be ignored."),
        ],
        CredentialSource::OAuth2 {
            client_id,
            client_secret,
        } => vec![
            format!("service '{name}' uses OAuth2 client credentials."),
            "Store each half under its own account:".to_string(),
            format!("  {}", oauth2_half_hint(name, client_id)),
            format!("  {}", oauth2_half_hint(name, client_secret)),
        ],
        CredentialSource::Ambient { mechanism } => vec![format!(
            "service '{name}' authenticates via {mechanism}; there is no secret to store."
        )],
    };

    lines.push("To store a keystore entry anyway, re-run with --account <name>.".to_string());
    NonoError::ActionRequired(format!("nono: {}", lines.join("\n      ")))
}

/// One line of guidance for an OAuth2 half.
fn oauth2_half_hint(service: &str, credential_ref: &str) -> String {
    match CredentialSource::classify(credential_ref) {
        CredentialSource::Keystore {
            service: keystore_service,
            account,
        } if keystore_service == DEFAULT_SERVICE => {
            format!("nono credential set {service} --account {account}")
        }
        // `--account` always writes the default keystore service, so it cannot
        // reach a half the profile points at another one.
        CredentialSource::Keystore {
            service: keystore_service,
            account,
        } => format!(
            "{} — store it under keystore service '{keystore_service}' with the \
             platform tool; nono writes only '{DEFAULT_SERVICE}'",
            account_label(&keystore_service, &account)
        ),
        other => other.display(),
    }
}

/// Warn when `--account` writes somewhere the named service does not read.
fn print_account_override_warning(service: &ResolvedService, account: &str) {
    // An OAuth2 service reads two accounts, so match against every reference
    // rather than the single source the list column summarizes.
    let reads_account = service.references.iter().any(|credential_ref| {
        matches!(
            CredentialSource::classify(credential_ref),
            CredentialSource::Keystore { service: keystore_service, account: resolved }
                if keystore_service == DEFAULT_SERVICE && resolved == account
        )
    });
    if reads_account {
        return;
    }

    eprintln!(
        "{}: service '{}' reads {} at run time, so this entry is only used if a \
         profile sets credential_key to '{}'",
        "warning".yellow(),
        service.name,
        service.source.display(),
        account
    );
}

/// Compact `service/account` form for the `list` source column.
fn qualified_account(service: &str, account: &str) -> String {
    if service == DEFAULT_SERVICE {
        account.to_string()
    } else {
        format!("{service}/{account}")
    }
}

/// Ask for confirmation on stderr. A non-interactive stdin has no answer to
/// give, so the caller is told to pass `-y` rather than being assumed to agree.
fn confirm(question: &str) -> Result<bool> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        return Err(NonoError::ActionRequired(format!(
            "nono: {question} stdin is not a terminal; re-run with -y to confirm."
        )));
    }

    eprint!("{question} [y/N]: ");
    std::io::stderr().flush().map_err(NonoError::Io)?;

    let mut answer = String::new();
    stdin.lock().read_line(&mut answer).map_err(NonoError::Io)?;
    let answer = answer.trim().to_ascii_lowercase();
    Ok(answer == "y" || answer == "yes")
}

/// Read a secret without echoing it.
///
/// Falls back to a plain line read when stdin is not a terminal.
fn read_secret(prompt: &str) -> Result<Zeroizing<String>> {
    let raw = if std::io::stdin().is_terminal() {
        // Echo goes off before the prompt is written, so there is no window in
        // which a signal can arrive after the user has been invited to type but
        // before the handler that puts the terminal back is installed.
        let _echo_off = EchoGuard::disable()?;

        eprint!("{prompt}");
        std::io::stderr().flush().map_err(NonoError::Io)?;

        let raw = read_secret_line()?;
        eprintln!();
        raw
    } else {
        read_secret_line()?
    };

    if raw.is_empty() {
        return Err(NonoError::ActionRequired(
            "nono: no secret on stdin".to_string(),
        ));
    }

    let mut buffer = decode_secret(raw)?;

    let trimmed = buffer.trim_end_matches(['\n', '\r']).len();
    buffer.truncate(trimmed);

    if trimmed > MAX_SECRET_LEN {
        return Err(NonoError::ActionRequired(format!(
            "nono: secret longer than {MAX_SECRET_LEN} bytes; nothing stored"
        )));
    }

    if buffer.is_empty() {
        return Err(NonoError::ActionRequired(
            "nono: empty secret; nothing stored".to_string(),
        ));
    }

    // Surrounding whitespace is almost always a paste artifact, but trimming
    // it silently would corrupt a secret that legitimately contains it.
    if buffer.trim() != buffer.as_str() {
        eprintln!(
            "{}: secret has leading or trailing whitespace; storing it verbatim",
            "warning".yellow()
        );
    }

    Ok(buffer)
}

/// The longest secret `set` accepts, in bytes.
const MAX_SECRET_LEN: usize = 4 * 1024;

/// Read one line of secret from stdin, unbuffered.
///
/// `Stdin::lock()` reads through a process-global 8 KiB `BufReader` that is
/// never zeroed and outlives every `Zeroizing` copy taken from it, so the
/// plaintext would stay in memory for the rest of the run. Reading the raw
/// descriptor a byte at a time keeps the only copy in the returned buffer, and
/// stops at the newline so nothing past it is taken from a pipe.
fn read_secret_line() -> Result<Zeroizing<Vec<u8>>> {
    use nix::errno::Errno;
    use std::os::fd::AsFd;

    // One byte over the limit is enough to tell "at the limit" from "too long",
    // and the capacity is reserved up front: growing mid-read would free an
    // unzeroed copy of a prefix of the secret.
    let mut buffer = Zeroizing::new(Vec::with_capacity(MAX_SECRET_LEN + 1));
    let stdin = std::io::stdin();

    while buffer.len() <= MAX_SECRET_LEN {
        let mut byte = [0u8; 1];
        match nix::unistd::read(stdin.as_fd(), &mut byte) {
            Ok(0) => break,
            Ok(_) => {
                buffer.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            }
            Err(Errno::EINTR) => continue,
            Err(e) => return Err(NonoError::Io(std::io::Error::from(e))),
        }
    }

    Ok(buffer)
}

/// Reinterpret the raw bytes as UTF-8 without copying the plaintext.
fn decode_secret(mut raw: Zeroizing<Vec<u8>>) -> Result<Zeroizing<String>> {
    // `String::from_utf8` takes the buffer's allocation over rather than
    // copying it, so no second plaintext buffer exists to zero.
    match String::from_utf8(std::mem::take(&mut *raw)) {
        Ok(text) => Ok(Zeroizing::new(text)),
        Err(e) => {
            let mut rejected = e.into_bytes();
            rejected.zeroize();
            Err(NonoError::ActionRequired(
                "nono: secret is not valid UTF-8; nothing stored".to_string(),
            ))
        }
    }
}

fn builtin_service(name: &str, cred: &CredentialDef) -> ResolvedService {
    let credential_ref = cred
        .credential_key
        .clone()
        .unwrap_or_else(|| name.to_string());
    ResolvedService {
        name: name.to_string(),
        origin: Origin::BuiltIn,
        source: CredentialSource::classify(&credential_ref),
        references: vec![credential_ref],
    }
}

fn custom_service(name: &str, cred: &CustomCredentialDef) -> ResolvedService {
    let (source, references) = if let Some(auth) = &cred.auth {
        match &auth.client_assertion {
            // Profile validation rejects client_id/client_secret alongside an
            // assertion, so both would be empty strings here.
            Some(nono_proxy::config::ClientAssertionConfig::SpiffeJwt { .. }) => (
                CredentialSource::Ambient {
                    mechanism: "oauth2 (spiffe jwt client assertion)",
                },
                Vec::new(),
            ),
            None => (
                CredentialSource::OAuth2 {
                    client_id: auth.client_id.clone(),
                    client_secret: auth.client_secret.clone(),
                },
                vec![auth.client_id.clone(), auth.client_secret.clone()],
            ),
        }
    } else if let Some(credential_ref) = &cred.credential_key {
        (
            CredentialSource::classify(credential_ref),
            vec![credential_ref.clone()],
        )
    } else if cred.aws_auth.is_some() {
        (
            CredentialSource::Ambient {
                mechanism: "aws-sigv4",
            },
            Vec::new(),
        )
    } else if cred.spiffe.is_some() {
        (
            CredentialSource::Ambient {
                mechanism: "spiffe",
            },
            Vec::new(),
        )
    } else {
        (
            CredentialSource::Ambient {
                mechanism: "none (no credential injected)",
            },
            Vec::new(),
        )
    };

    ResolvedService {
        name: name.to_string(),
        origin: Origin::Profile,
        source,
        references,
    }
}

/// Split a `keyring://service/account[?decode=…]` reference.
///
/// Returns `None` for URIs that fail validation, so callers surface the
/// profile error instead of writing to a guessed account.
fn parse_keyring_ref(credential_ref: &str) -> Option<(String, String, bool)> {
    nono::validate_keyring_uri(credential_ref).ok()?;
    let path = credential_ref.strip_prefix("keyring://")?;
    let (path, query) = match path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path, None),
    };
    let (service, account) = path.split_once('/')?;
    Some((
        service.to_string(),
        account.to_string(),
        query.is_some_and(|q| q.contains("decode=")),
    ))
}

/// Resolve the keystore entry a write or delete should target.
fn resolve_target(
    catalog: &ServiceCatalog,
    service_name: Option<&str>,
    account: Option<&str>,
    decline_non_keystore: bool,
) -> Result<KeystoreTarget> {
    if let Some(account) = account {
        validate_account(account)?;
        if let Some(name) = service_name {
            let service = catalog.resolve(name)?;
            print_account_override_warning(&service, account);
        }
        return Ok(KeystoreTarget {
            service: DEFAULT_SERVICE.to_string(),
            account: account.to_string(),
        });
    }

    let name = service_name.ok_or_else(|| {
        NonoError::ConfigParse("a service name or --account is required".to_string())
    })?;
    let service = catalog.resolve(name)?;

    match &service.source {
        CredentialSource::Keystore {
            service: keystore_service,
            account,
        } => Ok(KeystoreTarget {
            service: keystore_service.clone(),
            account: account.clone(),
        }),
        // nono cannot produce the go-keyring encoding a write would need, but
        // the entry itself is an ordinary keystore entry, so a delete targets
        // it like any other.
        CredentialSource::KeystoreEncoded {
            service: keystore_service,
            account,
            ..
        } if !decline_non_keystore => Ok(KeystoreTarget {
            service: keystore_service.clone(),
            account: account.clone(),
        }),
        _ if decline_non_keystore => Err(declined_write_error(&service)),
        _ => Err(NonoError::ActionRequired(format!(
            "nono: service '{}' is not keystore-backed ({}); nothing to remove.",
            service.name,
            service.source.display()
        ))),
    }
}

/// Reject account names that are really credential references.
fn validate_account(account: &str) -> Result<()> {
    if account.is_empty() {
        return Err(NonoError::ConfigParse(
            "--account cannot be empty".to_string(),
        ));
    }
    if account.contains("://") {
        return Err(NonoError::ConfigParse(format!(
            "--account takes a keystore account name, not a credential reference: {account}"
        )));
    }
    if let Some(bad) = account.chars().find(|c| c.is_control()) {
        return Err(NonoError::ConfigParse(format!(
            "--account contains a control character {bad:?}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn catalog() -> ServiceCatalog {
        match ServiceCatalog::load(None) {
            Ok(catalog) => catalog,
            Err(e) => panic!("embedded network policy must load: {e}"),
        }
    }

    fn custom_credential(json: serde_json::Value) -> CustomCredentialDef {
        match serde_json::from_value(json) {
            Ok(def) => def,
            Err(e) => panic!("custom credential fixture must deserialize: {e}"),
        }
    }

    #[test]
    fn bare_reference_is_a_default_service_keystore_account() {
        assert_eq!(
            CredentialSource::classify("openai"),
            CredentialSource::Keystore {
                service: DEFAULT_SERVICE.to_string(),
                account: "openai".to_string(),
            }
        );
    }

    #[test]
    fn env_reference_is_not_keystore_backed() {
        assert_eq!(
            CredentialSource::classify("env://ANTHROPIC_API_KEY"),
            CredentialSource::Env {
                var: "ANTHROPIC_API_KEY".to_string(),
            }
        );
    }

    #[test]
    fn keyring_reference_keeps_its_custom_service() {
        assert_eq!(
            CredentialSource::classify("keyring://gh:github.com/user"),
            CredentialSource::Keystore {
                service: "gh:github.com".to_string(),
                account: "user".to_string(),
            }
        );
    }

    #[test]
    fn decoded_keyring_reference_is_not_writable() {
        assert_eq!(
            CredentialSource::classify("keyring://gh:github.com/user?decode=go-keyring"),
            CredentialSource::KeystoreEncoded {
                service: "gh:github.com".to_string(),
                account: "user".to_string(),
                reference: "keyring://gh:github.com/user?decode=go-keyring".to_string(),
            }
        );
    }

    #[test]
    fn manager_references_are_redacted() {
        let source = CredentialSource::classify("op://vault/item/field");
        assert_eq!(source.display(), "1password: op://vault/item/<redacted>");
    }

    #[test]
    fn builtin_openai_resolves_to_its_own_account() {
        let service = match catalog().resolve("openai") {
            Ok(service) => service,
            Err(e) => panic!("openai must resolve: {e}"),
        };
        assert_eq!(service.origin, Origin::BuiltIn);
        assert_eq!(
            service.source,
            CredentialSource::Keystore {
                service: DEFAULT_SERVICE.to_string(),
                account: "openai".to_string(),
            }
        );
    }

    #[test]
    fn builtin_anthropic_resolves_to_an_env_var() {
        let service = match catalog().resolve("anthropic") {
            Ok(service) => service,
            Err(e) => panic!("anthropic must resolve: {e}"),
        };
        assert_eq!(
            service.source,
            CredentialSource::Env {
                var: "ANTHROPIC_API_KEY".to_string(),
            }
        );
    }

    #[test]
    fn unknown_service_lists_the_available_ones() {
        let error = match catalog().resolve("nope") {
            Err(error) => error.to_string(),
            Ok(_) => panic!("unknown service must not resolve"),
        };
        assert!(error.contains("openai"), "{error}");
        assert!(error.contains("--account"), "{error}");
    }

    #[test]
    fn env_backed_service_declines_a_keystore_write() {
        let error = match resolve_target(&catalog(), Some("anthropic"), None, true) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("env-backed service must not resolve to a keystore write"),
        };
        assert!(error.contains("ANTHROPIC_API_KEY"), "{error}");
        assert!(error.contains("--account"), "{error}");
    }

    #[test]
    fn keystore_backed_service_resolves_to_its_account() {
        let target = match resolve_target(&catalog(), Some("openai"), None, true) {
            Ok(target) => target,
            Err(e) => panic!("openai must resolve to a keystore target: {e}"),
        };
        assert_eq!(target.service, DEFAULT_SERVICE);
        assert_eq!(target.account, "openai");
    }

    #[test]
    fn encoded_keystore_service_can_still_be_removed() {
        let cred = custom_credential(serde_json::json!({
            "upstream": "https://api.github.com",
            "credential_key": "keyring://gh:github.com/user?decode=go-keyring",
        }));
        let mut catalog = catalog();
        catalog.custom.insert("gh".to_string(), cred);

        let target = match resolve_target(&catalog, Some("gh"), None, false) {
            Ok(target) => target,
            Err(e) => panic!("an encoded entry must still be removable: {e}"),
        };
        assert_eq!(target.service, "gh:github.com");
        assert_eq!(target.account, "user");

        let error = match resolve_target(&catalog, Some("gh"), None, true) {
            Err(error) => error.to_string(),
            Ok(_) => panic!("an encoded entry must not accept a plain write"),
        };
        assert!(error.contains("decode=go-keyring"), "{error}");
    }

    #[test]
    fn account_override_bypasses_service_resolution() {
        let target = match resolve_target(&catalog(), Some("anthropic"), Some("alt_key"), true) {
            Ok(target) => target,
            Err(e) => panic!("--account must override: {e}"),
        };
        assert_eq!(target.account, "alt_key");
    }

    #[test]
    fn account_rejects_credential_references() {
        assert!(validate_account("op://vault/item/field").is_err());
        assert!(validate_account("env://FOO").is_err());
        assert!(validate_account("openai").is_ok());
    }

    #[test]
    fn client_assertion_route_stores_no_secret() {
        let cred = custom_credential(serde_json::json!({
            "upstream": "https://api.example.com",
            "auth": {
                "token_url": "https://auth.example.com/token",
                "client_assertion": {
                    "type": "spiffe_jwt",
                    "workload_api_socket": "unix:///run/spire/agent.sock",
                    "audience": ["https://auth.example.com"],
                },
            },
        }));

        let service = custom_service("internal", &cred);
        assert_eq!(
            service.source,
            CredentialSource::Ambient {
                mechanism: "oauth2 (spiffe jwt client assertion)",
            }
        );
        assert!(service.references.is_empty(), "{:?}", service.references);
    }

    #[test]
    fn client_credentials_route_reads_both_halves() {
        let cred = custom_credential(serde_json::json!({
            "upstream": "https://api.example.com",
            "auth": {
                "token_url": "https://auth.example.com/token",
                "client_id": "svc-id",
                "client_secret": "svc_secret_account",
            },
        }));

        let service = custom_service("internal", &cred);
        assert_eq!(
            service.source,
            CredentialSource::OAuth2 {
                client_id: "svc-id".to_string(),
                client_secret: "svc_secret_account".to_string(),
            }
        );
        assert_eq!(service.references.len(), 2);
    }

    #[test]
    fn oauth2_hint_offers_set_only_for_the_default_keystore_service() {
        assert_eq!(
            oauth2_half_hint("internal", "internal_client_secret"),
            "nono credential set internal --account internal_client_secret"
        );

        let hint = oauth2_half_hint("internal", "keyring://vault:internal/client_secret");
        assert!(!hint.contains("nono credential set"), "{hint}");
        assert!(hint.contains("vault:internal"), "{hint}");
    }

    #[test]
    fn a_keystore_failure_leaves_the_rest_unprobed() {
        let mut probe = KeystoreProbe::default();
        let first = probe.record(Err(NonoError::KeystoreAccess(
            "keyring lookup for 'openai' timed out after 120s".to_string(),
        )));
        assert!(matches!(first, Availability::Error(_)), "{first:?}");

        // Short-circuited, so this reaches no keystore: a second locked-keychain
        // wait is what the sweep exists to avoid.
        assert_eq!(probe.exists("nono", "openai"), Availability::NotProbed);
    }

    #[test]
    fn a_decode_failure_does_not_stop_the_sweep() {
        let mut probe = KeystoreProbe::default();
        let result = probe.record(Err(NonoError::ConfigParse(
            "does not have the expected 'go-keyring-base64:' prefix".to_string(),
        )));
        assert!(matches!(result, Availability::Error(_)), "{result:?}");
        assert!(!probe.keystore_unavailable);
    }

    #[test]
    fn a_missing_entry_is_not_a_probe_failure() {
        let mut probe = KeystoreProbe::default();
        assert_eq!(
            probe.record(Err(NonoError::SecretNotFound("openai".to_string()))),
            Availability::Missing
        );
        assert!(!probe.keystore_unavailable);
    }

    #[test]
    fn oauth2_availability_needs_both_halves() {
        assert_eq!(
            Availability::Available.and(Availability::Missing),
            Availability::Missing
        );
        assert_eq!(
            Availability::Available.and(Availability::Available),
            Availability::Available
        );
    }
}
