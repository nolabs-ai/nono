//! CLI argument definitions for nono
//!
//! Uses clap for argument parsing. This module defines all subcommands
//! and their options.

use clap::builder::styling::{Style, Styles};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const STYLES: Styles = Styles::plain().header(Style::new().bold());

/// Parse a byte-size value of the form `512M` / `1G` / `256K` / raw bytes `268435456`.
/// Suffix is case-insensitive; multipliers are 1024-based (K=1024, M=1024^2, G=1024^3, T=1024^4).
/// Rejects `0`, negative, empty, unrecognized suffixes, and values that overflow u64.
pub(crate) fn parse_byte_size(s: &str) -> std::result::Result<u64, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("memory size cannot be empty".to_string());
    }
    let (num_str, multiplier): (&str, u64) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let mult: u64 = match c.to_ascii_uppercase() {
                'K' => 1024,
                'M' => 1024 * 1024,
                'G' => 1024 * 1024 * 1024,
                'T' => 1024u64.pow(4),
                other => {
                    return Err(format!(
                        "unrecognized memory suffix '{other}'; expected K/M/G/T"
                    ))
                }
            };
            (&s[..s.len() - 1], mult)
        }
        _ => (s, 1),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid memory value '{s}'"))?;
    if n == 0 {
        return Err("memory value must be > 0".to_string());
    }
    n.checked_mul(multiplier)
        .ok_or_else(|| format!("memory value '{s}' overflows u64"))
}

/// Parse a duration of the form `30s` / `5m` / `1h` / `1d` / raw seconds `300`.
/// Rejects `0`, negative, empty, unrecognized suffixes, and overflow past u64 seconds.
pub(crate) fn parse_duration(s: &str) -> std::result::Result<std::time::Duration, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("timeout cannot be empty".to_string());
    }
    let (num_str, multiplier): (&str, u64) = match s.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let mult: u64 = match c.to_ascii_lowercase() {
                's' => 1,
                'm' => 60,
                'h' => 3600,
                'd' => 86_400,
                other => {
                    return Err(format!(
                        "unrecognized duration suffix '{other}'; expected s/m/h/d"
                    ))
                }
            };
            (&s[..s.len() - 1], mult)
        }
        _ => (s, 1),
    };
    let n: u64 = num_str
        .parse()
        .map_err(|_| format!("invalid duration '{s}'"))?;
    if n == 0 {
        return Err("timeout must be > 0".to_string());
    }
    let secs = n
        .checked_mul(multiplier)
        .ok_or_else(|| format!("duration '{s}' overflows u64 seconds"))?;
    Ok(std::time::Duration::from_secs(secs))
}

/// Parse `--cpu-percent` at clap time, with platform-level gating.
///
/// On macOS, this function rejects the flag immediately with a message referencing
/// REQ-RESL-NIX-03 acceptance criterion 3. No child is spawned and no cgroup or
/// rlimit syscall is issued.
///
/// On Linux and Windows, the value is validated as a `u16` in `1..=100` and returned.
///
/// # macOS rejection rationale
///
/// macOS does not have a per-process CPU-quota equivalent (no cgroup-style `cpu.max`).
/// `RLIMIT_CPU` measures aggregate CPU time, not rate, and is not a useful substitute.
/// Accepting the flag silently on macOS would give a false sense of security.
///
/// The `MacosResourceLimits::new` function in `supervisor_macos.rs` also rejects
/// `cpu_percent` as a defense-in-depth check for programmatic callers.
pub(crate) fn parse_cpu_percent(s: &str) -> std::result::Result<u16, String> {
    #[cfg(target_os = "macos")]
    {
        let _ = s;
        return Err(
            "--cpu-percent is not supported on macOS: there is no per-process \
             CPU-quota equivalent (no cgroup cpu.max). See REQUIREMENTS.md \
             § REQ-RESL-NIX-03 acceptance criterion 3 (cpu_percent_macos)."
                .into(),
        );
    }
    #[cfg(not(target_os = "macos"))]
    {
        let n: u16 = s
            .trim()
            .parse()
            .map_err(|_| format!("invalid cpu_percent '{s}': expected an integer in 1..=100"))?;
        if !(1..=100).contains(&n) {
            return Err(format!("--cpu-percent must be in 1..=100; got {n}"));
        }
        Ok(n)
    }
}

/// Validate an environment-variable filter pattern for `--env-allow` /
/// `--env-deny`.
///
/// Accepted shapes (matching upstream v0.37.1 commit 1b412a7 semantics):
/// - Exact variable name: `PATH`, `HOME` — must be non-empty and contain no `*`
/// - Trailing-prefix glob: `AWS_*` — `*` must be the last character
/// - Bare wildcard: `*` — matches all variables
///
/// Rejected (fails closed at clap parse time, BEFORE any child launch):
/// - Empty pattern
/// - `*` used as anything other than a trailing suffix (e.g. `A*B`, `*X`)
///
/// Security: fail-closed is mandated by CLAUDE.md § Fail Secure. A malformed
/// filter that silently admitted everything would let sensitive parent-env
/// vars leak into the sandboxed child. We reject at parse time so the child
/// is never launched with an ambiguous filter.
pub(crate) fn parse_env_filter_pattern(s: &str) -> std::result::Result<String, String> {
    let s = s.trim();
    if s.is_empty() {
        return Err("env filter pattern cannot be empty".to_string());
    }
    if s == "*" {
        return Ok(s.to_string());
    }
    if s.contains('*') && !s.ends_with('*') {
        return Err(format!(
            "invalid env filter pattern '{s}': '*' is only valid as a trailing suffix \
             (use 'AWS_*' or a bare '*', not 'A*B' or '*X')"
        ));
    }
    if s.starts_with('*') && s.len() > 1 {
        return Err(format!(
            "invalid env filter pattern '{s}': use a bare '*' to match all variables, \
             or a specific prefix like 'AWS_*'"
        ));
    }
    Ok(s.to_string())
}

#[cfg(target_os = "windows")]
const CLI_ABOUT: &str = "A capability-based shell for running untrusted AI agents and processes with OS-enforced isolation.\nUnsupported flows fail closed instead of implying full sandbox parity.";

#[cfg(not(target_os = "windows"))]
const CLI_ABOUT: &str = "A capability-based shell for running untrusted AI agents and processes\nwith OS-enforced filesystem and network isolation.";

#[cfg(target_os = "windows")]
const SHELL_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono shell                                   # Launch interactive shell (PowerShell or cmd.exe)
  nono shell --shell cmd.exe                   # Explicitly use cmd.exe
  nono shell --allow . --block-net             # Shell with write access but no network

\x1b[1mWINDOWS BEHAVIOR\x1b[0m
  On Windows, `nono shell` launches PowerShell (or cmd.exe if PowerShell is absent)
  inside a Job Object + WFP sandbox via ConPTY (requires Windows 10 build 17763+).
  The supervisor process stays alive as Job Object owner; it does not exec-replace
  the CLI, unlike on Unix.
  Terminal resize events are forwarded via ResizePseudoConsole.
  Ctrl-C is forwarded to the child shell without terminating the supervisor.
  There is no silent fallback to a non-PTY path on unsupported builds.";

#[cfg(not(target_os = "windows"))]
const SHELL_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono shell --allow .                         # Shell with read/write to current dir
  nono shell --profile claude-code             # Use a named profile
  nono shell --allow . --shell /bin/zsh        # Override shell binary
";

#[cfg(target_os = "windows")]
const WRAP_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono wrap --allow . -- cmd /c echo hello    # Sandbox and exec into command
  nono wrap --dry-run -- cmd /c echo hello    # Inspect wrap policy without launching

\x1b[1mWINDOWS BEHAVIOR\x1b[0m
  On Windows, `nono wrap` uses Job Object + WFP enforcement.
  The supervisor process stays alive as the Job Object owner and does NOT
  exec-replace the CLI process, unlike on Unix where nono disappears after exec.
  Proxy filtering is not supported with wrap.";

#[cfg(target_os = "windows")]
const RUN_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono run --allow . claude                    # Read/write current dir, run claude
  nono run --profile claude-code claude        # Use a built-in profile
  nono run --profile claude-code --allow-domain api.openai.com claude
                                               # Restrict outbound access to listed domains
  nono run --read ./src --write ./output cargo build
                                               # Separate read/write permissions
  nono run --allow . --block-net cargo build   # Block network access
  nono run --allow . --env-credential openai_api_key,anthropic_api_key -- claude
                                               # Load secrets from system keystore

\x1b[1mWINDOWS\x1b[0m
  Windows `run` covers the current supported command surface with backend-owned
  launch validation and low-integrity write boundaries.
  Blocked-network and other enforcement-dependent flows require current Windows
  backend readiness and unsupported restrictions fail closed with backend diagnostics.";

#[cfg(not(target_os = "windows"))]
const RUN_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono run --allow . claude                    # Read/write current dir, run claude
  nono run --profile claude-code claude        # Use a built-in profile
  nono run --profile claude-code --allow-domain api.openai.com claude
                                               # Restrict outbound access to listed domains
  nono run --read ./src --write ./output cargo build
                                               # Separate read/write permissions
  nono run --allow . --block-net cargo build   # Block network access
  nono run --allow . --env-credential openai_api_key,anthropic_api_key -- claude
                                               # Load secrets from system keystore
";

#[cfg(target_os = "windows")]
const ROOT_HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  nono <command> [flags]

\x1b[1mGETTING STARTED\x1b[0m
  setup      Set up nono on this system

\x1b[1mCORE USAGE\x1b[0m
  run        Run a command inside the sandbox
  shell      Launch interactive shell (ConPTY, build 17763+); use --dry-run to inspect policy
  wrap       Sandbox and exec into command (supervisor stays alive as Job Object owner)

\x1b[1mEXPLORATION & DEBUGGING\x1b[0m
  learn      Trace a command to discover required filesystem paths
  why        Check why a path or network operation would be allowed or denied

\x1b[1mSESSION MANAGEMENT\x1b[0m
  ps         Inspect the unsupported Windows session-management surface
  stop       Stop a running agent session
  detach     Inspect the unsupported Windows session-management surface
  attach     Inspect the unsupported Windows session-management surface
  logs       View runtime session event logs
  inspect    Show detailed runtime session state
  session    Manage runtime session storage (cleanup)
  rollback   Manage rollback sessions (browse, restore, cleanup)
  audit      View audit trail of sandboxed commands
  trust      Manage file trust and attestation

\x1b[1mPACKAGES\x1b[0m
  pull       Install a signed package from the registry
  remove     Remove an installed package
  update     Update installed packages
  search     Search the registry for packages
  list       List installed packages

\x1b[1mPOLICY & PROFILES\x1b[0m
  policy     Inspect policy groups, profiles, and security rules
  profile    Create and manage nono profiles

\x1b[1mSHELL\x1b[0m
  completion   Generate shell completion scripts

\x1b[1mOPTIONS\x1b[0m
{options}

\x1b[1mLEARN MORE\x1b[0m
  Use `nono <command> --help` for more information about a command.
  Read the docs at https://nono.sh/docs
";

#[cfg(target_os = "windows")]
const PS_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono ps                                      # Unsupported on Windows; prints an explicit limitation

\x1b[1mWINDOWS\x1b[0m
  `nono ps` is intentionally unavailable on Windows.
  Runtime session discovery still depends on detached-session infrastructure
  that is not available on Windows.
  Use `nono run` for supported execution instead of relying on session inspection.";

#[cfg(not(target_os = "windows"))]
const PS_AFTER_HELP: &str = "EXAMPLES:
    # Show running sessions
    nono ps

    # Show all sessions (including exited)
    nono ps --all

    # JSON output
    nono ps --json
";

#[cfg(target_os = "windows")]
const STOP_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono stop <session>                          # Unsupported on Windows; prints an explicit limitation

\x1b[1mWINDOWS\x1b[0m
  `nono stop` is intentionally unavailable on Windows.
  Supervisor-owned session lifecycle control still depends on detached-session
  plumbing that is not available on Windows.";

#[cfg(not(target_os = "windows"))]
const STOP_AFTER_HELP: &str = "EXAMPLES:
    # Stop a session by ID (prefix match)
    nono stop a3f7c2

    # Force stop (SIGKILL)
    nono stop --force a3f7c2
";

#[cfg(target_os = "windows")]
const DETACH_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono detach <session>                        # Unsupported on Windows; prints an explicit limitation

\x1b[1mWINDOWS\x1b[0m
  `nono detach` is intentionally unavailable on Windows.
  PTY-backed detachable runtime sessions are not available on Windows, so help examples for in-band detach do not apply.";

#[cfg(not(target_os = "windows"))]
const DETACH_AFTER_HELP: &str = "EXAMPLES:
    # Detach by session ID
    nono detach a3f7c2

    # Detach by name
    nono detach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach without opening a second terminal.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
";

#[cfg(target_os = "windows")]
const ATTACH_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono attach <session>                        # Unsupported on Windows; prints an explicit limitation

\x1b[1mWINDOWS\x1b[0m
  `nono attach` is intentionally unavailable on Windows.
  Detached-session reattachment still depends on PTY/socket session transport
  that is not available on Windows.";

#[cfg(not(target_os = "windows"))]
const ATTACH_AFTER_HELP: &str = "EXAMPLES:
    # Attach by session ID
    nono attach a3f7c2

    # Attach by name
    nono attach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach from the session.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
";

#[cfg(target_os = "windows")]
const LOGS_AFTER_HELP: &str = "\x1b[1mWINDOWS LIMITATION\x1b[0m
  `nono logs` is intentionally unavailable on Windows.
  Runtime session event-log inspection depends on detached-session infrastructure
  that is not available on Windows.
  Use `nono run` for supported execution instead.

\x1b[1mEXAMPLES\x1b[0m
  nono logs a3f7c2                             # View event log for session
  nono logs --tail 20 a3f7c2                   # Show last 20 events
  nono logs --json a3f7c2                      # JSON output
  nono logs -f a3f7c2                          # Follow events in real-time
";

#[cfg(not(target_os = "windows"))]
const LOGS_AFTER_HELP: &str = "EXAMPLES:
    # View recent events
    nono logs a3f7c2

    # Follow events in real-time
    nono logs -f a3f7c2

    # Show last 20 events
    nono logs --tail 20 a3f7c2

    # JSON output
    nono logs --json a3f7c2
";

#[cfg(target_os = "windows")]
const LOGS_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono logs [flags] <session>

{all-args}
{after-help}";

#[cfg(not(target_os = "windows"))]
const LOGS_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono logs [flags] <session>

{all-args}
{after-help}";

#[cfg(target_os = "windows")]
const INSPECT_AFTER_HELP: &str = "\x1b[1mWINDOWS LIMITATION\x1b[0m
  `nono inspect` is intentionally unavailable on Windows.
  Detailed runtime session inspection depends on detached-session infrastructure
  that is not available on Windows.
  Use `nono run` for supported execution instead.

\x1b[1mEXAMPLES\x1b[0m
  nono inspect a3f7c2                          # Show session details
  nono inspect --json a3f7c2                   # JSON output
";

#[cfg(not(target_os = "windows"))]
const INSPECT_AFTER_HELP: &str = "EXAMPLES:
    # Inspect a session
    nono inspect a3f7c2

    # Include event log
    nono inspect --events a3f7c2

    # JSON output
    nono inspect --json a3f7c2
";

#[cfg(target_os = "windows")]
const INSPECT_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono inspect [flags] <session>

{all-args}
{after-help}";

#[cfg(not(target_os = "windows"))]
const INSPECT_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono inspect [flags] <session>

{all-args}
{after-help}";

#[cfg(target_os = "windows")]
const PRUNE_AFTER_HELP: &str = "\x1b[1mWINDOWS LIMITATION\x1b[0m
  `nono prune` is intentionally unavailable on Windows.
  Runtime session file cleanup depends on session-management infrastructure
  that is not available on Windows.
  Use `nono session cleanup` on a supported platform.

\x1b[1mDEPRECATED\x1b[0m
  `nono prune` is deprecated; use `nono session cleanup` instead.
  This alias is hidden from `nono --help` and will emit a deprecation
  note to stderr on every invocation. Survival horizon: v2.3-milestone
  scoping decision (Plan 22-05b Task 3, AUD-04 acceptance #3).

\x1b[1mEXAMPLES\x1b[0m
  nono prune --dry-run                         # Preview what would be cleaned
  nono prune --older-than 7d                   # Remove exited sessions
  nono prune --all-exited                      # Remove every exited session
  nono prune --keep 10                         # Keep only 10 most recent sessions
";

#[cfg(not(target_os = "windows"))]
const PRUNE_AFTER_HELP: &str = "DEPRECATED:
    `nono prune` is deprecated; use `nono session cleanup` instead.
    This alias is hidden from `nono --help` and will emit a deprecation
    note to stderr on every invocation. Survival horizon: v2.3-milestone
    scoping decision (Plan 22-05b Task 3, AUD-04 acceptance #3).

EXAMPLES:
    # Preview what would be cleaned
    nono prune --dry-run

    # Remove exited sessions older than 7 days (suffix REQUIRED)
    nono prune --older-than 7d

    # Remove every exited session (ignore age — escape hatch)
    nono prune --all-exited

    # Keep only 10 most recent sessions
    nono prune --keep 10
";

#[cfg(target_os = "windows")]
const PRUNE_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono prune [flags]

{all-args}
{after-help}";

#[cfg(not(target_os = "windows"))]
const PRUNE_USAGE: &str = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono prune [flags]

{all-args}
{after-help}";

#[cfg(not(target_os = "windows"))]
const ROOT_HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  nono <command> [flags]

\x1b[1mGETTING STARTED\x1b[0m
  setup      Set up nono on this system

\x1b[1mCORE USAGE\x1b[0m
  run        Run a command inside the sandbox
  shell      Start an interactive shell inside the sandbox
  wrap       Apply sandbox and exec into command (nono disappears)

\x1b[1mEXPLORATION & DEBUGGING\x1b[0m
  learn      [deprecated] Use `nono run` to learn from sandbox denials
  why        Check why a path or network operation would be allowed or denied

\x1b[1mSESSION MANAGEMENT\x1b[0m
  ps         List running or detached sandbox sessions
  stop       Stop a running sandbox session
  detach     Detach from an interactive runtime session
  attach     Attach to a detached runtime session
  logs       View runtime session event logs
  inspect    Show detailed runtime session state
  session    Manage runtime session storage (cleanup)
  rollback   Manage rollback sessions (browse, restore, cleanup)
  audit      View audit trail of sandboxed commands
  trust      Manage file trust and attestation

\x1b[1mPACKS\x1b[0m
  pull       Install a signed nono pack from the registry
  remove     Remove an installed nono pack
  update     Update installed nono packs
  search     Search the registry for nono packs
  list       List installed nono packs

\x1b[1mPOLICY & PROFILES\x1b[0m
  policy     [deprecated] Use 'nono profile' instead
  profile    Create, inspect, and compare nono profiles

\x1b[1mSHELL\x1b[0m
  completion   Generate shell completion scripts

\x1b[1mOPTIONS\x1b[0m
{options}

\x1b[1mLEARN MORE\x1b[0m
  Use `nono <command> --help` for more information about a command.
  Read the docs at https://nono.sh/docs
";

#[cfg(not(target_os = "windows"))]
const WRAP_AFTER_HELP: &str = "\x1b[1mEXAMPLES\x1b[0m
  nono wrap --allow . -- cargo build           # Sandbox and exec into cargo build
  nono wrap --profile developer -- cargo test  # Use a named profile
";

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about = CLI_ABOUT, long_about = None)]
#[command(styles = STYLES, next_help_heading = "OPTIONS")]
#[command(subcommand_help_heading = "")]
#[command(help_template = ROOT_HELP_TEMPLATE)]
pub struct Cli {
    /// Silent mode - suppress all nono output (banner, summary, status)
    #[arg(long, short = 's', global = true, help_heading = "OPTIONS")]
    pub silent: bool,

    /// Color theme for output (mocha, latte, frappe, macchiato, tokyo-night, dark-factory, minimal)
    #[arg(
        long,
        global = true,
        env = "NONO_THEME",
        value_name = "THEME",
        help_heading = "OPTIONS"
    )]
    pub theme: Option<String>,

    /// Write logs to a file instead of stderr
    #[arg(
        long,
        global = true,
        env = "NONO_LOG_FILE",
        value_name = "PATH",
        help_heading = "OPTIONS"
    )]
    pub log_file: Option<PathBuf>,

    /// Internal: used for the double-launch supervisor pattern on Windows.
    #[arg(long, hide = true, global = true)]
    pub internal_supervisor: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    // ── Getting started ─────────────────────────────────────────────────
    /// Set up nono on this system
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono setup [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono setup --profiles                        # Full setup with profile generation
  nono setup --check-only                      # Verify installation and sandbox support
  nono setup --register-wfp-service            # Register the nono-wfp-service
  nono setup --install-wfp-service             # Register the Windows WFP placeholder service
  nono setup --install-wfp-driver              # Register the Windows WFP placeholder driver
  nono setup --start-wfp-service               # Attempt to start the registered WFP placeholder service
  nono setup --start-wfp-driver                # Attempt to start the registered WFP placeholder driver
  nono setup --install-wfp-service --install-wfp-driver --start-wfp-driver --start-wfp-service  # Register the placeholder components, then try to start them
  nono setup --profiles --shell-integration    # Setup with shell integration help
  nono setup -v --profiles                     # Verbose setup
")]
    Setup(SetupArgs),

    // ── Core usage ──────────────────────────────────────────────────────
    /// Run a command inside the sandbox
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono run [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = RUN_AFTER_HELP)]
    Run(Box<RunArgs>),

    /// Start an interactive shell inside the sandbox
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono shell [flags]

{all-args}
{after-help}")]
    #[command(after_help = SHELL_AFTER_HELP)]
    Shell(Box<ShellArgs>),

    /// Apply sandbox and exec into command (nono disappears).
    /// For scripts, piping, and embedding where no parent process is wanted.
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono wrap [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = WRAP_AFTER_HELP)]
    Wrap(Box<WrapArgs>),

    // ── Exploration & debugging ─────────────────────────────────────────
    /// [deprecated] Use `nono run` to learn from sandbox denials
    /// DEPRECATED(canonical="nono run", introduced="v0.50.1", remove_by="v1.0.0", issue="#445")
    #[command(trailing_var_arg = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono learn [flags] <program>...

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mDEPRECATED\x1b[0m
  Use `nono run --profile <name> -- <command>` instead. `nono run` keeps the
  command sandboxed, reports denials, and offers to save profile updates.

\x1b[1mEXAMPLES\x1b[0m
  nono run --profile my-profile -- my-app      # Preferred learning workflow
  nono learn --profile my-profile -- my-app    # Deprecated compatibility path
  nono learn --json -- node server.js          # Output as JSON for profile
  nono learn --timeout 30 -- my-app            # Limit trace duration

\x1b[1mPLATFORM NOTES\x1b[0m
  Linux   Uses strace (install with: apt install strace)
  macOS   Uses fs_usage (requires sudo)
")]
    Learn(Box<LearnArgs>),

    /// Check why a path or network operation would be allowed or denied
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono why [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono why --path ~/.ssh --op read             # Check if ~/.ssh is readable
  nono why --path ./src --op write --allow .   # Check with capability context
  nono why --json --path ~/.aws --op read      # JSON output for agents
  nono why --host api.openai.com --port 443    # Query network access
  nono why --self --path /tmp --op write       # Inside sandbox, query own capabilities
")]
    Why(Box<WhyArgs>),

    // ── Session management ───────────────────────────────────────────────
    /// Manage rollback sessions (browse, restore, cleanup)
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono rollback <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono rollback list                           # List sessions with file changes
  nono rollback show <id> --diff               # Show changes with diff
  nono rollback restore <id>                   # Restore files from a session
  nono rollback restore <id> --dry-run         # Preview what would change
  nono rollback verify <id>                    # Verify session integrity
  nono rollback cleanup --dry-run              # Preview cleanup
")]
    Rollback(RollbackArgs),

    /// View audit trail of sandboxed commands
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono audit <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono audit list                              # List all sessions
  nono audit list --today                      # List sessions from today
  nono audit list --command claude             # Filter by command
  nono audit show <id> --json                  # Export as JSON
")]
    Audit(AuditArgs),

    /// Manage file trust and attestation
    #[command(subcommand_help_heading = "COMMANDS", disable_help_subcommand = true)]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono trust <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono trust sign SKILLS.md                    # Sign with default keystore key
  nono trust sign SKILLS.md --key my-key       # Sign with a specific key ID
  nono trust sign-policy                       # Sign project trust policy
  nono trust sign-policy --user                # Sign user-level trust policy
  nono trust verify SKILLS.md                  # Verify a file
  nono trust verify --all                      # Verify all files matching policy
  nono trust list                              # List files and verification status
  nono trust keygen                            # Generate a new signing key pair
")]
    Trust(TrustArgs),

    /// List running sandboxed sessions
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono ps [flags]

{all-args}
{after-help}")]
    #[command(after_help = PS_AFTER_HELP)]
    Ps(PsArgs),

    /// Stop a running sandboxed session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono stop [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = STOP_AFTER_HELP)]
    Stop(StopArgs),

    /// Detach from a running sandboxed session and return to the shell
    #[command(
        help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono detach <session>

{all-args}
{after-help}",
        alias = "pause",
        after_help = DETACH_AFTER_HELP
    )]
    Detach(DetachArgs),

    /// Attach to a detached or running session from another terminal
    #[command(
        help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono attach <session>

{all-args}
{after-help}",
        alias = "resume",
        after_help = ATTACH_AFTER_HELP
    )]
    Attach(AttachArgs),

    /// View event log for a session
    #[command(help_template = LOGS_USAGE)]
    #[command(after_help = LOGS_AFTER_HELP)]
    Logs(LogsArgs),

    /// Show detailed information about a session
    #[command(help_template = INSPECT_USAGE)]
    #[command(after_help = INSPECT_AFTER_HELP)]
    Inspect(InspectArgs),

    /// [DEPRECATED — use `nono session cleanup`] Clean up old session files
    ///
    /// Plan 22-05b Task 3 (upstream `4f9552ec`): hidden compatibility alias
    /// for `nono session cleanup`. Surfaces a stderr deprecation note on
    /// every invocation; alias survival horizon is a v2.3-milestone
    /// scoping decision (CONTEXT Claude's Discretion). AUD-04 acceptance #3.
    #[command(hide = true)]
    #[command(help_template = PRUNE_USAGE)]
    #[command(after_help = PRUNE_AFTER_HELP)]
    Prune(PruneArgs),

    /// Manage runtime session storage
    ///
    /// Plan 22-05b Task 2 (upstream `4f9552ec`): introduces `nono session
    /// cleanup` as the renamed entry point for the prune semantics.
    /// `Cmd::Prune` is preserved as a hidden alias (Plan 22-05b Task 3
    /// adds `#[command(hide = true)]` + the deprecation note); both
    /// variants delegate to the unchanged `auto_prune_if_needed` /
    /// `run_prune` worker family per Decision 2 LOCKED reframe.
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono session <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono session cleanup --dry-run                # Preview what would be cleaned
  nono session cleanup --older-than 7d          # Remove exited sessions older than 7 days
  nono session cleanup --all-exited             # Remove every exited session (escape hatch)
  nono session cleanup --keep 10                # Keep only 10 most recent sessions
")]
    Session(SessionArgs),

    // ── Policy & profiles ────────────────────────────────────────────────
    /// [deprecated] Use 'nono profile' instead
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono policy <command>

\x1b[1mNOTE\x1b[0m
  These commands are deprecated. Use the corresponding 'nono profile'
  form; every invocation of 'nono policy <sub>' prints a deprecation
  warning to stderr.

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono policy groups        # deprecated -> use 'nono profile groups'
  nono policy profiles      # deprecated -> use 'nono profile list'
  nono policy show <name>   # deprecated -> use 'nono profile show <name>'
  nono policy diff a b      # deprecated -> use 'nono profile diff a b'
  nono policy validate <f>  # deprecated -> use 'nono profile validate <f>'
")]
    Policy(crate::deprecated_policy::PolicyArgs),

    /// Create, inspect, and compare nono profiles
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono profile <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono profile init my-agent                   # Create a new profile with defaults
  nono profile init my-agent --extends default --groups deny_credentials
                                               # Extend an existing profile
  nono profile init my-agent --full            # Generate a full skeleton
  nono profile list                            # List all profiles (built-in and user)
  nono profile show claude-code                # Show a fully resolved profile
  nono profile diff default claude-code        # Compare two profiles
  nono profile validate ~/my-profile.json      # Validate a user profile file
  nono profile groups                          # List all policy groups
  nono profile groups deny_credentials         # Show details for a specific group
  nono profile schema                          # Print JSON Schema for editor validation
  nono profile guide                           # Print profile authoring guide
")]
    Profile(ProfileCmdArgs),

    /// Install a signed nono pack from the registry
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono pull <namespace>/<name>[@<version>] [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono pull nono-project/claude-code
  nono pull nono-project/claude-code@1.2.0 --registry http://localhost:3000
  nono pull nono-project/claude-code --init
")]
    Pull(PullArgs),

    /// Remove an installed nono pack
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono remove <namespace>/<name>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono remove nono-project/claude-code
")]
    Remove(RemoveArgs),

    /// Update installed nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono update [<namespace>/<name>] [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono update
  nono update nono-project/claude-code
")]
    Update(UpdateArgs),

    /// Search the registry for nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono search <query> [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono search claude
  nono search sandbox --json
")]
    Search(SearchArgs),

    /// List installed nono packs
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono list --installed [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono list --installed
  nono list --installed --json
")]
    List(ListArgs),

    /// Generate shell completion scripts
    #[command(name = "completion")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono completion <shell>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono completion bash >> ~/.bashrc
  nono completion zsh > ~/.zfunc/_nono
  nono completion fish > ~/.config/fish/completions/nono.fish
  nono completion powershell >> $PROFILE
")]
    Completions(CompletionsArgs),

    /// Internal: open a URL via supervisor IPC
    #[command(hide = true)]
    OpenUrlHelper(OpenUrlHelperArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct PullArgs {
    /// Package reference (<namespace>/<name>[@<version>])
    pub package_ref: String,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Overwrite conflicts and accept signer changes
    #[arg(long, help_heading = "OPTIONS")]
    pub force: bool,

    /// Copy project instructions into the current directory
    #[arg(long, help_heading = "OPTIONS")]
    pub init: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RemoveArgs {
    /// Installed package reference (<namespace>/<name>)
    pub package_ref: String,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct UpdateArgs {
    /// Optional package reference (<namespace>/<name>)
    pub package_ref: Option<String>,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Accept signer changes
    #[arg(long, help_heading = "OPTIONS")]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SearchArgs {
    /// Search query
    pub query: String,

    /// Registry base URL
    #[arg(
        long,
        env = "NONO_REGISTRY",
        value_name = "URL",
        help_heading = "OPTIONS"
    )]
    pub registry: Option<String>,

    /// Output as JSON
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ListArgs {
    /// Show installed nono packs
    #[arg(long, help_heading = "OPTIONS")]
    pub installed: bool,

    /// Output as JSON
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for the hidden open-url-helper subcommand.
///
/// Invoked as `BROWSER=nono open-url-helper` on Linux, or via the `open`
/// PATH shim on macOS. Reads `NONO_SUPERVISOR_FD` from the environment,
/// sends an `OpenUrl` IPC message to the unsandboxed supervisor, and
/// waits for a response.
#[derive(Parser, Debug, Clone)]
pub struct OpenUrlHelperArgs {
    /// The URL to open
    pub url: String,
}

/// Shell variant for completion generation.
///
/// Mirrors `clap_complete::Shell` but is defined here so it implements
/// `clap::ValueEnum` and appears correctly in `--help` output.
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum CompletionShell {
    /// Bourne Again SHell (bash)
    Bash,
    /// Z Shell (zsh)
    Zsh,
    /// Friendly Interactive Shell (fish)
    Fish,
    /// PowerShell
    #[value(name = "powershell")]
    PowerShell,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    pub shell: CompletionShell,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

// NOTE: `PolicyArgs`, `PolicyCommands`, and `Policy*Args` types that
// backed `nono policy <sub>` now live in `crate::deprecated_policy`. They
// share their inner arg shapes with `ProfileGroupsArgs` / `ProfileListArgs`
// / `ProfileShowArgs` / `ProfileDiffArgs` / `ProfileValidateArgs` via
// `pub use` aliases so there is no parallel set of types to keep in sync.

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ProfileCmdArgs {
    #[command(subcommand)]
    pub command: ProfileCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum ProfileCommands {
    /// Generate a skeleton profile JSON file
    Init(ProfileInitArgs),
    /// List all available profiles (built-in and user)
    List(ProfileListArgs),
    /// Apply a YAML overlay to a profile file via yaml_merge directive
    Patch(ProfilePatchArgs),
    /// Show a fully resolved profile
    Show(ProfileShowArgs),
    /// Diff two profiles
    Diff(ProfileDiffArgs),
    /// Validate a profile JSON file
    Validate(ProfileValidateArgs),
    /// List policy groups or show details for a specific group
    Groups(ProfileGroupsArgs),
    /// Output the JSON Schema for profile files
    Schema(ProfileSchemaArgs),
    /// Print the profile authoring guide
    Guide(ProfileGuideArgs),
}

#[derive(Parser, Debug)]
pub struct ProfileInitArgs {
    /// Profile name (alphanumeric + hyphens)
    pub name: String,
    /// Base profile to extend
    #[arg(long)]
    pub extends: Option<String>,
    /// Security groups to include (comma-separated)
    #[arg(long, value_delimiter = ',')]
    pub groups: Vec<String>,
    /// Profile description
    #[arg(long)]
    pub description: Option<String>,
    /// Generate a full skeleton with all sections
    #[arg(long)]
    pub full: bool,
    /// Output file path (default: ~/.config/nono/profiles/<name>.json)
    #[arg(long, short)]
    pub output: Option<PathBuf>,
    /// Overwrite existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileSchemaArgs {
    /// Write schema to a file instead of stdout
    #[arg(long, short)]
    pub output: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ProfileGuideArgs {}

#[derive(Parser, Debug)]
pub struct ProfilePatchArgs {
    /// Path to a YAML overlay file containing yaml_merge directives.
    ///
    /// Plan 36-02 (D-20 manual-replay of upstream d44f5541 + 242d4917): accepts
    /// `yaml_merge:` directives matching upstream semantics (REQ-PORT-CLOSURE-04
    /// acceptance #2). Idempotent JSON-merge install records are deferred to
    /// v2.5-FU-3 (REQ-PORT-CLOSURE-04 acceptance #1, per D-36-C1).
    #[arg(long, value_name = "OVERLAY")]
    pub yaml: PathBuf,
    /// Profile directory to resolve target paths against (default: profile config dir)
    #[arg(long, value_name = "DIR")]
    pub profile_dir: Option<PathBuf>,
}

#[derive(Parser, Debug)]
pub struct ProfileListArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileShowArgs {
    /// Profile name or path
    pub profile: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show raw paths before expansion (e.g., $HOME instead of /Users/luke)
    #[arg(long)]
    pub raw: bool,
    /// Output format: 'profile' (default) or 'manifest' (capability manifest JSON)
    #[arg(long, value_enum, value_name = "FORMAT")]
    pub format: Option<ProfileShowFormat>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ProfileShowFormat {
    Profile,
    Manifest,
}

#[derive(Parser, Debug)]
pub struct ProfileDiffArgs {
    /// First profile name or path
    pub profile1: String,
    /// Second profile name or path
    pub profile2: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Fail closed on legacy profile fields (e.g. `override_deny`). Default
    /// mode warns to stderr but continues; `--strict` exits non-zero.
    #[arg(long)]
    pub strict: bool,
}

#[derive(Parser, Debug)]
pub struct ProfileGroupsArgs {
    /// Group name to show details for (omit to list all)
    pub name: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Show all platforms (not just current)
    #[arg(long)]
    pub all_platforms: bool,
}

#[derive(Parser, Debug, Clone, Default)]
pub struct SandboxArgs {
    // ── Filesystem ───────────────────────────────────────────────────────
    /// Allow read+write access to a directory (recursive)
    #[arg(
        long,
        short = 'a',
        value_name = "DIR",
        env = "NONO_ALLOW",
        value_delimiter = ',',
        help_heading = "FILESYSTEM"
    )]
    pub allow: Vec<PathBuf>,

    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub read: Vec<PathBuf>,

    /// Allow write-only access to a directory (recursive). Directory deletion NOT included
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub write: Vec<PathBuf>,

    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub allow_file: Vec<PathBuf>,

    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub read_file: Vec<PathBuf>,

    /// Allow write-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub write_file: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    ///
    /// Plan 34-04b (upstream f0abd413, v0.47.0, #594): canonical flag name
    /// is `--bypass-protection`. `--override-deny` continues to work via
    /// the clap `visible_alias` for v2.3 backwards-compat. Internal Rust
    /// identifier remains `override_deny` (210-callsite flag-day rename
    /// deferred to P34-DEFER-04b).
    #[arg(
        long = "override-deny",
        visible_alias = "bypass-protection",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub override_deny: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    #[arg(
        long = "block-net",
        alias = "net-block",
        conflicts_with = "allow_net",
        env = "NONO_BLOCK_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub block_net: bool,

    /// Deprecated compatibility flag. Network is unrestricted by default.
    #[arg(
        long = "allow-net",
        alias = "net-allow",
        env = "NONO_ALLOW_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        conflicts_with_all = [
            "block_net",
            "network_profile",
            "allow_proxy",
            "proxy_credential",
            "external_proxy",
            "external_proxy_bypass",
            "proxy_port"
        ],
        hide = true,
        help_heading = "NETWORK"
    )]
    pub allow_net: bool,

    /// Enable proxy filtering with a named network profile
    #[arg(
        long,
        value_name = "PROFILE",
        env = "NONO_NETWORK_PROFILE",
        help_heading = "NETWORK"
    )]
    pub network_profile: Option<String>,

    /// Add a domain to the proxy allowlist (repeatable)
    #[arg(
        long = "allow-domain",
        alias = "allow-proxy",
        alias = "proxy-allow",
        env = "NONO_ALLOW_DOMAIN",
        value_name = "DOMAIN",
        help_heading = "NETWORK"
    )]
    pub allow_proxy: Vec<String>,

    /// Allow the sandboxed child to listen on a TCP port (repeatable)
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    #[arg(
        long = "open-port",
        alias = "allow-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_port: Vec<u16>,

    /// Allow outbound TCP connect to a specific port (repeatable; Linux Landlock V4+ only)
    #[arg(
        long = "allow-connect-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_connect_port: Vec<u16>,

    /// Chain outbound traffic through an upstream proxy (host:port)
    #[arg(
        long = "upstream-proxy",
        alias = "external-proxy",
        value_name = "HOST:PORT",
        env = "NONO_UPSTREAM_PROXY",
        help_heading = "NETWORK"
    )]
    pub external_proxy: Option<String>,

    /// Route these domains direct instead of through the upstream proxy
    #[arg(
        long = "upstream-bypass",
        alias = "external-proxy-bypass",
        value_name = "DOMAIN",
        env = "NONO_UPSTREAM_BYPASS",
        value_delimiter = ',',
        help_heading = "NETWORK"
    )]
    pub external_proxy_bypass: Vec<String>,

    /// Fixed port for the credential proxy (default: OS-assigned)
    #[arg(long, value_name = "PORT", help_heading = "NETWORK")]
    pub proxy_port: Option<u16>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Inject credentials via reverse proxy for a service (repeatable)
    #[arg(
        long = "credential",
        alias = "proxy-credential",
        env = "NONO_CREDENTIAL",
        value_name = "SERVICE",
        help_heading = "CREDENTIALS"
    )]
    pub proxy_credential: Vec<String>,

    /// Restrict a credential service to specific HTTP method+path patterns (repeatable).
    /// Format: "SERVICE:METHOD:/path/pattern" (e.g., "github:GET:/repos/*/issues")
    /// Use "*" for any method: "github:*:/repos/*/issues"
    /// Patterns: "*" matches one path segment, "**" matches zero or more.
    #[arg(
        long = "allow-endpoint",
        value_name = "SERVICE:METHOD:PATH",
        help_heading = "CREDENTIALS"
    )]
    pub allow_endpoint: Vec<String>,

    /// Load credentials as env vars. For network API keys, prefer --credential
    #[arg(
        long,
        value_name = "CREDENTIALS",
        env = "NONO_ENV_CREDENTIAL",
        help_heading = "CREDENTIALS"
    )]
    pub env_credential: Option<String>,

    /// Map a credential reference to an environment variable (repeatable)
    #[arg(
        long,
        value_names = ["CREDENTIAL_REF", "ENV_VAR"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help_heading = "CREDENTIALS"
    )]
    pub env_credential_map: Vec<String>,

    // ── Environment filter (upstream v0.37.1 #688 / 1b412a7) ─────────────────────────────────
    /// Allow-list pattern for environment variables inherited by the
    /// sandboxed child. Accepts an exact name (`PATH`), a trailing-prefix
    /// glob (`AWS_*`), or a bare `*` to match all variables. Repeatable.
    /// Malformed patterns fail closed at parse time with a clap error,
    /// BEFORE the sandbox is launched. When any `--env-allow` is set, only
    /// matching variables (plus nono-injected credentials) reach the child.
    /// Upstream parity shim: full propagation to the child env boundary
    /// lives in profile-surface code owned by a sibling plan; the flag is
    /// accepted here with fail-closed validation so a future profile-wiring
    /// patch can consume it without re-plumbing the CLI surface.
    #[arg(
        long,
        value_name = "PATTERN",
        value_parser = parse_env_filter_pattern,
        action = clap::ArgAction::Append,
        help_heading = "ENVIRONMENT"
    )]
    pub env_allow: Vec<String>,

    /// Deny-list pattern for environment variables inherited by the
    /// sandboxed child. Accepts an exact name or a trailing-prefix glob
    /// (e.g. `AWS_*`). Repeatable. Malformed patterns fail closed at
    /// parse time. When both `--env-allow` and `--env-deny` match, deny
    /// takes precedence — this prevents an overly-broad allow from
    /// accidentally admitting something listed in deny.
    #[arg(
        long,
        value_name = "PATTERN",
        value_parser = parse_env_filter_pattern,
        action = clap::ArgAction::Append,
        help_heading = "ENVIRONMENT"
    )]
    pub env_deny: Vec<String>,

    // ── Commands ─────────────────────────────────────────────────────────
    /// Allow a normally-blocked dangerous command (use with caution)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Block an additional command beyond the default blocklist
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub block_command: Vec<String>,

    // ── General ──────────────────────────────────────────────────────────
    /// Use a profile by name or file path
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "OPTIONS"
    )]
    pub profile: Option<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Grant the sandboxed process access to GPU device nodes (Linux) or GPU
    /// framework paths (macOS). On Windows, accepted but not enforced — emits
    /// a warning (upstream v0.31–0.33 D-12 + v0.34 D-13).
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_gpu: bool,

    /// Internal: force WFP readiness for test-built Windows binaries.
    #[cfg(debug_assertions)]
    #[arg(long, hide = true, help_heading = "OPTIONS")]
    pub dangerous_force_wfp_ready: bool,

    /// Capability manifest file (JSON). A fully-resolved sandbox specification —
    /// mutually exclusive with all other sandbox configuration flags.
    #[arg(
        long,
        short = 'c',
        value_name = "FILE",
        conflicts_with_all = &[
            "allow", "read", "write", "allow_file", "read_file", "write_file",
            "profile", "override_deny", "allow_cwd",
            "block_net", "allow_net", "network_profile", "allow_proxy",
            "allow_bind", "allow_port", "allow_connect_port", "external_proxy", "proxy_port",
            "proxy_credential", "allow_endpoint", "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Show what would be sandboxed without executing
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,
}

impl SandboxArgs {
    /// Whether any CLI flag requires proxy mode activation.
    pub fn has_proxy_flags(&self) -> bool {
        self.network_profile.is_some()
            || !self.allow_proxy.is_empty()
            || !self.proxy_credential.is_empty()
            || self.external_proxy.is_some()
    }

    /// Emit a `tracing::warn!` for `--allow-gpu` when the flag is set but the
    /// current platform's sandbox backend cannot enforce GPU passthrough.
    ///
    /// Upstream parity D-12 (v0.31–0.33) ships the flag with a three-platform
    /// behavior split:
    ///
    /// - **Linux (Landlock):** allowlist NVIDIA/AMD/DRM device nodes +
    ///   NVIDIA procfs (D-13). Enforced.
    /// - **macOS (Seatbelt):** emit IOKit Metal/AGX GPU user-client rules.
    ///   Enforced.
    /// - **Windows (WFP + Job Object):** no kernel-level GPU sandboxing
    ///   primitive exists. The flag is accepted for CLI parity so scripts
    ///   are portable, but a warning is emitted so operators do not falsely
    ///   assume GPU passthrough is sandboxed. Mirrors the Phase 16
    ///   RESL-01..04 pattern (per-flag warning for unsupported flags) for
    ///   unsupported flags, but lives at the CLI layer — per D-21, the
    ///   Windows sandbox backend (`crates/nono/src/sandbox/windows.rs`) is
    ///   NOT touched by this port and receives no GPU-related capability
    ///   bit. The Windows sandbox state is byte-identical with and without
    ///   `--allow-gpu`.
    ///
    /// Callers should invoke this at most once per sandbox launch. The
    /// capability-wiring layer (`capability_ext::CapabilitySetExt::from_args`)
    /// calls this before deciding whether to set
    /// `CapabilitySet::allow_gpu()` — on Windows the warning fires and the
    /// capability is deliberately NOT added to the set, which is the
    /// enforcement-boundary proof that the Windows sandbox state does not
    /// change.
    pub fn warn_if_allow_gpu_unsupported_on_platform(&self) {
        if !self.allow_gpu {
            return;
        }
        #[cfg(target_os = "windows")]
        {
            tracing::warn!(
                "--allow-gpu is not enforced on Windows: GPU access on Windows is \
                 not supported by nono's sandbox backend (WFP + Job Object has no \
                 GPU-passthrough primitive). The flag is accepted for CLI parity \
                 with Linux/macOS; no capability is added to the Windows sandbox \
                 state. See REQUIREMENTS.md § UPST-04."
            );
        }
        #[cfg(not(target_os = "windows"))]
        {
            // No-op on Linux/macOS — the flag is enforced by the respective
            // sandbox backends (Landlock / Seatbelt).
        }
    }
}

#[derive(Parser, Debug, Clone, Default)]
pub struct WrapSandboxArgs {
    // ── Filesystem ───────────────────────────────────────────────────────
    /// Allow read+write access to a directory (recursive)
    #[arg(
        long,
        short = 'a',
        value_name = "DIR",
        env = "NONO_ALLOW",
        value_delimiter = ',',
        help_heading = "FILESYSTEM"
    )]
    pub allow: Vec<PathBuf>,

    /// Allow read-only access to a directory (recursive)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub read: Vec<PathBuf>,

    /// Allow write-only access to a directory (recursive). Directory deletion NOT included
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "FILESYSTEM")]
    pub write: Vec<PathBuf>,

    /// Allow read+write access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub allow_file: Vec<PathBuf>,

    /// Allow read-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub read_file: Vec<PathBuf>,

    /// Allow write-only access to a single file
    #[arg(long, value_name = "FILE", help_heading = "FILESYSTEM")]
    pub write_file: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    ///
    /// Plan 34-04b (upstream f0abd413, v0.47.0, #594): canonical flag name
    /// is `--bypass-protection`. `--override-deny` continues to work via
    /// the clap `visible_alias` for v2.3 backwards-compat. Internal Rust
    /// identifier remains `override_deny` (210-callsite flag-day rename
    /// deferred to P34-DEFER-04b).
    #[arg(
        long = "override-deny",
        visible_alias = "bypass-protection",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub override_deny: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    #[arg(
        long = "block-net",
        alias = "net-block",
        env = "NONO_BLOCK_NET",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub block_net: bool,

    /// Allow the sandboxed child to listen on a TCP port (repeatable)
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    #[arg(
        long = "open-port",
        alias = "allow-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_port: Vec<u16>,

    /// Allow outbound TCP connect to a specific port (repeatable; Linux Landlock V4+ only)
    #[arg(
        long = "allow-connect-port",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_connect_port: Vec<u16>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Load credentials as env vars
    #[arg(
        long,
        value_name = "CREDENTIALS",
        env = "NONO_ENV_CREDENTIAL",
        help_heading = "CREDENTIALS"
    )]
    pub env_credential: Option<String>,

    /// Map a credential reference to an environment variable (repeatable)
    #[arg(
        long,
        value_names = ["CREDENTIAL_REF", "ENV_VAR"],
        num_args = 2,
        action = clap::ArgAction::Append,
        help_heading = "CREDENTIALS"
    )]
    pub env_credential_map: Vec<String>,

    // ── Environment filter (upstream v0.37.1 #688 / 1b412a7) ─────────────────────────────────
    /// Allow-list pattern for environment variables inherited by the
    /// sandboxed child. Accepts an exact name (`PATH`), a trailing-prefix
    /// glob (`AWS_*`), or a bare `*` to match all variables. Repeatable.
    /// Malformed patterns fail closed at parse time with a clap error,
    /// BEFORE the sandbox is launched. When any `--env-allow` is set, only
    /// matching variables (plus nono-injected credentials) reach the child.
    /// Upstream parity shim: full propagation to the child env boundary
    /// lives in profile-surface code owned by a sibling plan; the flag is
    /// accepted here with fail-closed validation so a future profile-wiring
    /// patch can consume it without re-plumbing the CLI surface.
    #[arg(
        long,
        value_name = "PATTERN",
        value_parser = parse_env_filter_pattern,
        action = clap::ArgAction::Append,
        help_heading = "ENVIRONMENT"
    )]
    pub env_allow: Vec<String>,

    /// Deny-list pattern for environment variables inherited by the
    /// sandboxed child. Accepts an exact name or a trailing-prefix glob
    /// (e.g. `AWS_*`). Repeatable. Malformed patterns fail closed at
    /// parse time. When both `--env-allow` and `--env-deny` match, deny
    /// takes precedence — this prevents an overly-broad allow from
    /// accidentally admitting something listed in deny.
    #[arg(
        long,
        value_name = "PATTERN",
        value_parser = parse_env_filter_pattern,
        action = clap::ArgAction::Append,
        help_heading = "ENVIRONMENT"
    )]
    pub env_deny: Vec<String>,

    // ── Commands ─────────────────────────────────────────────────────────
    /// Allow a normally-blocked dangerous command (use with caution)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Block an additional command beyond the default blocklist
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub block_command: Vec<String>,

    // ── General ──────────────────────────────────────────────────────────
    /// Use a profile by name or file path
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "OPTIONS"
    )]
    pub profile: Option<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Grant the sandboxed process access to GPU device nodes (Linux) or GPU
    /// framework paths (macOS). On Windows, accepted but not enforced — emits
    /// a warning (upstream v0.31–0.33 D-12 + v0.34 D-13).
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_gpu: bool,

    /// Capability manifest file (JSON). A fully-resolved sandbox specification —
    /// mutually exclusive with all other sandbox configuration flags.
    #[arg(
        long,
        short = 'c',
        value_name = "FILE",
        conflicts_with_all = &[
            "allow", "read", "write", "allow_file", "read_file", "write_file",
            "profile", "override_deny", "allow_cwd",
            "block_net", "allow_bind", "allow_port", "allow_connect_port",
            "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Show what would be sandboxed without executing
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,
}

impl From<WrapSandboxArgs> for SandboxArgs {
    fn from(args: WrapSandboxArgs) -> Self {
        Self {
            allow: args.allow,
            read: args.read,
            write: args.write,
            allow_file: args.allow_file,
            read_file: args.read_file,
            write_file: args.write_file,
            override_deny: args.override_deny,
            allow_cwd: args.allow_cwd,
            workdir: args.workdir,
            block_net: args.block_net,
            allow_net: false,
            network_profile: None,
            allow_proxy: Vec::new(),
            allow_bind: args.allow_bind,
            allow_port: args.allow_port,
            allow_connect_port: args.allow_connect_port,
            external_proxy: None,
            external_proxy_bypass: Vec::new(),
            proxy_port: None,
            proxy_credential: Vec::new(),
            allow_endpoint: Vec::new(),
            env_credential: args.env_credential,
            env_credential_map: args.env_credential_map,
            allow_command: args.allow_command,
            block_command: args.block_command,
            env_allow: args.env_allow,
            env_deny: args.env_deny,
            profile: args.profile,
            allow_launch_services: args.allow_launch_services,
            allow_gpu: args.allow_gpu,
            config: args.config,
            verbose: args.verbose,
            #[cfg(debug_assertions)]
            dangerous_force_wfp_ready: false,
            dry_run: args.dry_run,
        }
    }
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RunArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Start the session without attaching the current terminal.
    /// The supervisor keeps the sandboxed process running in the background;
    /// use `nono attach <session>` later to inspect or interact with it.
    #[arg(long, help_heading = "OPTIONS")]
    pub detached: bool,

    // ── Rollback ──────────────────────────────────────────────────────
    /// Enable atomic rollback snapshots for the session
    #[arg(long, conflicts_with = "no_rollback", help_heading = "ROLLBACK")]
    pub rollback: bool,

    /// Skip the post-exit rollback review prompt
    #[arg(long, help_heading = "ROLLBACK")]
    pub no_rollback_prompt: bool,

    /// Disable rollback entirely (no snapshots taken)
    #[arg(long, conflicts_with = "rollback", help_heading = "ROLLBACK")]
    pub no_rollback: bool,

    /// Exclude from snapshots. Globs match filenames; plain names match path components
    #[arg(long, value_name = "PATTERN", help_heading = "ROLLBACK")]
    pub rollback_exclude: Vec<String>,

    /// Force-include an auto-excluded directory (name only, not full path)
    #[arg(long, value_name = "DIR_NAME", help_heading = "ROLLBACK")]
    pub rollback_include: Vec<String>,

    /// Include all directories in snapshots. VCS dirs (.git) always excluded
    #[arg(long, conflicts_with = "rollback_include", help_heading = "ROLLBACK")]
    pub rollback_all: bool,

    /// Skip large directory trees during trust scanning and rollback preflight.
    /// Matched as an exact path component name. Repeatable.
    #[arg(long, value_name = "DIR_NAME", help_heading = "OPTIONS")]
    pub skip_dir: Vec<String>,

    /// Override the rollback snapshot destination directory.
    /// By default, snapshots are stored in the platform's nono rollback directory.
    /// The destination must be within a path already granted write access
    /// by --allow (or profile); nono will fail with a clear error if not.
    /// Useful for Docker volume mounts or shared storage paths.
    #[arg(
        long,
        value_name = "PATH",
        requires = "rollback",
        help_heading = "ROLLBACK"
    )]
    pub rollback_dest: Option<std::path::PathBuf>,

    // ── Options ────────────────────────────────────────────────────────
    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Disable the audit trail for this session
    #[arg(
        long,
        conflicts_with_all = ["audit_integrity", "no_audit_integrity", "rollback"],
        help_heading = "OPTIONS"
    )]
    pub no_audit: bool,

    /// Disable the default Merkleized append-only audit log.
    ///
    /// CL-01-M (Phase 22 review): `--rollback` was previously listed as a
    /// conflict, but rollback (filesystem snapshot) and audit-integrity
    /// (Merkleized append-only ledger) are orthogonal concerns. POLY-02
    /// only requires `--rollback` to conflict with `--no-audit` (the entire
    /// audit trail), not with `--no-audit-integrity` (just the cryptographic
    /// ledger). Pairing `--rollback --no-audit-integrity` is now allowed:
    /// users get rollback without the audit-integrity overhead.
    #[arg(long, conflicts_with_all = ["audit_integrity"], help_heading = "OPTIONS")]
    pub no_audit_integrity: bool,

    /// Add filesystem-state hashing over in-scope writable paths
    #[arg(long, help_heading = "OPTIONS")]
    pub audit_integrity: bool,

    /// Sign the audit-integrity Merkle root with a configured trust key.
    ///
    /// Plan 22-05a Task 7 (upstream `6ecade2e`): when set, after the audit
    /// recorder finalizes, the supervisor signs the (`chain_head`,
    /// `merkle_root`, `session_id`) tuple via fork's existing
    /// `nono::trust::signing::sign_files` and writes the resulting Sigstore
    /// bundle to `audit-attestation.bundle` in the session directory.
    ///
    /// Key resolution flows through `nono::keystore::load_secret_by_ref`,
    /// so the value can be a `keystore://<credential>` URI. If the
    /// referenced key is missing the CLI fails fail-closed (default
    /// provisioning model: user pre-provisions key).
    #[arg(
        long,
        value_name = "KEY_REF",
        help_heading = "OPTIONS",
        requires = "audit_integrity"
    )]
    pub audit_sign_key: Option<String>,

    /// Disable trust verification (not recommended for production)
    #[arg(long, help_heading = "OPTIONS")]
    pub trust_override: bool,

    /// Name for this session (shown in `nono ps`)
    #[arg(long, value_name = "NAME", help_heading = "OPTIONS")]
    pub name: Option<String>,

    /// Enable runtime capability elevation (seccomp-notify + approval prompts).
    /// Overrides the profile's capability_elevation setting.
    /// When enabled, the supervisor can grant access to paths not in the
    /// initial capability set via interactive prompts.
    #[arg(long, env = "NONO_CAPABILITY_ELEVATION", help_heading = "OPTIONS")]
    pub capability_elevation: bool,

    // ── Resource Limits ──────────────────────────────────────────────
    /// Cap the sandboxed agent tree's CPU to this percentage of one logical core.
    /// Kernel-enforced on Windows via `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE` with hard-cap.
    /// On Linux: enforced via cgroup v2 `cpu.max` (requires systemd delegation).
    /// On macOS: rejected at parse time — no per-process CPU-quota equivalent exists.
    /// See REQUIREMENTS.md § REQ-RESL-NIX-03 for the macOS constraint.
    #[arg(
        long,
        value_name = "PERCENT",
        value_parser = parse_cpu_percent,
        help_heading = "RESOURCE LIMITS"
    )]
    pub cpu_percent: Option<u16>,

    /// Cap the sandboxed agent tree's total memory. Accepts `512M`, `1G`, `256K`,
    /// or raw bytes. Kernel-enforced job-wide on Windows via `JobMemoryLimit`.
    /// On Linux/macOS: accepted with a warning pending cross-platform follow-up.
    /// See REQUIREMENTS.md § RESL-02.
    #[arg(
        long,
        value_name = "SIZE",
        value_parser = parse_byte_size,
        help_heading = "RESOURCE LIMITS"
    )]
    pub memory: Option<u64>,

    /// Kill the sandboxed agent tree after this wall-clock duration.
    /// Accepts `30s`, `5m`, `1h`, `1d`, or raw seconds. Enforced by supervisor-side
    /// timer + `TerminateJobObject` on Windows (see REQUIREMENTS.md § RESL-03).
    /// On Linux/macOS: accepted with a warning pending cross-platform follow-up.
    #[arg(
        long,
        value_name = "DURATION",
        value_parser = parse_duration,
        help_heading = "RESOURCE LIMITS"
    )]
    pub timeout: Option<std::time::Duration>,

    /// Cap the number of active processes in the sandboxed agent tree.
    /// Kernel-enforced on Windows via `ActiveProcessLimit`. Range: 1..=65535.
    /// On Linux/macOS: accepted with a warning pending cross-platform follow-up.
    /// See REQUIREMENTS.md § RESL-04.
    #[arg(
        long,
        value_name = "N",
        value_parser = clap::value_parser!(u32).range(1..=65535),
        help_heading = "RESOURCE LIMITS"
    )]
    pub max_processes: Option<u32>,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ShellArgs {
    #[command(flatten)]
    pub sandbox: SandboxArgs,

    /// Shell to execute (defaults to $SHELL or /bin/sh)
    #[arg(long, value_name = "SHELL", help_heading = "OPTIONS")]
    pub shell: Option<PathBuf>,

    /// Name for this session (shown in `nono ps`)
    #[arg(long, value_name = "NAME", help_heading = "OPTIONS")]
    pub name: Option<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct WrapArgs {
    #[command(flatten)]
    pub sandbox: WrapSandboxArgs,

    /// Suppress diagnostic footer on command failure
    #[arg(long, help_heading = "OPTIONS")]
    pub no_diagnostics: bool,

    /// Command to run inside the sandbox
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SetupArgs {
    /// Only verify installation and sandbox support, don't create files
    #[arg(long, help_heading = "OPTIONS")]
    pub check_only: bool,

    /// Register the Windows WFP service (Windows only)
    #[arg(long, help_heading = "OPTIONS")]
    pub register_wfp_service: bool,

    /// Register the Windows WFP service placeholder (Windows only)
    #[arg(long, help_heading = "OPTIONS")]
    pub install_wfp_service: bool,

    /// Register the Windows WFP placeholder driver service
    #[arg(long, help_heading = "OPTIONS")]
    pub install_wfp_driver: bool,

    /// Attempt to start the registered Windows WFP service placeholder
    #[arg(long, help_heading = "OPTIONS")]
    pub start_wfp_service: bool,

    /// Attempt to start the registered Windows WFP placeholder driver
    #[arg(long, help_heading = "OPTIONS")]
    pub start_wfp_driver: bool,

    /// Refresh the cached Sigstore trusted root from https://tuf-repo-cdn.sigstore.dev (per-user, no admin required)
    #[arg(long, help_heading = "OPTIONS")]
    pub refresh_trust_root: bool,

    /// Generate example user profiles in ~/.config/nono/profiles/
    #[arg(long, help_heading = "OPTIONS")]
    pub profiles: bool,

    /// Show shell integration instructions
    #[arg(long, help_heading = "OPTIONS")]
    pub shell_integration: bool,

    /// Show detailed information during setup
    #[arg(short, long, action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct WhyArgs {
    /// Path to check
    #[arg(long, help_heading = "QUERY")]
    pub path: Option<PathBuf>,

    /// Operation to check: read, write, or readwrite
    #[arg(long, value_enum, help_heading = "QUERY")]
    pub op: Option<WhyOp>,

    /// Network host to check
    #[arg(long, help_heading = "QUERY")]
    pub host: Option<String>,

    /// Network port (default 443)
    #[arg(long, default_value = "443", help_heading = "QUERY")]
    pub port: u16,

    /// Output JSON instead of human-readable format
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Query current sandbox state (use inside a sandboxed process)
    #[arg(long = "self", help_heading = "OPTIONS")]
    pub self_query: bool,

    // ── Capability context ─────────────────────────────────────────────
    /// Directories to allow read+write access (for query context)
    #[arg(long, short = 'a', value_name = "DIR", help_heading = "CONTEXT")]
    pub allow: Vec<PathBuf>,

    /// Directories to allow read-only access (for query context)
    #[arg(long, short = 'r', value_name = "DIR", help_heading = "CONTEXT")]
    pub read: Vec<PathBuf>,

    /// Directories to allow write-only access (for query context)
    #[arg(long, short = 'w', value_name = "DIR", help_heading = "CONTEXT")]
    pub write: Vec<PathBuf>,

    /// Single files to allow read+write access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub allow_file: Vec<PathBuf>,

    /// Single files to allow read-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub read_file: Vec<PathBuf>,

    /// Single files to allow write-only access (for query context)
    #[arg(long, value_name = "FILE", help_heading = "CONTEXT")]
    pub write_file: Vec<PathBuf>,

    /// Block network access (for query context)
    #[arg(long = "block-net", alias = "net-block", help_heading = "CONTEXT")]
    pub block_net: bool,

    /// Use a named profile for query context
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "CONTEXT")]
    pub profile: Option<String>,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "CONTEXT")]
    pub workdir: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct LearnArgs {
    /// Use a named profile to compare against (shows only missing paths)
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "OPTIONS")]
    pub profile: Option<String>,

    /// Output discovered paths as JSON fragment for profile
    #[arg(long, help_heading = "OPTIONS")]
    pub json: bool,

    /// Timeout in seconds (default: run until command exits)
    #[arg(long, value_name = "SECS", help_heading = "OPTIONS")]
    pub timeout: Option<u64>,

    /// Show all accessed paths, not just those that would be blocked
    #[arg(long, help_heading = "OPTIONS")]
    pub all: bool,

    /// Skip reverse DNS lookups for discovered IPs
    #[arg(long, help_heading = "OPTIONS")]
    pub no_rdns: bool,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Command to trace
    #[arg(required = true, hide = true)]
    pub command: Vec<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

impl LearnArgs {
    /// Construct a minimal `LearnArgs` for unit tests on Windows.
    #[cfg(all(test, target_os = "windows"))]
    pub(crate) fn default_for_test() -> Self {
        Self {
            profile: None,
            json: false,
            timeout: None,
            all: false,
            no_rdns: false,
            verbose: 0,
            command: vec!["echo".to_string(), "test".to_string()],
            help: None,
        }
    }
}

/// Operation type for why command
#[derive(Clone, Debug, ValueEnum)]
pub enum WhyOp {
    /// Read-only access
    Read,
    /// Write-only access
    Write,
    /// Read and write access
    #[value(name = "readwrite")]
    ReadWrite,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackArgs {
    #[command(subcommand)]
    pub command: RollbackCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum RollbackCommands {
    /// List sessions with file changes
    List(RollbackListArgs),
    /// Show changes in a session
    Show(RollbackShowArgs),
    /// Restore files from a past session
    Restore(RollbackRestoreArgs),
    /// Verify session integrity
    Verify(RollbackVerifyArgs),
    /// Clean up old sessions
    Cleanup(RollbackCleanupArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackListArgs {
    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Filter sessions by tracked path (matches if session tracked this path or a parent/child)
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Show all sessions (including those with no file changes)
    #[arg(long)]
    pub all: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Show unified diff (git diff style)
    #[arg(long)]
    pub diff: bool,

    /// Show side-by-side diff
    #[arg(long)]
    pub side_by_side: bool,

    /// Show full file content from snapshot
    #[arg(long)]
    pub full: bool,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackRestoreArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Snapshot number to restore to (default: last snapshot)
    #[arg(long)]
    pub snapshot: Option<u32>,

    /// Show what would change without modifying files
    #[arg(long)]
    pub dry_run: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackVerifyArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct RollbackCleanupArgs {
    /// Retain N newest sessions (default: from config, usually 10)
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all sessions (requires confirmation)
    #[arg(long)]
    pub all: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

// ---------------------------------------------------------------------------
// Audit command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditArgs {
    #[command(subcommand)]
    pub command: AuditCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum AuditCommands {
    /// List all sandboxed sessions
    List(AuditListArgs),
    /// Show audit details for a session
    Show(AuditShowArgs),
    /// Verify the cryptographic integrity of an audit session
    ///
    /// Plan 22-05a Task 6 (upstream `0b1822a9`): re-reads
    /// `audit-events.ndjson`, recomputes the per-event leaf hash, the
    /// hash-chain head, and the Merkle root under the Alpha schema, then
    /// fail-closes if any commitment in `SessionMetadata.audit_integrity`
    /// does not match. AUD-02 acceptance criterion #2.
    Verify(AuditVerifyArgs),
    /// Remove old audit sessions
    ///
    /// Plan 22-05b Task 2 (upstream `4f9552ec`): peer to the new
    /// `nono session cleanup` runtime cleanup; operates on audit
    /// ledger sessions. AUD-04 acceptance #2.
    Cleanup(AuditCleanupArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditListArgs {
    /// Show only sessions from today
    #[arg(long)]
    pub today: bool,

    /// Show sessions since date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub since: Option<String>,

    /// Show sessions until date (YYYY-MM-DD)
    #[arg(long, value_name = "DATE")]
    pub until: Option<String>,

    /// Filter by command name (e.g., claude, cat)
    #[arg(long, value_name = "CMD")]
    pub command: Option<String>,

    /// Filter by tracked path
    #[arg(long, value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Show only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub recent: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditShowArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for `nono audit verify <session-id>` (Plan 22-05a Task 6,
/// upstream `0b1822a9`; Task 7 attestation pin per upstream `6ecade2e`).
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditVerifyArgs {
    /// Session ID to verify (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Optional PEM-encoded public key file used to pin attestation
    /// verification to a specific signer (Plan 22-05a Task 7, upstream
    /// `6ecade2e`). When omitted, the embedded public key from the
    /// `audit-attestation.bundle` itself is used (self-verification).
    #[arg(long, value_name = "PATH")]
    pub public_key_file: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for `nono audit cleanup` (Plan 22-05b Task 2, upstream
/// `4f9552ec`). Peer to the new `nono session cleanup` runtime cleanup;
/// operates on audit ledger sessions. AUD-04 acceptance #2.
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditCleanupArgs {
    /// Retain N newest audit sessions
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove all audit sessions (skips active sessions)
    #[arg(long)]
    pub all: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for `nono session` (Plan 22-05b Task 2, upstream `4f9552ec`).
/// Hosts `nono session cleanup` as the renamed entry point for the prune
/// semantics. The inner `SessionCommands::Cleanup` reuses the existing
/// fork `PruneArgs` so the CLEAN-04 `parse_prune_duration` enforcement
/// (no raw integers without a suffix) is preserved trivially.
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SessionArgs {
    #[command(subcommand)]
    pub command: SessionCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum SessionCommands {
    /// Remove old runtime sessions
    ///
    /// Reuses the existing fork `PruneArgs` shape so the v2.1 CLEAN-04
    /// `parse_prune_duration` enforcement (rejects `--older-than 30`
    /// without a suffix) is preserved verbatim. Routes to the unchanged
    /// `session_commands::run_prune` worker; `auto_prune_if_needed` and
    /// `AUTO_PRUNE_STALE_THRESHOLD = 100` stay byte-identical per
    /// Decision 2 LOCKED reframe.
    Cleanup(PruneArgs),
}

#[derive(Parser, Debug)]
pub struct PsArgs {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Include exited sessions
    #[arg(long)]
    pub all: bool,
}

#[derive(Parser, Debug)]
pub struct StopArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Force stop (SIGKILL instead of SIGTERM)
    #[arg(long)]
    pub force: bool,

    /// Grace period in seconds before SIGKILL (default: 10)
    #[arg(long, default_value = "10")]
    pub timeout: u64,
}

#[derive(Parser, Debug)]
pub struct DetachArgs {
    /// Session ID, prefix, or name
    pub session: String,
}

#[derive(Parser, Debug)]
pub struct AttachArgs {
    /// Session ID, prefix, or name
    pub session: String,
}

#[derive(Parser, Debug)]
pub struct LogsArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Follow events in real-time
    #[arg(long, short = 'f')]
    pub follow: bool,

    /// Show last N events
    #[arg(long, value_name = "N")]
    pub tail: Option<usize>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Parser, Debug)]
pub struct InspectArgs {
    /// Session ID (or prefix)
    pub session: String,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Include event log
    #[arg(long)]
    pub events: bool,

    /// Include file changes
    #[arg(long)]
    pub changes: bool,
}

/// Parse a duration for prune's `--older-than`, REQUIRING a suffix.
///
/// Unlike `parse_duration` directly, this rejects raw integers because
/// `--older-than 30` used to mean "30 days" (pre-CLEAN-04) but would
/// suddenly mean "30 seconds" under parse_duration's rules. We refuse
/// ambiguous input instead of silently changing behavior.
pub(crate) fn parse_prune_duration(s: &str) -> std::result::Result<std::time::Duration, String> {
    let trimmed = s.trim();
    // A suffix is any trailing non-digit char. parse_duration accepts both
    // raw ("30") and suffixed ("30d") forms; we gate on the former.
    if !trimmed.is_empty() && trimmed.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!(
            "ambiguous duration '{trimmed}' — please specify a suffix: \
             {trimmed}s (seconds), {trimmed}m (minutes), {trimmed}h (hours), {trimmed}d (days)"
        ));
    }
    parse_duration(trimmed)
}

#[derive(Parser, Debug)]
pub struct PruneArgs {
    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove exited sessions older than this duration.
    /// Accepts 30s, 5m, 1h, 30d (no raw integers — specify a suffix).
    /// Default when unset: 30 days.
    #[arg(long, value_name = "DURATION", value_parser = parse_prune_duration)]
    pub older_than: Option<std::time::Duration>,

    /// Ignore age and prune every exited session (escape hatch).
    /// Mutually exclusive with --older-than.
    #[arg(long, conflicts_with = "older_than")]
    pub all_exited: bool,

    /// Keep only the N most recent sessions
    #[arg(long, value_name = "N")]
    pub keep: Option<usize>,
}

// ---------------------------------------------------------------------------
// Trust command args
// ---------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustArgs {
    #[command(subcommand)]
    pub command: TrustCommands,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Subcommand, Debug)]
pub enum TrustCommands {
    /// Create a trust-policy.json in the current directory
    Init(TrustInitArgs),
    /// Sign a file, producing a .bundle alongside it
    Sign(TrustSignArgs),
    /// Sign a trust policy file, producing a .bundle alongside it
    SignPolicy(TrustSignPolicyArgs),
    /// Verify a file's bundle against the trust policy
    Verify(TrustVerifyArgs),
    /// List files and their verification status
    List(TrustListArgs),
    /// Generate a new ECDSA P-256 signing key pair
    Keygen(TrustKeygenArgs),
    /// Export the public key for a signing key (base64 DER)
    ExportKey(TrustExportKeyArgs),
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustSignArgs {
    /// Instruction file(s) to sign
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Sign all files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with_all = ["keyless", "keyref"])]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with_all = ["key", "keyless"])]
    pub keyref: Option<String>,

    /// Use Sigstore keyless signing (Fulcio + Rekor via ambient OIDC)
    #[arg(long, conflicts_with = "keyref")]
    pub keyless: bool,

    /// Produce a single .nono-trust.bundle containing all subjects instead of per-file bundles
    #[arg(long)]
    pub multi_subject: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustSignPolicyArgs {
    /// Trust policy file to sign (default: trust-policy.json in CWD)
    #[arg(conflicts_with = "user")]
    pub file: Option<PathBuf>,

    /// Key ID to use from the system keystore (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with = "keyref")]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "key")]
    pub keyref: Option<String>,

    /// Sign the user-level trust policy at ~/.config/nono/trust-policy.json
    #[arg(long)]
    pub user: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustVerifyArgs {
    /// Instruction file(s) to verify
    #[arg(required_unless_present = "all")]
    pub files: Vec<PathBuf>,

    /// Verify all files matching trust policy patterns in CWD
    #[arg(long)]
    pub all: bool,

    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// OIDC issuer URL (REQUIRED for keyless verify; exact match against signer's iss claim).
    /// Example: https://token.actions.githubusercontent.com
    #[arg(long, value_name = "URL")]
    pub issuer: Option<String>,

    /// OIDC identity regex (REQUIRED for keyless verify; matched via `regress` against the
    /// bundle's Fulcio Build Config URI). Example:
    /// '^https://github\\.com/org/repo/\\.github/workflows/release\\.yml@refs/tags/v.*$'
    #[arg(long, value_name = "REGEX")]
    pub identity: Option<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustInitArgs {
    /// Glob patterns for files to include in the trust policy (e.g., "*.md", "*.py", "SKILLS.md")
    #[arg(long, value_name = "PATTERN", num_args = 1..)]
    pub include: Vec<String>,

    /// Key ID to include as a publisher (default: "default")
    #[arg(long, value_name = "KEY_ID", conflicts_with = "keyref")]
    pub key: Option<String>,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "key")]
    pub keyref: Option<String>,

    /// Create a user-level policy at ~/.config/nono/ instead of the current directory
    #[arg(long)]
    pub user: bool,

    /// Overwrite existing trust-policy.json
    #[arg(long)]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustListArgs {
    /// Trust policy file (default: auto-discover)
    #[arg(long, value_name = "FILE")]
    pub policy: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustKeygenArgs {
    /// Key identifier (stored in system keystore under this name)
    #[arg(
        long,
        value_name = "NAME",
        default_value = "default",
        conflicts_with = "keyref"
    )]
    pub id: String,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "id")]
    pub keyref: Option<String>,

    /// Overwrite existing key with the same ID
    #[arg(long)]
    pub force: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct TrustExportKeyArgs {
    /// Key identifier to export (default: "default")
    #[arg(
        long,
        value_name = "NAME",
        default_value = "default",
        conflicts_with = "keyref"
    )]
    pub id: String,

    /// Key reference URI (keystore://name or file:///path/to/key.pem)
    #[arg(long, value_name = "URI", conflicts_with = "id")]
    pub keyref: Option<String>,

    /// Output as PEM instead of base64 DER
    #[arg(long)]
    pub pem: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[cfg(test)]
mod parser_tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn parse_byte_size_accepts_kmgt_suffixes() {
        assert_eq!(parse_byte_size("256K"), Ok(256 * 1024));
        assert_eq!(parse_byte_size("512M"), Ok(512 * 1024 * 1024));
        assert_eq!(parse_byte_size("1G"), Ok(1u64 << 30));
        assert_eq!(parse_byte_size("2T"), Ok(2u64 * 1024u64.pow(4)));
        assert_eq!(parse_byte_size("1g"), Ok(1u64 << 30));
    }

    #[test]
    fn parse_byte_size_accepts_raw_bytes() {
        assert_eq!(parse_byte_size("268435456"), Ok(268_435_456));
    }

    #[test]
    fn parse_byte_size_rejects_invalid() {
        assert!(parse_byte_size("0").is_err());
        assert!(parse_byte_size("-1").is_err());
        assert!(parse_byte_size("").is_err());
        assert!(parse_byte_size("foo").is_err());
        assert!(parse_byte_size("1X").is_err());
    }

    #[test]
    fn parse_byte_size_rejects_overflow() {
        let huge = format!("{}T", u64::MAX);
        assert!(parse_byte_size(&huge).is_err());
    }

    #[test]
    fn parse_duration_accepts_suffixes() {
        assert_eq!(parse_duration("30s"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_duration("5m"), Ok(Duration::from_secs(300)));
        assert_eq!(parse_duration("1h"), Ok(Duration::from_secs(3600)));
        assert_eq!(parse_duration("1d"), Ok(Duration::from_secs(86_400)));
    }

    #[test]
    fn parse_duration_accepts_raw_seconds() {
        assert_eq!(parse_duration("300"), Ok(Duration::from_secs(300)));
    }

    #[test]
    fn parse_duration_rejects_invalid() {
        assert!(parse_duration("0").is_err());
        assert!(parse_duration("-1").is_err());
        assert!(parse_duration("").is_err());
        assert!(parse_duration("5x").is_err());
    }

    #[test]
    fn cpu_percent_range_enforced_by_clap() {
        let err_zero =
            Cli::try_parse_from(["nono", "run", "--cpu-percent", "0", "--allow", ".", "echo"]);
        assert!(err_zero.is_err());
        let err_over = Cli::try_parse_from([
            "nono",
            "run",
            "--cpu-percent",
            "101",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(err_over.is_err());
        let ok =
            Cli::try_parse_from(["nono", "run", "--cpu-percent", "25", "--allow", ".", "echo"]);
        assert!(ok.is_ok());
    }

    #[test]
    fn max_processes_range_enforced_by_clap() {
        let err_zero = Cli::try_parse_from([
            "nono",
            "run",
            "--max-processes",
            "0",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(err_zero.is_err());
        let err_over = Cli::try_parse_from([
            "nono",
            "run",
            "--max-processes",
            "65536",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(err_over.is_err());
        let ok = Cli::try_parse_from([
            "nono",
            "run",
            "--max-processes",
            "10",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(ok.is_ok());
    }

    #[test]
    fn memory_zero_rejected_by_parser() {
        let err = Cli::try_parse_from(["nono", "run", "--memory", "0", "--allow", ".", "echo"]);
        assert!(err.is_err());
    }

    // ==================================================================
    // Environment-variable filter flags (upstream v0.37.1 #688 / 1b412a7)
    // D-09 scoped port — CLI surface + parse-time validator only.
    // ==================================================================

    #[test]
    fn parse_env_filter_pattern_accepts_exact_names() {
        assert_eq!(parse_env_filter_pattern("PATH"), Ok("PATH".to_string()));
        assert_eq!(parse_env_filter_pattern("HOME"), Ok("HOME".to_string()));
        assert_eq!(
            parse_env_filter_pattern("MY_CUSTOM_VAR"),
            Ok("MY_CUSTOM_VAR".to_string())
        );
    }

    #[test]
    fn parse_env_filter_pattern_accepts_prefix_glob() {
        assert_eq!(parse_env_filter_pattern("AWS_*"), Ok("AWS_*".to_string()));
        assert_eq!(parse_env_filter_pattern("LANG_*"), Ok("LANG_*".to_string()));
    }

    #[test]
    fn parse_env_filter_pattern_accepts_bare_wildcard() {
        assert_eq!(parse_env_filter_pattern("*"), Ok("*".to_string()));
    }

    #[test]
    fn parse_env_filter_pattern_rejects_empty() {
        assert!(parse_env_filter_pattern("").is_err());
        assert!(parse_env_filter_pattern("   ").is_err());
    }

    #[test]
    fn parse_env_filter_pattern_rejects_middle_wildcard() {
        let err = parse_env_filter_pattern("INVALID*PATTERN")
            .expect_err("middle wildcard should fail closed");
        assert!(err.contains("trailing suffix"), "got: {err}");
    }

    #[test]
    fn parse_env_filter_pattern_rejects_leading_wildcard() {
        let err =
            parse_env_filter_pattern("*SUFFIX").expect_err("leading wildcard should fail closed");
        assert!(
            err.contains("bare '*'") || err.contains("trailing suffix"),
            "got: {err}"
        );
    }

    #[test]
    fn env_allow_accepts_exact_and_glob_via_clap() {
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--env-allow",
            "PATH",
            "--env-allow",
            "AWS_*",
            "--env-allow",
            "*",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(cli.is_ok(), "valid allow patterns should parse: {cli:?}");
        if let Ok(Cli {
            command: Commands::Run(args),
            ..
        }) = cli
        {
            assert_eq!(args.sandbox.env_allow, vec!["PATH", "AWS_*", "*"]);
        } else {
            panic!("expected Run command");
        }
    }

    #[test]
    fn env_deny_accepts_exact_and_glob_via_clap() {
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--env-deny",
            "SECRET_KEY",
            "--env-deny",
            "AWS_SECRET_*",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(cli.is_ok(), "valid deny patterns should parse");
        if let Ok(Cli {
            command: Commands::Run(args),
            ..
        }) = cli
        {
            assert_eq!(args.sandbox.env_deny, vec!["SECRET_KEY", "AWS_SECRET_*"]);
        }
    }

    #[test]
    fn env_allow_malformed_pattern_fails_closed_at_parse() {
        // Plan-required: malformed pattern fails closed BEFORE sandbox launch.
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--env-allow",
            "MIDDLE*STAR",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(cli.is_err(), "malformed --env-allow must reject at parse");
        let err = cli
            .expect_err("malformed --env-allow must reject at parse")
            .to_string();
        assert!(
            err.contains("trailing suffix") || err.contains("invalid"),
            "got: {err}"
        );
    }

    #[test]
    fn env_deny_malformed_pattern_fails_closed_at_parse() {
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--env-deny",
            "*LEADING_STAR",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(cli.is_err(), "malformed --env-deny must reject at parse");
    }

    #[test]
    fn env_filter_flags_do_not_collide_with_phase16_flags() {
        // Regression guard: Phase 16's --cpu-percent / --memory / --timeout /
        // --max-processes remain parseable alongside the new env filter flags.
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--env-allow",
            "PATH",
            "--env-deny",
            "SECRET",
            "--cpu-percent",
            "25",
            "--memory",
            "512M",
            "--timeout",
            "30s",
            "--max-processes",
            "10",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(
            cli.is_ok(),
            "env-filter + Phase 16 flags must coexist: {cli:?}"
        );
    }

    #[test]
    fn env_filter_flags_available_on_shell_and_wrap() {
        let shell_cli =
            Cli::try_parse_from(["nono", "shell", "--env-allow", "PATH", "--allow", "."]);
        assert!(
            shell_cli.is_ok(),
            "shell env-allow should parse: {shell_cli:?}"
        );

        let wrap_cli = Cli::try_parse_from([
            "nono",
            "wrap",
            "--env-deny",
            "SECRET_*",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(wrap_cli.is_ok(), "wrap env-deny should parse: {wrap_cli:?}");
    }

    #[test]
    fn env_allow_default_is_empty_vec() {
        let cli = Cli::try_parse_from(["nono", "run", "--allow", ".", "echo"])
            .expect("baseline `nono run --allow . echo` must parse");
        if let Commands::Run(args) = &cli.command {
            assert!(args.sandbox.env_allow.is_empty());
            assert!(args.sandbox.env_deny.is_empty());
        }
    }

    // --allow-gpu CLI surface (D-12 upstream parity port).

    #[test]
    fn allow_gpu_default_is_false() {
        // T-20-04-01 mitigation: flag must default to off.
        let cli = Cli::try_parse_from(["nono", "run", "--allow", ".", "echo"])
            .expect("baseline nono run should parse");
        if let Commands::Run(args) = &cli.command {
            assert!(!args.sandbox.allow_gpu);
        } else {
            panic!("expected Run subcommand");
        }
    }

    #[test]
    fn allow_gpu_parses_on_run() {
        let cli = Cli::try_parse_from(["nono", "run", "--allow-gpu", "--allow", ".", "echo"])
            .expect("nono run --allow-gpu should parse");
        if let Commands::Run(args) = &cli.command {
            assert!(args.sandbox.allow_gpu);
        } else {
            panic!("expected Run subcommand");
        }
    }

    #[test]
    fn allow_gpu_parses_on_wrap() {
        let cli = Cli::try_parse_from(["nono", "wrap", "--allow-gpu", "--allow", ".", "echo"])
            .expect("wrap --allow-gpu should parse");
        if let Commands::Wrap(args) = &cli.command {
            assert!(args.sandbox.allow_gpu);
        } else {
            panic!("expected Wrap subcommand");
        }
    }

    #[test]
    fn allow_gpu_parses_on_shell() {
        let cli = Cli::try_parse_from(["nono", "shell", "--allow-gpu", "--allow", "."])
            .expect("shell --allow-gpu should parse");
        // Shell uses the same SandboxArgs surface — presence alone is enough.
        assert!(matches!(cli.command, Commands::Shell(_)));
    }

    #[test]
    fn allow_gpu_coexists_with_phase16_and_env_filter_flags() {
        // Regression guard: --allow-gpu does NOT collide with Phase 16's
        // resource-limit flags or Plan 20-03's env-filter flags. All four
        // sets land on SandboxArgs via the same clap surface.
        let cli = Cli::try_parse_from([
            "nono",
            "run",
            "--allow-gpu",
            "--env-allow",
            "PATH",
            "--env-deny",
            "SECRET",
            "--cpu-percent",
            "25",
            "--memory",
            "512M",
            "--timeout",
            "30s",
            "--max-processes",
            "10",
            "--allow",
            ".",
            "echo",
        ]);
        assert!(
            cli.is_ok(),
            "--allow-gpu must coexist with Phase 16 + Plan 20-03 flags: {cli:?}"
        );
    }

    #[test]
    fn wrap_to_sandbox_args_propagates_allow_gpu() {
        // The WrapSandboxArgs → SandboxArgs conversion must carry allow_gpu
        // across. A regression here would silently drop the flag on
        // `nono wrap --allow-gpu` even though the parser accepts it.
        let wrap_cli = Cli::try_parse_from(["nono", "wrap", "--allow-gpu", "--allow", ".", "echo"])
            .expect("nono wrap --allow-gpu should parse");
        if let Commands::Wrap(args) = wrap_cli.command {
            let sandbox: SandboxArgs = args.sandbox.clone().into();
            assert!(sandbox.allow_gpu);
        } else {
            panic!("expected Wrap subcommand");
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn allow_gpu_windows_warning_helper_is_callable() {
        // T-20-04-05 mitigation: on Windows, `warn_if_allow_gpu_unsupported_on_platform`
        // emits a `tracing::warn!`. We don't intercept tracing events here
        // (that requires `tracing-test`), but we verify the helper is callable
        // without panic on both branches (flag off and flag on).
        let args_off = SandboxArgs {
            allow_gpu: false,
            ..SandboxArgs::default()
        };
        args_off.warn_if_allow_gpu_unsupported_on_platform(); // no-op branch

        let args_on = SandboxArgs {
            allow_gpu: true,
            ..SandboxArgs::default()
        };
        args_on.warn_if_allow_gpu_unsupported_on_platform(); // emits warn!, no panic
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn allow_gpu_non_windows_warning_helper_is_noop() {
        // On Linux/macOS the helper must be a total no-op even when the flag
        // is set — enforcement happens in the sandbox backend, not at CLI
        // parse time.
        let args = SandboxArgs {
            allow_gpu: true,
            ..SandboxArgs::default()
        };
        args.warn_if_allow_gpu_unsupported_on_platform();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_run_basic() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_with_separator() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "--", "echo", "hello"]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert_eq!(args.command, vec!["echo", "hello"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_run_multiple_paths() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            "./src",
            "--allow",
            "./docs",
            "--read",
            "/usr/share",
            "ls",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow.len(), 2);
                assert_eq!(args.sandbox.read.len(), 1);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_wrap_basic() {
        let cli = Cli::parse_from(["nono", "wrap", "--allow", ".", "--", "cargo", "build"]);
        match cli.command {
            Commands::Wrap(args) => {
                assert_eq!(args.command, vec!["cargo", "build"]);
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(!args.no_diagnostics);
            }
            _ => panic!("Expected Wrap command"),
        }
    }

    #[test]
    fn test_wrap_supports_direct_network_flags_only() {
        let cli = Cli::parse_from([
            "nono",
            "wrap",
            "--block-net",
            "--listen-port",
            "3000",
            "--open-port",
            "5432",
            "--allow",
            ".",
            "--",
            "cargo",
            "build",
        ]);
        match cli.command {
            Commands::Wrap(args) => {
                assert!(args.sandbox.block_net);
                assert_eq!(args.sandbox.allow_bind, vec![3000]);
                assert_eq!(args.sandbox.allow_port, vec![5432]);
            }
            _ => panic!("Expected Wrap command"),
        }
    }

    #[test]
    fn test_wrap_rejects_proxy_flags_at_parse_time() {
        let result = Cli::try_parse_from([
            "nono",
            "wrap",
            "--allow-domain",
            "api.openai.com",
            "--",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "wrap should not accept proxy filtering flags"
        );
    }

    #[test]
    fn test_wrap_help_hides_proxy_flags() {
        let mut cmd = Cli::command();
        let wrap = cmd
            .find_subcommand_mut("wrap")
            .expect("wrap subcommand should exist");

        let mut buf = Vec::new();
        wrap.write_long_help(&mut buf)
            .expect("failed to write wrap help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        assert!(help.contains("--block-net"));
        assert!(help.contains("--listen-port"));
        assert!(help.contains("--open-port"));
        assert!(!help.contains("--allow-domain"));
        assert!(!help.contains("--credential"));
        assert!(!help.contains("--network-profile"));
        assert!(!help.contains("--upstream-proxy"));
        assert!(!help.contains("--upstream-bypass"));
        assert!(!help.contains("--proxy-port"));
        assert!(!help.contains("--allow-net"));
    }

    #[test]
    fn test_root_help_short_circuits_in_parser() {
        let err = Cli::try_parse_from(["nono", "--help"])
            .expect_err("--help should short-circuit with clap display help");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayHelp);
    }

    #[test]
    fn test_root_version_short_circuits_in_parser() {
        let err = Cli::try_parse_from(["nono", "--version"])
            .expect_err("--version should short-circuit with clap display version");
        assert_eq!(err.kind(), clap::error::ErrorKind::DisplayVersion);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_root_help_mentions_windows_restricted_execution_surface() {
        let mut cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.write_long_help(&mut buf)
            .expect("failed to write root help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        assert!(
            help.contains("OS-enforced isolation"),
            "root help should describe OS-enforced isolation"
        );
        assert!(
            help.contains("ConPTY, build 17763+"),
            "root help should mention Windows shell support requirements"
        );
    }

    #[test]
    fn test_invalid_subcommand_is_parse_error() {
        let err = Cli::try_parse_from(["nono", "bad-subcommand"])
            .expect_err("unknown subcommand should be rejected by clap");
        assert_eq!(err.kind(), clap::error::ErrorKind::InvalidSubcommand);
    }

    #[test]
    fn test_shell_basic() {
        let cli = Cli::parse_from(["nono", "shell", "--allow", "."]);
        match cli.command {
            Commands::Shell(args) => {
                assert_eq!(args.sandbox.allow.len(), 1);
                assert!(args.shell.is_none());
            }
            _ => panic!("Expected Shell command"),
        }
    }

    #[test]
    fn test_rollback_list() {
        let cli = Cli::parse_from(["nono", "rollback", "list"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert!(list_args.recent.is_none());
                    assert!(list_args.path.is_none());
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_list_recent_json() {
        let cli = Cli::parse_from(["nono", "rollback", "list", "--recent", "5", "--json"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::List(list_args) => {
                    assert_eq!(list_args.recent, Some(5));
                    assert!(list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_show() {
        let cli = Cli::parse_from(["nono", "rollback", "show", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(!show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "restore", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.session_id, "20260214-143022-12345");
                    assert_eq!(restore_args.snapshot, None); // Default to last snapshot
                    assert!(!restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_restore_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "restore",
            "20260214-143022-12345",
            "--snapshot",
            "3",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Restore(restore_args) => {
                    assert_eq!(restore_args.snapshot, Some(3));
                    assert!(restore_args.dry_run);
                }
                _ => panic!("Expected Restore subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_audit_list() {
        let cli = Cli::parse_from(["nono", "audit", "list", "--today"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::List(list_args) => {
                    assert!(list_args.today);
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_show() {
        let cli = Cli::parse_from(["nono", "audit", "show", "20260214-143022-12345", "--json"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Show(show_args) => {
                    assert_eq!(show_args.session_id, "20260214-143022-12345");
                    assert!(show_args.json);
                }
                _ => panic!("Expected Show subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_rollback_verify() {
        let cli = Cli::parse_from(["nono", "rollback", "verify", "20260214-143022-12345"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.session_id, "20260214-143022-12345");
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_defaults() {
        let cli = Cli::parse_from(["nono", "rollback", "cleanup"]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert!(cleanup_args.keep.is_none());
                    assert!(cleanup_args.older_than.is_none());
                    assert!(!cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_rollback_cleanup_with_options() {
        let cli = Cli::parse_from([
            "nono",
            "rollback",
            "cleanup",
            "--keep",
            "5",
            "--older-than",
            "30",
            "--dry-run",
        ]);
        match cli.command {
            Commands::Rollback(args) => match args.command {
                RollbackCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.keep, Some(5));
                    assert_eq!(cleanup_args.older_than, Some(30));
                    assert!(cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Rollback command"),
        }
    }

    #[test]
    fn test_trust_init_defaults() {
        let cli = Cli::parse_from(["nono", "trust", "init"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Init(init_args) => {
                    assert!(!init_args.force);
                    assert!(init_args.key.is_none());
                    assert!(init_args.include.is_empty());
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_init_with_includes() {
        let cli = Cli::parse_from([
            "nono",
            "trust",
            "init",
            "--include",
            "*.md",
            "*.py",
            "--force",
        ]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Init(init_args) => {
                    assert!(init_args.force);
                    assert_eq!(init_args.include, vec!["*.md", "*.py"]);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!sign_args.all);
                    assert!(sign_args.key.is_none());
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_with_key() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "SKILLS.md", "--key", "my-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert_eq!(sign_args.key, Some("my-key".to_string()));
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_all() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "--all"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert!(sign_args.all);
                    assert!(sign_args.files.is_empty());
                    assert!(!sign_args.multi_subject);
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_sign_multi_subject() {
        let cli = Cli::parse_from(["nono", "trust", "sign", "--all", "--multi-subject"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Sign(sign_args) => {
                    assert!(sign_args.all);
                    assert!(sign_args.multi_subject);
                }
                _ => panic!("Expected Sign subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_verify() {
        let cli = Cli::parse_from(["nono", "trust", "verify", "SKILLS.md"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.files, vec![PathBuf::from("SKILLS.md")]);
                    assert!(!verify_args.all);
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_list() {
        let cli = Cli::parse_from(["nono", "trust", "list"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::List(list_args) => {
                    assert!(!list_args.json);
                }
                _ => panic!("Expected List subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen() {
        let cli = Cli::parse_from(["nono", "trust", "keygen"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "default");
                    assert!(!keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_keygen_with_id() {
        let cli = Cli::parse_from(["nono", "trust", "keygen", "--id", "my-key", "--force"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::Keygen(keygen_args) => {
                    assert_eq!(keygen_args.id, "my-key");
                    assert!(keygen_args.force);
                }
                _ => panic!("Expected Keygen subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_defaults() {
        let cli = Cli::parse_from(["nono", "trust", "export-key"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "default");
                    assert!(!export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_trust_export_key_with_options() {
        let cli = Cli::parse_from(["nono", "trust", "export-key", "--id", "my-key", "--pem"]);
        match cli.command {
            Commands::Trust(args) => match args.command {
                TrustCommands::ExportKey(export_args) => {
                    assert_eq!(export_args.id, "my-key");
                    assert!(export_args.pem);
                }
                _ => panic!("Expected ExportKey subcommand"),
            },
            _ => panic!("Expected Trust command"),
        }
    }

    #[test]
    fn test_rollback_flags_with_no_rollback() {
        // --no-rollback alongside rollback customization flags should parse
        // (the warning is emitted at runtime, not parse time)
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--no-rollback",
            "--rollback-exclude",
            "target",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.no_rollback);
                assert_eq!(args.rollback_exclude, vec!["target"]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_rollback_all_conflicts_with_include() {
        // --rollback-all conflicts with --rollback-include (clap enforced)
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--rollback-all",
            "--rollback-include",
            "target",
            "echo",
            "hello",
        ]);
        assert!(
            result.is_err(),
            "--rollback-all and --rollback-include should conflict"
        );
    }

    #[test]
    fn test_allow_net_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
                assert!(!args.sandbox.block_net);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_net_conflicts_with_block_net() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--block-net",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --block-net should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_network_profile() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--network-profile",
            "developer",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --network-profile should conflict"
        );
    }

    #[test]
    fn test_allow_net_conflicts_with_allow_domain() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-net",
            "--allow-domain",
            "api.openai.com",
            "echo",
        ]);
        assert!(
            result.is_err(),
            "--allow-net and --allow-domain should conflict"
        );
    }

    #[test]
    fn test_network_flag_aliases_still_parse() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--allow-domain",
            "api.openai.com",
            "--credential",
            "openai",
            "--listen-port",
            "3000",
            "--open-port",
            "5432",
            "--upstream-proxy",
            "squid.corp:3128",
            "--upstream-bypass",
            "internal.corp",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_proxy, vec!["api.openai.com"]);
                assert_eq!(args.sandbox.proxy_credential, vec!["openai"]);
                assert_eq!(args.sandbox.allow_bind, vec![3000]);
                assert_eq!(args.sandbox.allow_port, vec![5432]);
                assert_eq!(
                    args.sandbox.external_proxy.as_deref(),
                    Some("squid.corp:3128")
                );
                assert_eq!(args.sandbox.external_proxy_bypass, vec!["internal.corp"]);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--net-allow",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.allow_net);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--proxy-allow",
            "api.openai.com",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_proxy, vec!["api.openai.com"]);
            }
            _ => panic!("Expected Run command"),
        }

        let cli = Cli::parse_from(["nono", "why", "--host", "example.com", "--net-block"]);
        match cli.command {
            Commands::Why(args) => {
                assert!(args.block_net);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_allow_endpoint_flag_parses() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--credential",
            "github",
            "--allow-endpoint",
            "github:GET:/repos/*/issues",
            "--allow-endpoint",
            "github:POST:/repos/*/issues/*/comments",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_endpoint.len(), 2);
                assert_eq!(args.sandbox.allow_endpoint[0], "github:GET:/repos/*/issues");
                assert_eq!(
                    args.sandbox.allow_endpoint[1],
                    "github:POST:/repos/*/issues/*/comments"
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_single() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/test",
            "--allow",
            "/tmp/test",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 1);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/test"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_multiple() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/a",
            "--override-deny",
            "/tmp/b",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.override_deny.len(), 2);
                assert_eq!(args.sandbox.override_deny[0], PathBuf::from("/tmp/a"));
                assert_eq!(args.sandbox.override_deny[1], PathBuf::from("/tmp/b"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_env_credential_map_repeatable_parses_pairs() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--env-credential-map",
            "op://vault/item/field",
            "OPENAI_API_KEY",
            "--env-credential-map",
            "apple-password://github.com/user=name",
            "GITHUB_PASSWORD",
            "echo",
            "ok",
        ]);

        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.env_credential_map,
                    vec![
                        "op://vault/item/field".to_string(),
                        "OPENAI_API_KEY".to_string(),
                        "apple-password://github.com/user=name".to_string(),
                        "GITHUB_PASSWORD".to_string()
                    ]
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_allow_port_parsing() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--open-port",
            "3000",
            "--open-port",
            "5000",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.allow_port, vec![3000, 5000]);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_profile_init_basic() {
        let cli = Cli::parse_from(["nono", "profile", "init", "my-agent"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert!(init.extends.is_none());
                    assert!(init.groups.is_empty());
                    assert!(init.description.is_none());
                    assert!(!init.full);
                    assert!(init.output.is_none());
                    assert!(!init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_all_flags() {
        let cli = Cli::parse_from([
            "nono",
            "profile",
            "init",
            "my-agent",
            "--extends",
            "default",
            "--groups",
            "deny_credentials,node_runtime",
            "--description",
            "My agent profile",
            "--full",
            "--output",
            "/tmp/out.json",
            "--force",
        ]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Init(init) => {
                    assert_eq!(init.name, "my-agent");
                    assert_eq!(init.extends, Some("default".to_string()));
                    assert_eq!(init.groups, vec!["deny_credentials", "node_runtime"]);
                    assert_eq!(init.description, Some("My agent profile".to_string()));
                    assert!(init.full);
                    assert_eq!(init.output, Some(std::path::PathBuf::from("/tmp/out.json")));
                    assert!(init.force);
                }
                _ => panic!("Expected Init subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_default() {
        let cli = Cli::parse_from(["nono", "profile", "schema"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert!(schema.output.is_none());
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_schema_with_output() {
        let cli = Cli::parse_from(["nono", "profile", "schema", "-o", "/tmp/schema.json"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Schema(schema) => {
                    assert_eq!(
                        schema.output,
                        Some(std::path::PathBuf::from("/tmp/schema.json"))
                    );
                }
                _ => panic!("Expected Schema subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_guide() {
        let cli = Cli::parse_from(["nono", "profile", "guide"]);
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::Guide(_) => {}
                _ => panic!("Expected Guide subcommand"),
            },
            _ => panic!("Expected Profile command"),
        }
    }

    #[test]
    fn test_profile_init_missing_name() {
        let result = Cli::try_parse_from(["nono", "profile", "init"]);
        assert!(result.is_err(), "init without name should fail");
    }

    #[test]
    fn test_profile_no_subcommand() {
        let result = Cli::try_parse_from(["nono", "profile"]);
        assert!(result.is_err(), "profile without subcommand should fail");
    }

    #[test]
    fn test_profile_list_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "list", "--json"])
            .expect("profile list --json must parse");
        match cli.command {
            Commands::Profile(args) => match args.command {
                ProfileCommands::List(a) => assert!(a.json, "--json flag not set"),
                _ => panic!("expected ProfileCommands::List"),
            },
            _ => panic!("expected Commands::Profile"),
        }
    }

    #[test]
    fn test_profile_show_parses_with_format_manifest() {
        let cli =
            Cli::try_parse_from(["nono", "profile", "show", "default", "--format", "manifest"])
                .expect("profile show --format manifest must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Show(a) = args.command {
                assert_eq!(a.profile, "default");
                assert!(matches!(a.format, Some(ProfileShowFormat::Manifest)));
                return;
            }
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_show_parses_with_json_and_raw() {
        let cli = Cli::try_parse_from(["nono", "profile", "show", "default", "--json", "--raw"])
            .expect("profile show --json --raw must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Show(a) = args.command {
                assert!(a.json);
                assert!(a.raw);
                return;
            }
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_groups_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "--json", "--all-platforms"])
            .expect("profile groups --json --all-platforms must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Groups(a) = args.command {
                assert!(a.json);
                assert!(a.all_platforms);
                return;
            }
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_groups_with_name() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "deny_credentials"])
            .expect("profile groups <name> must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Groups(a) = args.command {
                assert_eq!(a.name.as_deref(), Some("deny_credentials"));
                return;
            }
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_diff_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "diff", "a", "b"])
            .expect("profile diff must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Diff(a) = args.command {
                assert_eq!(a.profile1, "a");
                assert_eq!(a.profile2, "b");
                return;
            }
        }
        panic!("expected Commands::Profile(Diff(..))");
    }

    #[test]
    fn test_profile_validate_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "validate", "/tmp/p.json"])
            .expect("profile validate must parse");
        if let Commands::Profile(args) = cli.command {
            if let ProfileCommands::Validate(a) = args.command {
                assert_eq!(a.file.to_string_lossy(), "/tmp/p.json");
                return;
            }
        }
        panic!("expected Commands::Profile(Validate(..))");
    }

    /// All subcommand names that must appear in the root help template.
    /// If you add a new command to the `Commands` enum, add it here too.
    ///
    /// Plan 22-05b Task 3 (upstream `4f9552ec`): `prune` was removed from
    /// this list and replaced by `session` because `Cmd::Prune` is now
    /// `#[command(hide = true)]` — the hidden alias surfaces a stderr
    /// deprecation note on every invocation but no longer appears in
    /// `nono --help`. AUD-04 acceptance #3.
    const ALL_SUBCOMMANDS: &[&str] = &[
        "setup",
        "run",
        "shell",
        "wrap",
        "learn",
        "why",
        "ps",
        "stop",
        "detach",
        "attach",
        "logs",
        "inspect",
        "session",
        "rollback",
        "audit",
        "trust",
        "policy",
        "profile",
        "pull",
        "remove",
        "update",
        "search",
        "list",
        "completion",
    ];

    #[test]
    fn test_root_help_lists_all_commands() {
        // The root help template is hardcoded — verify every subcommand appears in it.
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for name in ALL_SUBCOMMANDS {
            assert!(
                help.contains(&format!("  {name}")),
                "Root --help is missing subcommand `{name}`. \
                 Update the help_template on the Cli struct.",
            );
        }

        // Also verify we haven't forgotten to add a new variant to ALL_SUBCOMMANDS.
        for sub in cmd.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue; // clap auto-generates help; hidden commands are internal
            }
            assert!(
                ALL_SUBCOMMANDS.contains(&name.as_str()),
                "Commands enum has variant `{name}` not listed in ALL_SUBCOMMANDS. \
                 Add it to the constant and to the root help_template.",
            );
        }
    }

    #[test]
    fn test_root_help_shows_all_flags() {
        // Every non-hidden root-level flag must appear in the rendered help.
        // Catches flags missing a help_heading (which puts them in an unnamed
        // group that our custom template doesn't render).
        let cmd = Cli::command();
        let mut buf = Vec::new();
        cmd.clone()
            .write_help(&mut buf)
            .expect("failed to write help");
        let help = String::from_utf8(buf).expect("help is not utf-8");

        for arg in cmd.get_arguments() {
            if arg.is_hide_set() {
                continue;
            }
            if let Some(long) = arg.get_long() {
                assert!(
                    help.contains(&format!("--{long}")),
                    "Root --help is missing flag `--{long}`. \
                     Add `help_heading = \"OPTIONS\"` to its #[arg] attribute.",
                );
            }
        }
    }

    #[test]
    fn test_subcommand_help_structure() {
        let root = Cli::command();

        for sub in root.get_subcommands() {
            let name = sub.get_name().to_string();
            if name == "help" || sub.is_hide_set() {
                continue;
            }

            // Render the help text
            let mut buf = Vec::new();
            sub.clone()
                .write_help(&mut buf)
                .expect("failed to write help");
            let help = String::from_utf8(buf).expect("help is not utf-8");

            // Every subcommand must have a USAGE section
            assert!(
                help.contains("USAGE"),
                "`nono {name} --help` is missing a USAGE section",
            );

            // Every subcommand must have an EXAMPLES section
            assert!(
                help.contains("EXAMPLES"),
                "`nono {name} --help` is missing an EXAMPLES section",
            );

            // USAGE line should reference the correct command name
            assert!(
                help.contains(&format!("nono {name}")),
                "`nono {name} --help` USAGE line doesn't mention `nono {name}`",
            );

            // Collect all flags this subcommand actually accepts
            let known_flags: Vec<String> = sub
                .get_arguments()
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Also collect flags from nested subcommands (for rollback/audit/trust)
            let known_sub_flags: Vec<String> = sub
                .get_subcommands()
                .flat_map(|s: &clap::Command| s.get_arguments())
                .filter_map(|a: &clap::Arg| a.get_long().map(|l| l.to_string()))
                .collect();

            // Extract the EXAMPLES section and check flags referenced there
            if let Some(examples_start) = help.find("EXAMPLES") {
                let examples = &help[examples_start..];

                // Find all --flag patterns in examples
                for token in examples.split_whitespace() {
                    if let Some(flag) = token.strip_prefix("--") {
                        let flag =
                            flag.trim_end_matches(|c: char| !c.is_ascii_alphanumeric() && c != '-');
                        if flag.is_empty() || flag == "help" {
                            continue;
                        }
                        let valid = known_flags.iter().any(|f| f == flag)
                            || known_sub_flags.iter().any(|f| f == flag);
                        assert!(
                            valid,
                            "`nono {name} --help` EXAMPLES references --{flag} \
                             which is not a known flag on this subcommand",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn test_log_file_flag() {
        let cli = Cli::parse_from([
            "nono",
            "--log-file",
            "/tmp/nono.log",
            "run",
            "--allow",
            ".",
            "echo",
            "hi",
        ]);
        assert_eq!(cli.log_file, Some(PathBuf::from("/tmp/nono.log")));
    }

    #[test]
    fn test_log_file_flag_absent() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "echo", "hi"]);
        assert!(cli.log_file.is_none());
    }

    #[test]
    fn test_no_audit_integrity_flag_parses() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--no-audit-integrity",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.no_audit_integrity);
                assert!(!args.audit_integrity);
            }
            _ => panic!("Expected Run command"),
        }
    }
}
