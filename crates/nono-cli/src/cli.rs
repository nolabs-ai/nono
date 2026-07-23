//! CLI argument definitions for nono
//!
//! Uses clap for argument parsing. This module defines all subcommands
//! and their options.

use clap::builder::styling::{Style, Styles};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

const STYLES: Styles = Styles::plain().header(Style::new().bold());

/// nono - The opposite of YOLO
///
/// A capability-based shell for running untrusted AI agents and processes
/// with OS-enforced filesystem and network isolation.
#[derive(Parser, Debug)]
#[command(name = "nono")]
#[command(author, version, about, long_about = None)]
#[command(styles = STYLES, next_help_heading = "OPTIONS")]
#[command(subcommand_help_heading = "")]
#[command(help_template = "\
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
  why        Check why filesystem, network, scope, or command access would be allowed or denied
  proxy      Run the network filtering / credential proxy as a standalone server

\x1b[1mSESSION MANAGEMENT\x1b[0m
  ps         List running or detached sandbox sessions
  stop       Stop a running sandbox session
  detach     Detach from an interactive runtime session
  attach     Attach to a detached runtime session
  logs       View runtime session event logs
  inspect    Show detailed runtime session state
  session    Manage runtime session storage
  rollback   Manage rollback sessions (browse, restore, cleanup)
  audit      View audit trail of sandboxed commands
  trust      Manage file trust and attestation

\x1b[1mPACKS\x1b[0m
  pull       Install a signed nono pack from the registry
  remove     Remove an installed nono pack
  update     Update installed nono packs
  outdated   Show which installed packs have newer versions available
  pin        Pin a pack to its current version
  unpin      Unpin a pack to re-include it in updates
  search     Search the registry for nono packs
  list       List installed nono packs
  sideload   Install a pack from a local directory (--features sideload builds only)

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
")]
pub struct Cli {
    /// Silent mode - suppress all nono output (banner, summary, status)
    #[arg(long, short = 's', global = true, help_heading = "OPTIONS")]
    pub silent: bool,

    /// Color theme for output (mocha, latte, frappe, macchiato, tokyo-night, minimal)
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
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono run --allow . claude                    # Read/write current dir, run claude
  nono run --profile nolabs-ai/claude claude        # Use a profile
  nono run --profile nolabs-ai/claude --allow-domain api.openai.com claude
                                               # Restrict outbound access to listed domains
  nono run --read ./src --write ./output cargo build
                                               # Separate read/write permissions
  nono run --allow . --block-net cargo build   # Block network access
  nono run --allow . --env-credential openai_api_key,anthropic_api_key -- claude
                                               # Load secrets from system keystore
")]
    Run(Box<RunArgs>),

    /// Start an interactive shell inside the sandbox
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono shell [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono shell --allow .                         # Shell with read/write to current dir
  nono shell --profile nolabs-ai/claude             # Use a named profile
  nono shell --allow . --shell /bin/zsh        # Override shell binary
")]
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
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono wrap --allow . -- cargo build           # Sandbox and exec into cargo build
  nono wrap --profile rust-dev -- cargo test    # Use a named profile
")]
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
  macOS   Prefer: nono run --profile <name> -- <command>
          Legacy unsandboxed fs_usage/nettop tracing: nono learn --trace -- <command>
")]
    Learn(Box<LearnArgs>),

    /// Check why filesystem, network, scope, or command access would be allowed or denied
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
  nono why --profile gh --command gh -- issue comment 1052
                                                # Query ETI command argv policy

\x1b[1mETI TOOL DENIALS\x1b[0m
  `nono why --command <cmd> -- <args...>` diagnoses tool-sandbox argv policy.
  A message like:

    nono: tool-sandbox denied gh: Command 'gh' is blocked: agents may read issues but not comment on them

  is an ephemeral tool invocation command-policy denial from
  command_policies.commands.<name>.from.<caller>.invocation_policy. If the
  command uses proxy credentials, also check endpoint_policy for HTTP method
  and path rules.
")]
    Why(Box<WhyArgs>),

    /// Run the network filtering / credential proxy as a standalone server
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono proxy [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono proxy                                   # Ephemeral port, token auth, prints connection info
  nono proxy --port 8080                       # Fixed port
  nono proxy --port 8080 --no-auth             # Open loopback proxy (no token required)
  nono proxy --allow-domain github.com         # Allowlist a host
  nono proxy --profile my-profile              # Load network settings from a profile
")]
    Proxy(Box<ProxyArgs>),

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
  nono rollback list                           # List rollback sessions
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
    #[command(after_help = "EXAMPLES:
    # Show running sessions
    nono ps

    # Show all sessions (including exited)
    nono ps --all

    # JSON output
    nono ps --json
")]
    Ps(PsArgs),

    /// Stop a running sandboxed session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono stop [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Stop a session by ID (prefix match)
    nono stop a3f7c2

    # Force stop (SIGKILL)
    nono stop --force a3f7c2
")]
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
        after_help = "EXAMPLES:
    # Detach by session ID
    nono detach a3f7c2

    # Detach by name
    nono detach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach without opening a second terminal.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
"
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
        after_help = "EXAMPLES:
    # Attach by session ID
    nono attach a3f7c2

    # Attach by name
    nono attach calm-gate

IN-BAND DETACH:
    By default, press Ctrl-] then d to detach from the session.
    This can be changed in ~/.config/nono/config.toml:
      [ui]
      detach_sequence = \"ctrl-] d\"
"
    )]
    Attach(AttachArgs),

    /// View event log for a session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono logs [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # View recent events
    nono logs a3f7c2

    # Follow events in real-time
    nono logs -f a3f7c2

    # Show last 20 events
    nono logs --tail 20 a3f7c2

    # JSON output
    nono logs --json a3f7c2
")]
    Logs(LogsArgs),

    /// Show detailed information about a session
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono inspect [flags] <session>

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Inspect a session
    nono inspect a3f7c2

    # Include event log
    nono inspect --events a3f7c2

    # JSON output
    nono inspect --json a3f7c2
")]
    Inspect(InspectArgs),

    /// Clean up old session files
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono prune [flags]

{all-args}
{after-help}")]
    #[command(after_help = "EXAMPLES:
    # Preview what would be cleaned
    nono prune --dry-run

    # Remove sessions older than 7 days
    nono prune --older-than 7

    # Keep only 10 most recent sessions
    nono prune --keep 10
")]
    #[command(hide = true)]
    Prune(PruneArgs),

    /// Manage runtime session storage
    #[command(subcommand_help_heading = "COMMANDS")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono session <command>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono session cleanup --dry-run              # Preview old runtime sessions
  nono session cleanup --older-than 7         # Remove sessions older than 7 days
  nono session cleanup --keep 10              # Keep only 10 recent sessions
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
  nono profile validate my-agent               # Validate a profile by name
  nono profile validate ~/my-profile.json      # Validate a profile file
  nono profile validate --draft my-profile     # Validate a profile draft
  nono profile promote my-profile              # Review and apply a profile draft
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
  nono pull nolabs-ai/claude
  nono pull nolabs-ai/claude@1.2.0 --registry http://localhost:3000
  nono pull nolabs-ai/claude --init
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
  nono remove nolabs-ai/claude
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
  nono update nolabs-ai/claude
  nono update --dry-run
  nono update --force                          # also update pinned packs
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

    /// Pin an installed pack to its current version, excluding it from updates
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono pin <namespace>/<name>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono pin nolabs-ai/claude
")]
    Pin(PinArgs),

    /// Unpin a pack so it is included in updates again
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono unpin <namespace>/<name>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono unpin nolabs-ai/claude
")]
    Unpin(UnpinArgs),

    /// Show which installed packs have newer versions available
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono outdated [flags]

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono outdated
  nono outdated --json
")]
    Outdated(OutdatedArgs),

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

    /// Install a nono pack from a local directory, bypassing registry attestation.
    ///
    /// WARNING: integrity protections are DISABLED for sideloaded packs.
    /// Use `nono remove` to uninstall. Do NOT use on production systems.
    #[cfg(feature = "sideload")]
    #[command(help_template = "\
{about}

\x1b[1mUSAGE\x1b[0m
  nono sideload <path>

{all-args}
{after-help}")]
    #[command(after_help = "\x1b[1mEXAMPLES\x1b[0m
  nono sideload ./my-pack                      # Install from local directory
  nono sideload /abs/path/to/pack              # Install from absolute path
")]
    Sideload(SideloadArgs),

    /// Internal: open a URL via supervisor IPC
    #[command(hide = true)]
    OpenUrlHelper(OpenUrlHelperArgs),

    /// Internal: refresh cached pack update hints out of process
    #[command(hide = true)]
    PackUpdateHintHelper(PackUpdateHintHelperArgs),
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

    /// Continue removal even if some wiring directives fail to reverse.
    /// Without this flag, partial reversal failures keep the lockfile
    /// entry intact so the user can retry, since silently forgetting a
    /// half-removed pack would orphan agent wiring (e.g. a hook entry
    /// in `~/.codex/hooks.json` left active with no record of who put
    /// it there).
    #[arg(long, default_value_t = false)]
    pub force: bool,

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

    /// Show what would be updated without making changes
    #[arg(long, help_heading = "OPTIONS")]
    pub dry_run: bool,

    /// Update pinned packs and accept signer changes
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

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct PinArgs {
    /// Installed package reference (<namespace>/<name>)
    pub package_ref: String,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct UnpinArgs {
    /// Installed package reference (<namespace>/<name>)
    pub package_ref: String,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct OutdatedArgs {
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

/// Arguments for the hidden open-url-helper subcommand.
///
/// Invoked as `BROWSER=nono open-url-helper` on Linux, or via the `open`
/// PATH shim on macOS. Reads `NONO_SUPERVISOR_PATH` from the environment,
/// connects to the supervisor's named Unix socket, sends an `OpenUrl` IPC
/// message, and waits for a response.
#[derive(Parser, Debug, Clone)]
pub struct OpenUrlHelperArgs {
    /// The URL to open
    pub url: String,
}

/// Arguments for `nono sideload`. Only present when the binary is compiled
/// with `--features sideload`. Do NOT use on production systems.
#[cfg(feature = "sideload")]
#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct SideloadArgs {
    /// Path to the local pack directory (must contain package.json)
    pub path: PathBuf,

    /// Namespace (registry owner) for the pack, e.g. `acme-corp`.
    ///
    /// If omitted, the namespace is inferred from the `origin` git remote of
    /// the pack directory (the GitHub owner extracted from the remote URL).
    /// Errors if the namespace cannot be determined from either source.
    #[arg(long, value_name = "NAMESPACE", help_heading = "OPTIONS")]
    pub namespace: Option<String>,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

/// Arguments for the hidden pack-update-hint-helper subcommand.
///
/// Invoked by `nono run` to refresh stale pack update hint cache entries in a
/// child process, so the supervised parent does not gain an extra thread before
/// fork.
#[derive(Parser, Debug, Clone)]
pub struct PackUpdateHintHelperArgs {
    /// Alternating package reference and installed version values.
    pub packs: Vec<String>,
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
    /// Show a fully resolved profile
    Show(ProfileShowArgs),
    /// Diff two profiles
    Diff(ProfileDiffArgs),
    /// Validate a profile JSON file
    Validate(ProfileValidateArgs),
    /// Review and apply a profile draft from ~/.config/nono/profile-drafts
    Promote(ProfilePromoteArgs),
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
#[command(disable_help_flag = true)]
pub struct ProfileValidateArgs {
    /// Profile JSON file to validate
    pub file: PathBuf,
    /// Treat the argument as a draft name under ~/.config/nono/profile-drafts
    #[arg(long)]
    pub draft: bool,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Treat deprecated schema warnings as errors (exit code 2 if any are found).
    ///
    /// Use this in CI to block profiles that still rely on the pre-#594
    /// legacy schema keys. A canonical profile with zero deprecation
    /// warnings passes as usual.
    #[arg(long)]
    pub strict: bool,
    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct ProfilePromoteArgs {
    /// Draft profile name
    pub name: String,
    /// Show the proposed diff without applying it
    #[arg(long)]
    pub diff: bool,
    /// Apply without interactive confirmation
    #[arg(long)]
    pub yes: bool,
    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
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

    /// Allow connect() to an AF_UNIX socket at this path (implies --read-file)
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket: Vec<PathBuf>,

    /// Allow connect() and bind() on an AF_UNIX socket at this path.
    /// If the path exists, implies --allow-file on the socket. If it
    /// does not yet exist (the typical bind(2) case), implies --allow
    /// on the parent directory so the kernel can create the socket
    /// file. Prefer --allow-unix-socket-dir-bind for runtime-generated
    /// filenames.
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket directly within this directory.
    /// Non-recursive on macOS and future Linux AF_UNIX mediation; current
    /// Linux Landlock filesystem fallback is recursive.
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket directly within this
    /// directory. Non-recursive on macOS and future Linux AF_UNIX mediation;
    /// current Linux Landlock filesystem fallback is recursive. Use for
    /// runtime-generated socket filenames (PID-derived paths, etc.).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket within this directory subtree
    /// (recursive; implies --read)
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_subtree: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket within this directory
    /// subtree (recursive; implies --allow).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_subtree_bind: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    /// ALIAS(canonical="--bypass-protection", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[arg(
        long = "bypass-protection",
        alias = "override-deny",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub bypass_protection: Vec<PathBuf>,

    /// Suppress save-profile prompts for denials under this path. Does not grant access
    /// ALIAS(canonical="--suppress-save-prompt", introduced="v0.52.0", remove_by="indefinite", issue="#875")
    #[arg(
        long = "suppress-save-prompt",
        alias = "ignore-denied",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub suppress_save_prompt: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    /// ALIAS(canonical="--block-net", introduced="v0.0.0", remove_by="indefinite", issue="#302")
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
    /// ALIAS(canonical="--allow-net", introduced="v0.0.0", remove_by="indefinite", issue="#302")
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

    /// Add a domain to the proxy allowlist (repeatable).
    /// Use a plain hostname for unrestricted access, or a URL with a path glob
    /// to restrict to specific endpoints (e.g., https://github.com/org/**)
    /// ALIAS(canonical="--allow-domain", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "allow-domain",
        alias = "allow-proxy",
        alias = "proxy-allow",
        env = "NONO_ALLOW_DOMAIN",
        value_name = "DOMAIN_OR_URL",
        help_heading = "NETWORK"
    )]
    pub allow_proxy: Vec<String>,

    /// Block a domain through the proxy. Evaluated before the allowlist.
    /// Supports wildcards (e.g. *.ads.example.com). Incompatible with --allow-net.
    #[arg(
        long = "deny-domain",
        env = "NONO_DENY_DOMAIN",
        value_name = "DOMAIN",
        conflicts_with = "allow_net",
        help_heading = "NETWORK"
    )]
    pub deny_proxy: Vec<String>,

    /// Allow the sandboxed child to listen on a TCP port (repeatable)
    /// ALIAS(canonical="--listen-port", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    /// ALIAS(canonical="--open-port", introduced="v0.0.0", remove_by="indefinite", issue="#415")
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
    /// ALIAS(canonical="--upstream-proxy", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "upstream-proxy",
        alias = "external-proxy",
        value_name = "HOST:PORT",
        env = "NONO_UPSTREAM_PROXY",
        help_heading = "NETWORK"
    )]
    pub external_proxy: Option<String>,

    /// Route these domains direct instead of through the upstream proxy
    /// ALIAS(canonical="--upstream-bypass", introduced="v0.0.0", remove_by="indefinite", issue="#415")
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

    /// Add the proxy CA to the macOS user trust store (enables Go CLI tools).
    /// Shares the CA across sessions via Keychain; regenerates daily.
    #[cfg(target_os = "macos")]
    #[arg(
        long,
        env = "NONO_TRUST_PROXY_CA",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "NETWORK"
    )]
    pub trust_proxy_ca: bool,

    /// Proxy CA certificate validity in days (1–365, default: 1).
    /// Controls how long the ephemeral CA (and its leaf certificates) remain valid.
    #[arg(
        long,
        value_name = "DAYS",
        env = "NONO_PROXY_CA_VALIDITY",
        value_parser = clap::value_parser!(u32).range(1..=365),
        help_heading = "NETWORK"
    )]
    pub proxy_ca_validity: Option<u32>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Inject credentials via reverse proxy for a service (repeatable)
    /// ALIAS(canonical="--credential", introduced="v0.0.0", remove_by="v1.0.0", issue="#143")
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

    // ── Commands ─────────────────────────────────────────────────────────
    /// Deprecated startup-only command allowlist override (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Deprecated startup-only command denylist extension (not child-process enforced)
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

    /// Allow GPU access (Metal/IOKit on Apple Silicon macOS, render nodes on Linux)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_gpu: bool,

    /// Linux sandbox enforcement mechanism [auto|landlock|external] (default: auto).
    ///
    /// auto     — Landlock with automatic seccomp fallback when the kernel
    ///            lacks network support (ABI < V4). This is the default.
    /// landlock — Landlock only; fails at startup if network restrictions
    ///            cannot be satisfied without seccomp.
    /// external — No sandbox installed by nono; enforcement is managed
    ///            externally (iptables, cgroups, systemd, etc.).
    #[cfg(target_os = "linux")]
    #[arg(long, help_heading = "OPTIONS", value_name = "POLICY")]
    pub sandbox_policy: Option<crate::profile::LinuxSandboxPolicy>,

    /// Allow HTTP/2 multiplexing for upstream proxy connections.
    ///
    /// When enabled, the proxy negotiates HTTP/2 via ALPN with upstream
    /// servers that support it, allowing multiple requests to be multiplexed
    /// over a single TCP connection. This can significantly improve throughput
    /// for workloads that make many concurrent requests to the same host
    /// (e.g., Maven/Gradle artifact downloads).
    ///
    /// Without this flag, the proxy uses HTTP/1.1 with keep-alive connection
    /// pooling (connections are reused but requests are serialized per
    /// connection). This is the conservative default since some upstream
    /// servers may not handle HTTP/2 correctly.
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_http2: bool,

    /// Extend the selected profile with an additional base profile for this invocation
    #[arg(
        long,
        value_name = "PROFILE",
        requires = "profile",
        help_heading = "OPTIONS"
    )]
    pub extends: Vec<String>,

    /// Capability manifest file (JSON). A fully-resolved sandbox specification —
    /// mutually exclusive with all other sandbox configuration flags.
    #[arg(
        long,
        short = 'c',
        value_name = "FILE",
        conflicts_with_all = &[
            "allow", "read", "write", "allow_file", "read_file", "write_file",
            "allow_unix_socket", "allow_unix_socket_bind",
            "allow_unix_socket_dir", "allow_unix_socket_dir_bind",
            "allow_unix_socket_subtree", "allow_unix_socket_subtree_bind",
            "profile", "extends", "bypass_protection", "suppress_save_prompt", "allow_cwd",
            "block_net", "allow_net", "network_profile", "allow_proxy",
            "allow_bind", "allow_port", "allow_connect_port", "external_proxy", "proxy_port",
            "proxy_credential", "allow_endpoint", "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services", "allow_gpu", "allow_http2",
            "memory", "max_processes",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    /// Maximum resident memory for the process tree (e.g. 512M, 1Gi).
    /// Enforced on Linux via cgroup v2; requires a supervised run.
    #[arg(long, value_name = "SIZE", help_heading = "RESOURCES")]
    pub memory: Option<String>,

    /// Maximum number of processes and threads in the process tree.
    /// Enforced on Linux via cgroup v2 (pids.max); requires a supervised run.
    /// At the cap the kernel refuses new forks rather than killing anything.
    #[arg(long, value_name = "COUNT", help_heading = "RESOURCES")]
    pub max_processes: Option<u64>,

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
}

/// Arguments for the standalone `nono proxy` command.
///
/// Runs the network-filtering / credential-injection proxy as a foreground
/// server (no sandboxed child). Proxy settings can be loaded from a profile
/// (`--profile`) and extended/overridden with explicit flags. The flag names
/// mirror the `NETWORK` / `CREDENTIALS` flags on `nono run`.
#[derive(Parser, Debug, Clone)]
pub struct ProxyArgs {
    /// Address the proxy listens on (loopback only unless --no-auth is omitted)
    #[arg(
        long,
        value_name = "ADDR",
        default_value = "127.0.0.1",
        help_heading = "PROXY"
    )]
    pub listen: std::net::IpAddr,

    /// Port to listen on (0 = OS-assigned ephemeral port)
    #[arg(long, value_name = "PORT", default_value_t = 0, help_heading = "PROXY")]
    pub port: u16,

    /// Disable session-token auth: accept every request on the bind address.
    /// Refused for non-loopback bind addresses. Use with care.
    #[arg(long, conflicts_with = "pass", help_heading = "PROXY")]
    pub no_auth: bool,

    /// Use this exact password as the proxy credential instead of a randomly
    /// generated session token. Clients present it via Proxy-Authorization
    /// (Basic password or Bearer token). Prefer NONO_PROXY_PASS to avoid
    /// leaking the secret in shell history / process listings.
    #[arg(
        long,
        value_name = "PASSWORD",
        env = "NONO_PROXY_PASS",
        help_heading = "PROXY"
    )]
    pub pass: Option<String>,

    /// Use a profile by name or file path (loads its network/credential settings)
    #[arg(
        long,
        short = 'p',
        value_name = "NAME_OR_PATH",
        env = "NONO_PROFILE",
        help_heading = "PROXY"
    )]
    pub profile: Option<String>,

    /// Maximum concurrent client connections (0 = unlimited). Raise this when
    /// driving highly parallel clients such as `docker pull`, which opens many
    /// simultaneous tunnels and can exhaust the default limit.
    #[arg(
        long,
        value_name = "N",
        default_value_t = 256,
        env = "NONO_PROXY_MAX_CONNECTIONS",
        help_heading = "PROXY"
    )]
    pub max_connections: usize,

    // ── Network ──────────────────────────────────────────────────────────
    /// Enable proxy filtering with a named network profile
    #[arg(
        long,
        value_name = "PROFILE",
        env = "NONO_NETWORK_PROFILE",
        help_heading = "NETWORK"
    )]
    pub network_profile: Option<String>,

    /// Add a domain to the proxy allowlist (repeatable).
    /// Plain hostname for unrestricted access, or a URL with a path glob
    /// to restrict to specific endpoints (e.g., https://github.com/org/**)
    /// ALIAS(canonical="--allow-domain", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "allow-domain",
        alias = "allow-proxy",
        alias = "proxy-allow",
        env = "NONO_ALLOW_DOMAIN",
        value_name = "DOMAIN_OR_URL",
        help_heading = "NETWORK"
    )]
    pub allow_proxy: Vec<String>,

    /// Block a domain through the proxy. Evaluated before the allowlist.
    /// Supports wildcards (e.g. *.ads.example.com).
    #[arg(
        long = "deny-domain",
        env = "NONO_DENY_DOMAIN",
        value_name = "DOMAIN",
        help_heading = "NETWORK"
    )]
    pub deny_proxy: Vec<String>,

    /// Chain outbound traffic through an upstream proxy (host:port)
    /// ALIAS(canonical="--upstream-proxy", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "upstream-proxy",
        alias = "external-proxy",
        value_name = "HOST:PORT",
        env = "NONO_UPSTREAM_PROXY",
        help_heading = "NETWORK"
    )]
    pub external_proxy: Option<String>,

    /// Route these domains direct instead of through the upstream proxy
    /// ALIAS(canonical="--upstream-bypass", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "upstream-bypass",
        alias = "external-proxy-bypass",
        value_name = "DOMAIN",
        env = "NONO_UPSTREAM_BYPASS",
        value_delimiter = ',',
        help_heading = "NETWORK"
    )]
    pub external_proxy_bypass: Vec<String>,

    /// Allow HTTP/2 multiplexing for upstream proxy connections.
    ///
    /// When enabled, the proxy negotiates HTTP/2 via ALPN with upstream
    /// servers that support it, allowing multiple requests to be multiplexed
    /// over a single TCP connection. This can significantly improve throughput
    /// for workloads that make many concurrent requests to the same host
    /// (e.g., Maven/Gradle artifact downloads).
    ///
    /// Without this flag, the proxy uses HTTP/1.1 with keep-alive connection
    /// pooling (connections are reused but requests are serialized per
    /// connection). This is the conservative default since some upstream
    /// servers may not handle HTTP/2 correctly.
    #[arg(long, help_heading = "NETWORK")]
    pub allow_http2: bool,

    /// Add the proxy CA to the macOS user trust store (enables Go CLI tools).
    #[cfg(target_os = "macos")]
    #[arg(long, env = "NONO_TRUST_PROXY_CA", help_heading = "NETWORK")]
    pub trust_proxy_ca: bool,

    /// Proxy CA certificate validity in days (1–365, default: 1).
    #[arg(
        long,
        value_name = "DAYS",
        env = "NONO_PROXY_CA_VALIDITY",
        value_parser = clap::value_parser!(u32).range(1..=365),
        help_heading = "NETWORK"
    )]
    pub proxy_ca_validity: Option<u32>,

    /// Sign intercepted TLS connections with this existing CA certificate
    /// (PEM) instead of a fresh per-session CA. Reuses the same CA across
    /// proxy runs so clients only have to trust it once. Requires
    /// --proxy-ca-key. Validity comes from the supplied certificate, so it
    /// cannot be combined with --proxy-ca-validity.
    #[arg(
        long,
        value_name = "PEM_FILE",
        env = "NONO_PROXY_CA_CERT",
        requires = "proxy_ca_key",
        conflicts_with = "proxy_ca_validity",
        help_heading = "NETWORK"
    )]
    pub proxy_ca_cert: Option<PathBuf>,

    /// Private key (PKCS#8 PEM) for --proxy-ca-cert. Prefer
    /// NONO_PROXY_CA_KEY to keep the path out of shell history; the key file
    /// itself should be readable only by you.
    #[arg(
        long,
        value_name = "PEM_FILE",
        env = "NONO_PROXY_CA_KEY",
        requires = "proxy_ca_cert",
        help_heading = "NETWORK"
    )]
    pub proxy_ca_key: Option<PathBuf>,

    // ── Credentials ──────────────────────────────────────────────────────
    /// Inject credentials via reverse proxy for a service (repeatable)
    /// ALIAS(canonical="--credential", introduced="v0.0.0", remove_by="v1.0.0", issue="#143")
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

    // ── Options ──────────────────────────────────────────────────────────
    /// Enable verbose output (-v info, -vv debug, -vvv trace)
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,
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

    /// Allow connect() to an AF_UNIX socket at this path (implies --read-file)
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket: Vec<PathBuf>,

    /// Allow connect() and bind() on an AF_UNIX socket at this path.
    /// If the path exists, implies --allow-file on the socket. If it
    /// does not yet exist (the typical bind(2) case), implies --allow
    /// on the parent directory so the kernel can create the socket
    /// file. Prefer --allow-unix-socket-dir-bind for runtime-generated
    /// filenames.
    #[arg(long, value_name = "SOCKET", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket directly within this directory.
    /// Non-recursive on macOS and future Linux AF_UNIX mediation; current
    /// Linux Landlock filesystem fallback is recursive.
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket directly within this
    /// directory. Non-recursive on macOS and future Linux AF_UNIX mediation;
    /// current Linux Landlock filesystem fallback is recursive. Use for
    /// runtime-generated socket filenames (PID-derived paths, etc.).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_dir_bind: Vec<PathBuf>,

    /// Allow connect() to any AF_UNIX socket within this directory subtree
    /// (recursive; implies --read)
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_subtree: Vec<PathBuf>,

    /// Allow connect() and bind() on any AF_UNIX socket within this directory
    /// subtree (recursive; implies --allow).
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub allow_unix_socket_subtree_bind: Vec<PathBuf>,

    /// Override a deny rule for a path. Pair with --allow/--read/--write grant
    /// ALIAS(canonical="--bypass-protection", introduced="v0.41.0", remove_by="v1.0.0", issue="#594")
    #[arg(
        long = "bypass-protection",
        alias = "override-deny",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub bypass_protection: Vec<PathBuf>,

    /// Suppress save-profile prompts for denials under this path. Does not grant access
    /// ALIAS(canonical="--suppress-save-prompt", introduced="v0.52.0", remove_by="indefinite", issue="#875")
    #[arg(
        long = "suppress-save-prompt",
        alias = "ignore-denied",
        value_name = "PATH",
        help_heading = "FILESYSTEM"
    )]
    pub suppress_save_prompt: Vec<PathBuf>,

    /// Allow CWD access without prompting (level set by profile, defaults to read-only)
    #[arg(long, help_heading = "FILESYSTEM")]
    pub allow_cwd: bool,

    /// Working directory for $WORKDIR expansion in profiles
    #[arg(long, value_name = "DIR", help_heading = "FILESYSTEM")]
    pub workdir: Option<PathBuf>,

    // ── Network ──────────────────────────────────────────────────────────
    /// Block outbound network access (allowed by default)
    /// ALIAS(canonical="--block-net", introduced="v0.0.0", remove_by="indefinite", issue="#302")
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
    /// ALIAS(canonical="--listen-port", introduced="v0.0.0", remove_by="indefinite", issue="#415")
    #[arg(
        long = "listen-port",
        alias = "allow-bind",
        value_name = "PORT",
        help_heading = "NETWORK"
    )]
    pub allow_bind: Vec<u16>,

    /// Allow bidirectional localhost TCP on a port: connect + listen (repeatable)
    /// ALIAS(canonical="--open-port", introduced="v0.0.0", remove_by="indefinite", issue="#415")
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

    // ── Commands ─────────────────────────────────────────────────────────
    /// Deprecated startup-only command allowlist override (not child-process enforced)
    #[arg(long, value_name = "CMD", help_heading = "COMMANDS")]
    pub allow_command: Vec<String>,

    /// Deprecated startup-only command denylist extension (not child-process enforced)
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

    /// Extend the selected profile with an additional base profile for this invocation
    #[arg(
        long,
        value_name = "PROFILE",
        requires = "profile",
        help_heading = "OPTIONS"
    )]
    pub extends: Vec<String>,

    /// Allow direct LaunchServices opens on macOS (temporary login/setup flows)
    #[arg(long, help_heading = "OPTIONS")]
    pub allow_launch_services: bool,

    /// Allow GPU access (Metal/IOKit on Apple Silicon macOS, render nodes on Linux)
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
            "allow_unix_socket", "allow_unix_socket_bind",
            "allow_unix_socket_dir", "allow_unix_socket_dir_bind",
            "allow_unix_socket_subtree", "allow_unix_socket_subtree_bind",
            "profile", "extends", "bypass_protection", "suppress_save_prompt", "allow_cwd",
            "block_net", "allow_bind", "allow_port", "allow_connect_port",
            "env_credential", "env_credential_map",
            "allow_command", "block_command", "allow_launch_services", "allow_gpu",
        ],
        help_heading = "OPTIONS"
    )]
    pub config: Option<PathBuf>,

    /// Enable verbose output
    #[arg(long, short = 'v', action = clap::ArgAction::Count, help_heading = "OPTIONS")]
    pub verbose: u8,

    // `wrap` deliberately has no `--memory`: it execs directly and cannot create
    // the enforcement cgroup, so a cap could not be applied. Use `nono run`. A
    // memory limit arriving via `--config <manifest>` is still refused at runtime
    // in `run_wrap`.
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
            allow_unix_socket: args.allow_unix_socket,
            allow_unix_socket_bind: args.allow_unix_socket_bind,
            allow_unix_socket_dir: args.allow_unix_socket_dir,
            allow_unix_socket_dir_bind: args.allow_unix_socket_dir_bind,
            allow_unix_socket_subtree: args.allow_unix_socket_subtree,
            allow_unix_socket_subtree_bind: args.allow_unix_socket_subtree_bind,
            bypass_protection: args.bypass_protection,
            suppress_save_prompt: args.suppress_save_prompt,
            allow_cwd: args.allow_cwd,
            workdir: args.workdir,
            block_net: args.block_net,
            allow_net: false,
            network_profile: None,
            allow_proxy: Vec::new(),
            deny_proxy: Vec::new(),
            allow_bind: args.allow_bind,
            allow_port: args.allow_port,
            allow_connect_port: args.allow_connect_port,
            external_proxy: None,
            external_proxy_bypass: Vec::new(),
            proxy_port: None,
            #[cfg(target_os = "macos")]
            trust_proxy_ca: false,
            proxy_ca_validity: None,
            proxy_credential: Vec::new(),
            allow_endpoint: Vec::new(),
            env_credential: args.env_credential,
            env_credential_map: args.env_credential_map,
            allow_command: args.allow_command,
            block_command: args.block_command,
            profile: args.profile,
            extends: args.extends,
            allow_launch_services: args.allow_launch_services,
            allow_gpu: args.allow_gpu,
            allow_http2: false,
            config: args.config,
            verbose: args.verbose,
            // `wrap` has no `--memory` / `--max-processes` flags (it cannot enforce
            // them); a limit in a `--config` manifest is refused at runtime in `run_wrap`.
            memory: None,
            max_processes: None,
            dry_run: args.dry_run,
            #[cfg(target_os = "linux")]
            sandbox_policy: None,
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

    /// How long (seconds) to wait for a detached session to become attachable.
    /// Only meaningful with --detached. Env: NONO_DETACH_STARTUP_TIMEOUT.
    #[arg(
        long = "detach-timeout",
        value_name = "SECS",
        requires = "detached",
        env = "NONO_DETACH_STARTUP_TIMEOUT",
        help_heading = "OPTIONS"
    )]
    pub detach_timeout_secs: Option<u64>,

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
    /// By default, snapshots are stored in $XDG_STATE_HOME/nono/rollbacks/.
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

    /// After the run, print session diagnostics as JSON on stderr (merged with proxy diagnostics when present).
    #[arg(long = "diagnostics-json", help_heading = "OPTIONS")]
    pub diagnostics_json: bool,

    /// Kill the process if it has not entered alt-screen mode after this many seconds.
    /// Startup banners and log lines do not count; only a full-screen TUI transition satisfies the check.
    /// Set to 0 to disable. Env: NONO_STARTUP_TIMEOUT.
    #[arg(
        long = "startup-timeout",
        value_name = "SECS",
        env = "NONO_STARTUP_TIMEOUT",
        help_heading = "OPTIONS"
    )]
    pub startup_timeout_secs: Option<u64>,

    /// Disable the audit trail for this session
    #[arg(
        long,
        conflicts_with_all = ["audit_integrity", "no_audit_integrity", "rollback"],
        help_heading = "OPTIONS"
    )]
    pub no_audit: bool,

    /// Disable the default Merkleized append-only audit log
    #[arg(long, conflicts_with_all = ["audit_integrity", "rollback"], help_heading = "OPTIONS")]
    pub no_audit_integrity: bool,

    /// Add filesystem-state hashing over in-scope writable paths
    #[arg(long, help_heading = "OPTIONS")]
    pub audit_integrity: bool,

    /// Sign the audit Merkle root with a keyed signing key loaded from the given secret reference.
    /// Accepts bare trust-key IDs, keystore:// names, file:// paths, op:// URIs, apple-password:// URIs, keyring:// URIs, or env:// URIs.
    #[arg(
        long,
        value_name = "SECRET_REF",
        conflicts_with_all = ["no_audit", "no_audit_integrity"],
        help_heading = "OPTIONS"
    )]
    pub audit_sign_key: Option<String>,

    /// Disable trust verification (not recommended for production)
    #[arg(
        long,
        env = "NONO_TRUST_OVERRIDE",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "OPTIONS"
    )]
    pub trust_override: bool,

    /// Name for this session (shown in `nono ps`)
    #[arg(long, value_name = "NAME", help_heading = "OPTIONS")]
    pub name: Option<String>,

    /// Enable runtime capability elevation (seccomp-notify + approval prompts).
    /// Overrides the profile's capability_elevation setting.
    /// When enabled, the supervisor can grant access to paths not in the
    /// initial capability set via interactive prompts.
    #[arg(
        long,
        env = "NONO_CAPABILITY_ELEVATION",
        value_parser = clap::builder::BoolishValueParser::new(),
        action = clap::ArgAction::SetTrue,
        help_heading = "OPTIONS"
    )]
    pub capability_elevation: bool,

    /// Command to run inside the sandbox (optional if profile specifies `binary`)
    #[arg(hide = true)]
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

    /// Kill the process if it has not become interactive after this many seconds.
    /// Set to 0 to disable. Env: NONO_STARTUP_TIMEOUT.
    #[arg(
        long = "startup-timeout",
        value_name = "SECS",
        env = "NONO_STARTUP_TIMEOUT",
        help_heading = "OPTIONS"
    )]
    pub startup_timeout_secs: Option<u64>,

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
    /// Tool-sandbox command name to check (ETI command policy)
    #[arg(long, help_heading = "QUERY")]
    pub command: Option<String>,

    /// Caller edge for command policy checks (default: session)
    #[arg(long, default_value = "session", help_heading = "QUERY")]
    pub caller: String,

    /// Arguments for --command after `--`
    #[arg(last = true, value_name = "ARGS", help_heading = "QUERY")]
    pub command_args: Vec<String>,

    /// Path to check
    #[arg(long, help_heading = "QUERY")]
    pub path: Option<PathBuf>,

    /// Operation to check: read, write, or readwrite
    #[arg(long, value_enum, help_heading = "QUERY")]
    pub op: Option<WhyOp>,

    /// Network host or URL to check (e.g. github.com or https://github.com/org/repo)
    #[arg(long, help_heading = "QUERY")]
    pub host: Option<String>,

    /// Landlock scope to check
    #[arg(long, value_enum, value_name = "SCOPE", help_heading = "QUERY")]
    pub scope: Option<WhyScope>,

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
    /// ALIAS(canonical="--block-net", introduced="v0.0.0", remove_by="indefinite", issue="#302")
    #[arg(long = "block-net", alias = "net-block", help_heading = "CONTEXT")]
    pub block_net: bool,

    /// Use a named profile for query context
    #[arg(long, short = 'p', value_name = "NAME", help_heading = "CONTEXT")]
    pub profile: Option<String>,

    /// Extend the selected profile with an additional base profile for this query
    #[arg(
        long,
        value_name = "PROFILE",
        requires = "profile",
        help_heading = "CONTEXT"
    )]
    pub extends: Vec<String>,

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

    /// Extend the selected profile with an additional base profile for this comparison
    #[arg(
        long,
        value_name = "PROFILE",
        requires = "profile",
        help_heading = "OPTIONS"
    )]
    pub extends: Vec<String>,

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

    /// On macOS, use legacy unsandboxed fs_usage/nettop tracing
    #[arg(long, help_heading = "OPTIONS")]
    pub trace: bool,

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

/// Landlock scope type for why command
#[derive(Clone, Debug, ValueEnum)]
pub enum WhyScope {
    /// Signal scoping
    Signal,
    /// Abstract UNIX socket scoping
    #[value(name = "abstract-unix-socket")]
    AbstractUnixSocket,
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
    /// List rollback sessions
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

    /// Compatibility flag; rollback sessions are shown by default
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
    /// Verify audit integrity by recomputing hashes from the event log
    Verify(AuditVerifyArgs),
    /// Remove old audit sessions
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

#[derive(Parser, Debug)]
#[command(disable_help_flag = true)]
pub struct AuditVerifyArgs {
    /// Session ID (e.g., 20260214-143022-12345)
    pub session_id: String,

    /// Public key file to match against the attested signer key (PEM or base64 DER)
    #[arg(long, value_name = "FILE")]
    pub public_key_file: Option<PathBuf>,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Print help
    #[arg(long, short = 'h', action = clap::ArgAction::Help, help_heading = "OPTIONS")]
    pub help: Option<bool>,
}

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

#[derive(Parser, Debug)]
pub struct PruneArgs {
    /// Show what would be removed without deleting
    #[arg(long)]
    pub dry_run: bool,

    /// Remove sessions older than N days
    #[arg(long, value_name = "DAYS")]
    pub older_than: Option<u64>,

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
    fn test_resource_flags_parse() {
        // Both resource flags parse, independently and together.
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--memory",
            "512M",
            "--max-processes",
            "64",
            "--",
            "true",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.memory.as_deref(), Some("512M"));
                assert_eq!(args.sandbox.max_processes, Some(64));
            }
            _ => panic!("Expected Run command"),
        }

        // --max-processes takes a plain integer; a non-integer is a clap parse error.
        assert!(
            Cli::try_parse_from(["nono", "run", "--max-processes", "lots", "--", "true"]).is_err(),
            "--max-processes must reject a non-integer"
        );
    }

    #[test]
    fn test_resource_flags_conflict_with_config() {
        // --config (manifest) is mutually exclusive with the resource flags.
        let res = Cli::try_parse_from([
            "nono", "run", "--config", "m.json", "--memory", "512M", "--", "true",
        ]);
        assert!(res.is_err(), "--config and --memory must conflict");

        let res = Cli::try_parse_from([
            "nono",
            "run",
            "--config",
            "m.json",
            "--max-processes",
            "64",
            "--",
            "true",
        ]);
        assert!(res.is_err(), "--config and --max-processes must conflict");
    }

    #[test]
    fn test_wrap_rejects_resource_flags_and_from_maps_them_to_none() {
        // `wrap` cannot enforce a cap (it execs directly), so it exposes neither
        // resource flag — clap rejects the unknown flags.
        let res = Cli::try_parse_from(["nono", "wrap", "--memory", "256M", "--", "true"]);
        assert!(res.is_err(), "wrap must not accept --memory");
        let res = Cli::try_parse_from(["nono", "wrap", "--max-processes", "64", "--", "true"]);
        assert!(res.is_err(), "wrap must not accept --max-processes");

        // And the hand-written `From<WrapSandboxArgs>` always maps both to None
        // (a manifest-borne limit is refused later in run_wrap, not here).
        let sandbox: SandboxArgs = WrapSandboxArgs::default().into();
        assert!(sandbox.memory.is_none());
        assert!(sandbox.max_processes.is_none());
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
    fn test_extends_repeated_preserves_order() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--profile",
            "agent",
            "--extends",
            "linux-host-compat",
            "--extends",
            "extra-git",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.extends,
                    vec!["linux-host-compat".to_string(), "extra-git".to_string()]
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_extends_requires_profile() {
        let result = Cli::try_parse_from(["nono", "run", "--extends", "base", "echo"]);
        assert!(result.is_err(), "--extends without --profile should fail");
    }

    #[test]
    fn test_config_conflicts_with_extends() {
        let result = Cli::try_parse_from([
            "nono",
            "run",
            "--config",
            "manifest.json",
            "--profile",
            "agent",
            "--extends",
            "base",
            "echo",
        ]);
        assert!(result.is_err(), "--config and --extends should conflict");
    }

    #[test]
    fn test_wrap_extends_is_copied_to_sandbox_args() {
        let cli = Cli::parse_from([
            "nono",
            "wrap",
            "--profile",
            "agent",
            "--extends",
            "base",
            "--",
            "echo",
        ]);
        match cli.command {
            Commands::Wrap(args) => {
                let wrap = *args;
                let sandbox: SandboxArgs = wrap.sandbox.into();
                assert_eq!(sandbox.extends, vec!["base".to_string()]);
            }
            _ => panic!("Expected Wrap command"),
        }
    }

    #[test]
    fn test_why_and_learn_extends_parse() {
        let cli = Cli::parse_from([
            "nono",
            "why",
            "--profile",
            "agent",
            "--extends",
            "base",
            "--path",
            "/tmp",
        ]);
        match cli.command {
            Commands::Why(args) => assert_eq!(args.extends, vec!["base".to_string()]),
            _ => panic!("Expected Why command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "learn",
            "--profile",
            "agent",
            "--extends",
            "base",
            "echo",
        ]);
        match cli.command {
            Commands::Learn(args) => assert_eq!(args.extends, vec!["base".to_string()]),
            _ => panic!("Expected Learn command"),
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
    fn test_audit_verify() {
        let cli = Cli::parse_from(["nono", "audit", "verify", "20260214-143022-12345", "--json"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Verify(verify_args) => {
                    assert_eq!(verify_args.session_id, "20260214-143022-12345");
                    assert!(verify_args.json);
                }
                _ => panic!("Expected Verify subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_audit_cleanup() {
        let cli = Cli::parse_from(["nono", "audit", "cleanup", "--keep", "5", "--dry-run"]);
        match cli.command {
            Commands::Audit(args) => match args.command {
                AuditCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.keep, Some(5));
                    assert!(cleanup_args.dry_run);
                    assert!(!cleanup_args.all);
                }
                _ => panic!("Expected Cleanup subcommand"),
            },
            _ => panic!("Expected Audit command"),
        }
    }

    #[test]
    fn test_session_cleanup() {
        let cli = Cli::parse_from(["nono", "session", "cleanup", "--older-than", "7"]);
        match cli.command {
            Commands::Session(args) => match args.command {
                SessionCommands::Cleanup(cleanup_args) => {
                    assert_eq!(cleanup_args.older_than, Some(7));
                    assert!(!cleanup_args.dry_run);
                }
            },
            _ => panic!("Expected Session command"),
        }
    }

    #[test]
    fn test_prune_still_parses_as_hidden_compat_command() {
        let cli = Cli::parse_from(["nono", "prune", "--dry-run"]);
        match cli.command {
            Commands::Prune(args) => assert!(args.dry_run),
            _ => panic!("Expected hidden Prune command"),
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

        let cli = Cli::parse_from(["nono", "why", "--scope", "abstract-unix-socket"]);
        match cli.command {
            Commands::Why(args) => {
                assert!(matches!(args.scope, Some(WhyScope::AbstractUnixSocket)));
            }
            _ => panic!("Expected Why command"),
        }

        let cli = Cli::parse_from([
            "nono",
            "why",
            "--profile",
            "gh",
            "--command",
            "gh",
            "--",
            "issue",
            "comment",
            "1052",
        ]);
        match cli.command {
            Commands::Why(args) => {
                assert_eq!(args.profile.as_deref(), Some("gh"));
                assert_eq!(args.command.as_deref(), Some("gh"));
                assert_eq!(args.caller, "session");
                assert_eq!(args.command_args, vec!["issue", "comment", "1052"]);
            }
            _ => panic!("Expected Why command"),
        }
    }

    #[test]
    fn test_why_help_mentions_eti_command_policy_denials() {
        let mut cmd = Cli::command();
        let help = cmd
            .find_subcommand_mut("why")
            .expect("why subcommand exists")
            .render_long_help()
            .to_string();

        assert!(help.contains("ETI TOOL DENIALS"), "{help}");
        assert!(
            help.contains("command_policies.commands.<name>.from.<caller>.invocation_policy"),
            "{help}"
        );
        assert!(help.contains("--command <COMMAND>"), "{help}");
        assert!(
            help.contains("nono why --command <cmd> -- <args...>"),
            "{help}"
        );
    }

    #[test]
    fn test_unix_socket_subtree_flags_parse() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow-unix-socket-subtree",
            "/tmp/nx",
            "--allow-unix-socket-subtree-bind",
            "/tmp/nx-bind",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.allow_unix_socket_subtree,
                    vec![PathBuf::from("/tmp/nx")]
                );
                assert_eq!(
                    args.sandbox.allow_unix_socket_subtree_bind,
                    vec![PathBuf::from("/tmp/nx-bind")]
                );
            }
            _ => panic!("Expected Run command"),
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
    fn test_bypass_protection_single() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--bypass-protection",
            "/tmp/test",
            "--allow",
            "/tmp/test",
            "echo",
            "hello",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.bypass_protection.len(), 1);
                assert_eq!(
                    args.sandbox.bypass_protection[0],
                    PathBuf::from("/tmp/test")
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_bypass_protection_multiple() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--bypass-protection",
            "/tmp/a",
            "--bypass-protection",
            "/tmp/b",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.bypass_protection.len(), 2);
                assert_eq!(args.sandbox.bypass_protection[0], PathBuf::from("/tmp/a"));
                assert_eq!(args.sandbox.bypass_protection[1], PathBuf::from("/tmp/b"));
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_override_deny_alias_populates_bypass_protection() {
        // The legacy `--override-deny` flag is retained as a clap alias for
        // `--bypass-protection`. This test locks in that parsing behavior so
        // removing the alias in the v1.0.0 cleanup is deliberate, not accidental.
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--override-deny",
            "/tmp/test",
            "--allow",
            "/tmp/test",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.bypass_protection.len(), 1);
                assert_eq!(
                    args.sandbox.bypass_protection[0],
                    PathBuf::from("/tmp/test")
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_suppress_save_prompt_multiple() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--suppress-save-prompt",
            "/tmp/a",
            "--suppress-save-prompt",
            "/tmp/b",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(args.sandbox.suppress_save_prompt.len(), 2);
                assert_eq!(
                    args.sandbox.suppress_save_prompt[0],
                    PathBuf::from("/tmp/a")
                );
                assert_eq!(
                    args.sandbox.suppress_save_prompt[1],
                    PathBuf::from("/tmp/b")
                );
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_ignore_denied_alias_maps_to_suppress_save_prompt() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--ignore-denied",
            "/tmp/a",
            "--allow",
            ".",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert_eq!(
                    args.sandbox.suppress_save_prompt,
                    vec![PathBuf::from("/tmp/a")]
                );
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
    fn test_capability_elevation_flag_sets_true() {
        let cli = Cli::parse_from([
            "nono",
            "run",
            "--allow",
            ".",
            "--capability-elevation",
            "echo",
        ]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.capability_elevation);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[test]
    fn test_trust_override_flag_sets_true() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "--trust-override", "echo"]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.trust_override);
            }
            _ => panic!("Expected Run command"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_trust_proxy_ca_flag_sets_true() {
        let cli = Cli::parse_from(["nono", "run", "--allow", ".", "--trust-proxy-ca", "echo"]);
        match cli.command {
            Commands::Run(args) => {
                assert!(args.sandbox.trust_proxy_ca);
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
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Show(a) = args.command
        {
            assert_eq!(a.profile, "default");
            assert!(matches!(a.format, Some(ProfileShowFormat::Manifest)));
            return;
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_show_parses_with_json_and_raw() {
        let cli = Cli::try_parse_from(["nono", "profile", "show", "default", "--json", "--raw"])
            .expect("profile show --json --raw must parse");
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Show(a) = args.command
        {
            assert!(a.json);
            assert!(a.raw);
            return;
        }
        panic!("expected Commands::Profile(Show(..))");
    }

    #[test]
    fn test_profile_groups_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "--json", "--all-platforms"])
            .expect("profile groups --json --all-platforms must parse");
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Groups(a) = args.command
        {
            assert!(a.json);
            assert!(a.all_platforms);
            return;
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_groups_with_name() {
        let cli = Cli::try_parse_from(["nono", "profile", "groups", "deny_credentials"])
            .expect("profile groups <name> must parse");
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Groups(a) = args.command
        {
            assert_eq!(a.name.as_deref(), Some("deny_credentials"));
            return;
        }
        panic!("expected Commands::Profile(Groups(..))");
    }

    #[test]
    fn test_profile_diff_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "diff", "a", "b"])
            .expect("profile diff must parse");
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Diff(a) = args.command
        {
            assert_eq!(a.profile1, "a");
            assert_eq!(a.profile2, "b");
            return;
        }
        panic!("expected Commands::Profile(Diff(..))");
    }

    #[test]
    fn test_profile_validate_parses() {
        let cli = Cli::try_parse_from(["nono", "profile", "validate", "/tmp/p.json"])
            .expect("profile validate must parse");
        if let Commands::Profile(args) = cli.command
            && let ProfileCommands::Validate(a) = args.command
        {
            assert_eq!(a.file.to_string_lossy(), "/tmp/p.json");
            return;
        }
        panic!("expected Commands::Profile(Validate(..))");
    }

    /// All subcommand names that must appear in the root help template.
    /// If you add a new command to the `Commands` enum, add it here too.
    const ALL_SUBCOMMANDS: &[&str] = &[
        "setup",
        "run",
        "shell",
        "wrap",
        "learn",
        "why",
        "proxy",
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
        "outdated",
        "pin",
        "unpin",
        "search",
        "list",
        "completion",
        // Only present when compiled with --features sideload.
        #[cfg(feature = "sideload")]
        "sideload",
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
}
