//! Auto-pull prompt when a user runs `--profile <name>` and no local
//! resolver (user dir, pack store, embedded) has the profile.
//!
//! Resolution order:
//!   1. The small in-tree `OFFICIAL_PACKS` map for well-known names
//!      (`claude-code`, `codex`, …). Lets new users go from a fresh
//!      install to a working sandbox without needing a network round
//!      trip — the common case stays fast and deterministic.
//!   2. Registry endpoint `GET /api/v1/profiles/<name>/providers` for
//!      community packs. Adding a community-published profile is a
//!      registry-side operation; no CLI release required.
//!
//! Community packs that aren't in the registry's index just need the
//! explicit `nono pull <ns>/<pack>` once.

use crate::cli::PullArgs;
use crate::package::ProfileProvider;
use crate::package_cmd;
use crate::registry_client::{RegistryClient, resolve_registry_url};
use colored::Colorize;
use nono::Result;
use std::io::{self, BufRead, IsTerminal, Write};

const ENV_AUTO_MIGRATE: &str = "NONO_AUTO_MIGRATE";
const ENV_NO_MIGRATE: &str = "NONO_NO_MIGRATE";

/// Where users can read about the registry-pack model: why this prompt
/// fires, what gets installed, and what to do if anything breaks.
/// Surfaced in both the install confirmation and the decline-path hint
/// so users have a way to investigate before they say yes (or come
/// back to after they say no).
const LEARN_MORE_URL: &str = "https://github.com/always-further/nono/discussions/780";

/// Profile names this CLI knows about as official, vetted packs.
/// Fast-path for the common case so users don't pay a network round
/// trip for the marquee integrations. Community-published profiles
/// resolve via the registry endpoint instead — see `fetch_providers`.
///
/// Adding to this list is a deliberate signal that the pack is
/// maintained in lockstep with nono itself. Third-party packs do
/// **not** belong here; they go through the registry path and require
/// an explicit `nono pull` if no provider lookup is available.
const OFFICIAL_PACKS: &[OfficialPack] = &[
    OfficialPack {
        profile_name: "claude",
        namespace: "always-further",
        pack_name: "claude",
        description: Some("Anthropic Claude Code sandbox profile + plugin"),
        installs_summary: Some("sandbox profile + Claude Code plugin (hooks, skill)"),
    },
    // Transitional alias: the profile was originally `claude-code`,
    // renamed to `claude` so it matches the pack name. Once the pack
    // is installed, the resolver also accepts `claude-code` via the
    // artifact's `aliases` field. This entry only matters for users
    // who type `--profile claude-code` *before* the pack is installed.
    OfficialPack {
        profile_name: "claude-code",
        namespace: "always-further",
        pack_name: "claude",
        description: Some("Anthropic Claude Code (legacy profile name; canonical is `claude`)"),
        installs_summary: Some("sandbox profile + Claude Code plugin (hooks, skill)"),
    },
    OfficialPack {
        profile_name: "codex",
        namespace: "always-further",
        pack_name: "codex",
        description: Some("OpenAI Codex CLI sandbox profile + plugin"),
        installs_summary: Some("sandbox profile + Codex plugin (hooks, skill)"),
    },
];

struct OfficialPack {
    profile_name: &'static str,
    namespace: &'static str,
    pack_name: &'static str,
    description: Option<&'static str>,
    installs_summary: Option<&'static str>,
}

impl OfficialPack {
    fn as_provider(&self) -> ProfileProvider {
        ProfileProvider {
            namespace: self.namespace.to_string(),
            name: self.pack_name.to_string(),
            description: self.description.map(str::to_string),
            installs_summary: self.installs_summary.map(str::to_string),
        }
    }
}

/// Outcome of the migration check, communicated back to the caller so
/// it can decide whether to re-resolve the profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationOutcome {
    /// No registry pack provides this profile name. Caller should
    /// surface a "profile not found" error unchanged.
    NotApplicable,
    /// Pull ran successfully. Caller should re-resolve.
    Migrated,
    /// User declined or the context didn't permit a prompt. Caller
    /// should surface a clean cancellation.
    Skipped,
}

/// Top-level entry. Looks the profile name up in the registry; if
/// any pack provides it, prompts to install (or auto-installs under
/// `NONO_AUTO_MIGRATE=1`). Returns Ok unless the underlying pull
/// itself fails.
pub fn check_and_run(profile_name: &str) -> Result<MigrationOutcome> {
    if is_path_or_registry_ref(profile_name) {
        return Ok(MigrationOutcome::NotApplicable);
    }
    if env_flag(ENV_NO_MIGRATE) {
        return Ok(MigrationOutcome::Skipped);
    }

    // Resolve in two stages: in-tree map first (fast, offline,
    // covers the marquee integrations), then registry for community
    // packs. The in-tree entry wins on collision — the registry
    // can't override an officially-vetted pack ref by accident.
    let chosen = if let Some(pack) = official_pack_for(profile_name) {
        pack.as_provider()
    } else {
        match fetch_providers(profile_name) {
            Ok(p) if p.is_empty() => return Ok(MigrationOutcome::NotApplicable),
            Ok(mut p) => p.remove(0),
            Err(e) => {
                tracing::debug!("could not look up providers for profile '{profile_name}': {e}");
                return Ok(MigrationOutcome::NotApplicable);
            }
        }
    };

    let auto = env_flag(ENV_AUTO_MIGRATE);
    let interactive = io::stdin().is_terminal() && io::stderr().is_terminal();

    if !auto && !interactive {
        emit_skipped_hint(&chosen, SkipReason::NonInteractive);
        return Ok(MigrationOutcome::Skipped);
    }
    if !auto && !confirm_pull(profile_name, &chosen) {
        emit_skipped_hint(&chosen, SkipReason::Declined);
        return Ok(MigrationOutcome::Skipped);
    }

    run_pull(&chosen.pack_ref())?;

    // Pack is now installed. If the user is upgrading from <0.43, the
    // legacy `~/.claude/hooks/*` files and `settings.json::hooks`
    // entries are still in place and would run alongside the new pack
    // hooks. Offer cleanup with its own prompt so the user controls
    // what gets touched. Order matters: cleanup runs after the pull, so
    // a cleanup failure can't strand the user without a working pack.
    if is_claude_pack(&chosen) {
        crate::legacy_cleanup::check_and_offer_cleanup()?;
    }

    Ok(MigrationOutcome::Migrated)
}

fn is_claude_pack(provider: &ProfileProvider) -> bool {
    provider.namespace == "always-further" && provider.name == "claude"
}

fn official_pack_for(profile_name: &str) -> Option<&'static OfficialPack> {
    OFFICIAL_PACKS
        .iter()
        .find(|pack| pack.profile_name == profile_name)
}

fn fetch_providers(profile_name: &str) -> Result<Vec<ProfileProvider>> {
    let registry_url = resolve_registry_url(None);
    let client = RegistryClient::new(registry_url);
    client.fetch_profile_providers(profile_name)
}

fn is_path_or_registry_ref(name: &str) -> bool {
    name.contains('/') || name.ends_with(".json")
}

fn env_flag(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("1" | "true" | "yes")
    )
}

fn confirm_pull(profile_name: &str, provider: &ProfileProvider) -> bool {
    let pack_ref = provider.pack_ref();
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    let _ = writeln!(err, "  {}  Install {}?", "⊕".cyan(), pack_ref.bold(),);
    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "     The `{profile_name}` profile is provided by this registry pack.",
    );
    let _ = writeln!(err);

    let label_w = "Provenance".len();
    write_field(
        &mut err,
        "Publisher",
        &format!("{} GitHub organisation", provider.namespace),
        label_w,
    );
    write_field(
        &mut err,
        "Provenance",
        "Sigstore cryptographic supply chain (verified on pull)",
        label_w,
    );
    if let Some(summary) = provider.installs_summary.as_deref() {
        write_field(&mut err, "Installs", summary, label_w);
    }

    let _ = writeln!(err);
    let _ = writeln!(
        err,
        "  {}  First time seeing this prompt? Background, trust model,",
        "ⓘ".cyan(),
    );
    let _ = writeln!(
        err,
        "     and what gets installed: {}",
        LEARN_MORE_URL.dimmed(),
    );

    let _ = writeln!(err);
    let _ = write!(err, "  Continue? [Y/n] ");
    let _ = err.flush();
    drop(err);

    let mut line = String::new();
    if io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    let answer = line.trim().to_ascii_lowercase();
    answer.is_empty() || answer == "y" || answer == "yes"
}

#[derive(Clone, Copy)]
enum SkipReason {
    Declined,
    NonInteractive,
}

fn emit_skipped_hint(provider: &ProfileProvider, reason: SkipReason) {
    let pack_ref = provider.pack_ref();
    let mut err = io::stderr().lock();
    let _ = writeln!(err);
    match reason {
        SkipReason::Declined => {
            let _ = writeln!(
                err,
                "  install skipped — install later with: {}",
                format!("nono pull {pack_ref}").bold(),
            );
        }
        SkipReason::NonInteractive => {
            let _ = writeln!(err, "  install required but no TTY available. Either:",);
            let _ = writeln!(err, "    {}", format!("nono pull {pack_ref}").bold(),);
            let _ = writeln!(
                err,
                "  or re-run with {} to install non-interactively.",
                "NONO_AUTO_MIGRATE=1".bold(),
            );
        }
    }
    let _ = writeln!(err, "  Learn more: {}", LEARN_MORE_URL.dimmed());
    let _ = writeln!(err);
}

/// Field row matching `pull_ui::render_summary` so prompt + post-pull
/// summary share the same visual language.
fn write_field<W: Write>(out: &mut W, label: &str, value: &str, label_w: usize) {
    let _ = writeln!(
        out,
        "     {label:<width$}   {value}",
        label = label.dimmed(),
        value = value,
        width = label_w,
    );
}

fn run_pull(pack_ref: &str) -> Result<()> {
    package_cmd::run_pull(PullArgs {
        package_ref: pack_ref.to_string(),
        registry: None,
        // Migration only triggers when the resolver couldn't find the
        // pack-provided profile. The lockfile may still claim "up to
        // date" if the user wiped the pack dir manually — force
        // re-install so the files actually exist before we retry.
        force: true,
        init: false,
        help: None,
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{ENV_LOCK, EnvVarGuard};

    #[test]
    fn registry_ref_skips_migration() {
        assert!(is_path_or_registry_ref("always-further/claude"));
        assert!(is_path_or_registry_ref("./local.json"));
        assert!(is_path_or_registry_ref("path/to/profile.json"));
        assert!(!is_path_or_registry_ref("claude-code"));
        assert!(!is_path_or_registry_ref("my-profile"));
    }

    #[test]
    fn env_flag_recognises_truthy_values() {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("NONO_TEST_FLAG_VALUE", "1")]);
        assert!(env_flag("NONO_TEST_FLAG_VALUE"));
    }

    #[test]
    fn official_packs_cover_marquee_profiles() {
        assert!(official_pack_for("claude").is_some());
        assert!(official_pack_for("claude-code").is_some());
        assert!(official_pack_for("codex").is_some());
        assert!(official_pack_for("definitely-not-real").is_none());
    }

    #[test]
    fn legacy_claude_code_routes_to_renamed_claude_pack() {
        let canonical = official_pack_for("claude").expect("claude").as_provider();
        let legacy = official_pack_for("claude-code")
            .expect("claude-code")
            .as_provider();
        assert_eq!(canonical.pack_ref(), legacy.pack_ref());
        assert_eq!(canonical.pack_ref(), "always-further/claude");
    }

    #[test]
    fn env_flag_rejects_other_values() {
        let _g = match ENV_LOCK.lock() {
            Ok(g) => g,
            Err(p) => p.into_inner(),
        };
        let _env = EnvVarGuard::set_all(&[("NONO_TEST_FLAG_VALUE", "0")]);
        assert!(!env_flag("NONO_TEST_FLAG_VALUE"));
    }
}
