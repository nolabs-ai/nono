//! Runtime checks for security-sensitive official pack status.

use crate::package::{self, PackageRef, PackageStatusResponse};
use crate::profile;
use crate::registry_client::{RegistryClient, resolve_registry_url};
use nono::{NonoError, Result};

#[derive(Clone, Copy, Debug)]
struct OfficialPackStatusTarget {
    namespace: &'static str,
    name: &'static str,
    legacy_namespaces: &'static [&'static str],
    profiles: &'static [&'static str],
}

const CLAUDE_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nolabs-ai",
    name: "claude",
    legacy_namespaces: &["always-further"],
    profiles: &["claude", "claude-code"],
};

const CODEX_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nolabs-ai",
    name: "codex",
    legacy_namespaces: &[],
    profiles: &["codex"],
};

const OFFICIAL_PACK_STATUS_TARGETS: &[OfficialPackStatusTarget] = &[CLAUDE_PACK, CODEX_PACK];

impl OfficialPackStatusTarget {
    /// Every namespace this pack has been published under, current one first.
    fn namespaces(self) -> impl Iterator<Item = &'static str> {
        std::iter::once(self.namespace).chain(self.legacy_namespaces.iter().copied())
    }

    /// Every `<namespace>/<name>` this pack has been published under.
    fn keys(self) -> impl Iterator<Item = String> {
        self.namespaces()
            .map(move |ns| format!("{ns}/{}", self.name))
    }

    fn package_ref(self) -> PackageRef {
        PackageRef {
            namespace: self.namespace.to_string(),
            name: self.name.to_string(),
            version: None,
        }
    }
}

/// Namespaces the official claude pack has been published under.
///
/// Exposed so `profile` can gate legacy cleanup on the same list this module
/// matches against, rather than keeping a second copy that can drift.
pub(crate) fn official_claude_pack_namespaces() -> impl Iterator<Item = &'static str> {
    CLAUDE_PACK.namespaces()
}

/// If `pack_ref` (`<namespace>/<name>` or `<namespace>/<name>@version`)
/// addresses an official pack through a retired namespace, return the same
/// reference rewritten to the pack's current namespace.
///
/// Used to point remediation commands (`nono pull ...`) at a namespace that
/// still resolves, instead of echoing back one the registry no longer serves
/// packs under.
pub(crate) fn canonicalize_legacy_pack_ref(pack_ref: &str) -> Option<String> {
    let (head, version) = match pack_ref.split_once('@') {
        Some((h, v)) => (h, Some(v)),
        None => (pack_ref, None),
    };
    let (namespace, name) = head.split_once('/')?;
    let target = OFFICIAL_PACK_STATUS_TARGETS
        .iter()
        .find(|t| t.name == name && t.legacy_namespaces.contains(&namespace))?;
    let canonical = format!("{}/{}", target.namespace, target.name);
    Some(match version {
        Some(v) => format!("{canonical}@{v}"),
        None => canonical,
    })
}

/// Enforce official-pack status for the profile this run selected.
///
/// `cli_extends` carries `--extends`, which behaves as if those bases were
/// prepended to the selected profile's `extends`, so a run that reaches a
/// yanked pack only through `--extends` must be gated too.
pub(crate) fn enforce_for_active_profile(
    profile_name: Option<&str>,
    cli_extends: &[String],
    silent: bool,
) -> Result<()> {
    let Some(profile_name) = profile_name else {
        return Ok(());
    };

    for target in OFFICIAL_PACK_STATUS_TARGETS {
        if run_loads_official_pack(*target, profile_name, cli_extends) {
            enforce_official_pack_status(*target, silent)?;
        }
    }
    Ok(())
}

fn enforce_official_pack_status(target: OfficialPackStatusTarget, silent: bool) -> Result<()> {
    let lockfile = package::read_lockfile()?;
    let Some((key, locked)) = target
        .keys()
        .find_map(|k| lockfile.packages.get(&k).map(|locked| (k, locked)))
    else {
        return Ok(());
    };

    let package_ref = target.package_ref();
    let registry_url = if lockfile.registry.trim().is_empty() {
        resolve_registry_url(None)
    } else {
        resolve_registry_url(Some(lockfile.registry.as_str()))
    };
    let client = RegistryClient::new(registry_url);
    let status = match client.fetch_package_status(&package_ref, Some(locked.version.as_str())) {
        Ok(status) => status,
        Err(error) => {
            tracing::debug!(
                "could not check official pack status for {key}@{}: {error}",
                locked.version
            );
            return Ok(());
        }
    };

    match status.installed_status.as_deref() {
        Some("yanked") => Err(NonoError::ActionRequired(yanked_message(
            &key,
            locked.version.as_str(),
            &status,
        ))),
        Some("current") | None => Ok(()),
        Some(other) => {
            if !silent {
                eprintln!(
                    "  [nono] official pack {}@{} status: {}",
                    key, locked.version, other
                );
                if let Some(latest) = status.latest.as_deref() {
                    eprintln!("  [nono] update with: nono pull {key}@{latest} --force");
                }
            }
            Ok(())
        }
    }
}

fn yanked_message(key: &str, installed: &str, status: &PackageStatusResponse) -> String {
    let mut message = format!("official pack {key}@{installed} has been yanked by the registry");
    if let Some(reason) = status.yank_reason.as_deref() {
        message.push_str(&format!(" (reason: {reason})"));
    }
    if let Some(advisory) = status.advisory.as_ref() {
        let severity = advisory.severity.as_deref().unwrap_or("unknown");
        let summary = advisory.summary.as_deref().unwrap_or("no summary provided");
        message.push_str(&format!("\nadvisory: {severity} - {summary}"));
    }
    if let Some(latest) = status.latest.as_deref() {
        message.push_str(&format!(
            "\nupdate before launching this profile: nono pull {key}@{latest} --force"
        ));
    } else {
        message.push_str(
            "\nno replacement version was returned by the registry; inspect package versions before launching this profile",
        );
    }
    message
}

/// Returns `true` when this run launches Claude Code: the `nolabs-ai/claude`
/// pack ref, any name the installed pack answers to (its `install_as` plus the
/// manifest's aliases), the names the pack is published under while it is not
/// installed yet, a user profile file named after one of those, or any profile
/// whose `extends` chain reaches one of those.
///
/// `cli_extends` carries `--extends`, whose bases are resolved as if they
/// were prepended to the selected profile's own `extends`.
///
/// This is deliberately broader than [`run_loads_official_pack`]: it gates the
/// Claude Code sandbox preparation, which a profile needs because of what it
/// launches, not because of where it came from.
pub(crate) fn profile_selects_claude_code(name_or_path: &str, cli_extends: &[String]) -> bool {
    reaches_official_pack_profile(
        CLAUDE_PACK,
        name_or_path,
        cli_extends,
        name_launches_official_pack,
    )
}

/// Returns `true` when this run loads `target`'s own profile: the pack ref, a
/// name the installed pack answers to, a name the pack is published under
/// while it is not installed yet, or any profile whose `extends` chain reaches
/// one of those.
///
/// Unlike [`profile_selects_claude_code`] this mirrors the resolver exactly, so
/// a user profile file shadowing a published name is not the pack: that run
/// never loads the pack, and the pack's registry status says nothing about it.
fn run_loads_official_pack(
    target: OfficialPackStatusTarget,
    name_or_path: &str,
    cli_extends: &[String],
) -> bool {
    reaches_official_pack_profile(target, name_or_path, cli_extends, name_loads_official_pack)
}

/// The pack a bare `--profile <name>` would resolve to, if any — matching the
/// canonical `install_as` names and the manifest aliases alike.
///
/// Delegates to the resolver's own lookup rather than re-deriving it from a
/// separate scan, so this answer cannot drift from the pack `load_profile_inner`
/// would load — including the tie-break when two installed packs publish the
/// same profile name.
///
/// Each call rescans the pack store (a `read_dir` per namespace plus a
/// `package.json` read and parse per pack). Detection asks this once per node of
/// every `extends` chain it walks, but the walk already pays the same scan per
/// node inside [`profile::load_profile_extends`], so this at most doubles a cost
/// bounded by chain length. Cache it in `profile` — behind the one lookup both
/// sides use — if that ever shows up in a profile.
fn pack_store_provider(name: &str) -> Option<String> {
    profile::find_pack_store_profile(name).map(|(_, pack_key)| pack_key)
}

/// Walk `name_or_path` and the `--extends` bases, asking `name_matches` about
/// each name and following every `extends` edge until one matches.
fn reaches_official_pack_profile(
    target: OfficialPackStatusTarget,
    name_or_path: &str,
    cli_extends: &[String],
    name_matches: fn(OfficialPackStatusTarget, &str) -> bool,
) -> bool {
    let mut visited = Vec::new();
    // `--extends` bases sit alongside the selected profile rather than under
    // it, so each one needs its own walk. `visited` is shared: a name that
    // fails to reach the pack fails for every root.
    std::iter::once(name_or_path)
        .chain(cli_extends.iter().map(String::as_str))
        .any(|name| walk_extends_chain(target, name, name_matches, &mut visited))
}

fn walk_extends_chain(
    target: OfficialPackStatusTarget,
    name_or_path: &str,
    name_matches: fn(OfficialPackStatusTarget, &str) -> bool,
    visited: &mut Vec<String>,
) -> bool {
    if name_matches(target, name_or_path) {
        return true;
    }
    if visited.iter().any(|visited| visited == name_or_path) {
        return false;
    }
    visited.push(name_or_path.to_string());

    let Some(bases) = profile::load_profile_extends(name_or_path) else {
        return false;
    };
    bases
        .iter()
        .any(|base| walk_extends_chain(target, base, name_matches, visited))
}

/// Returns `true` when this single name loads `target`'s own profile, ignoring
/// `extends`.
///
/// Mirrors the resolver's precedence (`load_profile_inner`): pack ref, then
/// user override, then the pack store, then the published names.
fn name_loads_official_pack(target: OfficialPackStatusTarget, name: &str) -> bool {
    if is_official_package_ref(target, name) {
        return true;
    }
    // A user file shadows the pack, so this name loads that file, not the pack.
    if profile::is_user_override(name) {
        return false;
    }
    name_resolves_to_official_pack(target, name)
}

/// Returns `true` when this single name launches `target`'s agent, ignoring
/// `extends`.
///
/// Differs from [`name_loads_official_pack`] on a user profile file named after
/// the pack: `~/.config/nono/profiles/claude-code.json` shadows the pack, but it
/// still launches Claude Code and still needs the Claude Code preparation.
fn name_launches_official_pack(target: OfficialPackStatusTarget, name: &str) -> bool {
    if is_official_package_ref(target, name) {
        return true;
    }
    if profile::is_user_override(name) {
        return is_official_profile_name(target, name);
    }
    name_resolves_to_official_pack(target, name)
}

/// The tail both questions share: the pack store, then the published names.
fn name_resolves_to_official_pack(target: OfficialPackStatusTarget, name: &str) -> bool {
    if let Some(pack_key) = pack_store_provider(name) {
        // An installed pack owns the name it installs, even when that name is
        // one the official pack publishes — `--profile claude` resolves to
        // that pack, so this run is not the official one.
        return target.keys().any(|key| key == pack_key);
    }
    is_official_profile_name(target, name)
}

fn is_official_profile_name(target: OfficialPackStatusTarget, name: &str) -> bool {
    target.profiles.contains(&name)
}

fn is_official_package_ref(target: OfficialPackStatusTarget, value: &str) -> bool {
    target
        .keys()
        .any(|key| value == key || value.starts_with(&format!("{key}@")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_env::{with_isolated_config_home, write_user_profile};
    use std::path::Path;

    /// No `--extends` on the command line.
    const NO_EXTENDS: &[String] = &[];

    /// "Is this run launching Claude Code?" — gates the sandbox preparation.
    fn selects_claude_code(name: &str) -> bool {
        profile_selects_claude_code(name, NO_EXTENDS)
    }

    /// "Does this run load the official claude pack?" — gates the yanked-pack
    /// check.
    fn loads_claude_pack(name: &str) -> bool {
        run_loads_official_pack(CLAUDE_PACK, name, NO_EXTENDS)
    }

    /// Install a fake pack providing one profile artifact under `install_as`,
    /// also answering to `aliases`.
    fn write_pack_profile(
        config_home: &Path,
        namespace: &str,
        pack_name: &str,
        install_as: &str,
        aliases: &[&str],
    ) {
        crate::test_env::write_fake_pack(
            config_home,
            namespace,
            pack_name,
            install_as,
            &format!(r#"{{ "meta": {{ "name": "{install_as}" }} }}"#),
            aliases,
            None,
        );
    }

    #[test]
    fn yanked_message_pins_latest_when_available() {
        let status = PackageStatusResponse {
            schema_version: 1,
            latest: Some("1.2.3".to_string()),
            installed_status: Some("yanked".to_string()),
            yank_reason: Some("security".to_string()),
            advisory: Some(package::PackageAdvisory {
                severity: Some("high".to_string()),
                summary: Some("profile policy fix".to_string()),
            }),
        };

        let message = yanked_message("nolabs-ai/claude", "1.2.2", &status);
        assert!(message.contains("nono pull nolabs-ai/claude@1.2.3 --force"));
        assert!(message.contains("security"));
        assert!(message.contains("high - profile policy fix"));
    }

    #[test]
    fn official_profile_names_include_claude_and_codex() {
        assert!(is_official_profile_name(CLAUDE_PACK, "claude"));
        assert!(is_official_profile_name(CLAUDE_PACK, "claude-code"));
        assert!(is_official_profile_name(CODEX_PACK, "codex"));
        assert!(!is_official_profile_name(CLAUDE_PACK, "codex"));
        assert!(!is_official_profile_name(CODEX_PACK, "claude"));
    }

    #[test]
    fn canonical_package_refs_target_official_packs() {
        assert!(is_official_package_ref(CLAUDE_PACK, "nolabs-ai/claude"));
        assert!(is_official_package_ref(
            CLAUDE_PACK,
            "nolabs-ai/claude@1.2.3"
        ));
        assert!(is_official_package_ref(CODEX_PACK, "nolabs-ai/codex"));
        assert!(is_official_package_ref(CODEX_PACK, "nolabs-ai/codex@1.2.3"));
        assert!(!is_official_package_ref(CLAUDE_PACK, "someone/claude"));
        assert!(!is_official_package_ref(
            CODEX_PACK,
            "nolabs-ai/codex-extra"
        ));
    }

    /// The claude pack predates the org rename, so an install or an `extends`
    /// written against the old namespace is still the official pack.
    #[test]
    fn legacy_namespace_refs_target_the_claude_pack() {
        assert!(is_official_package_ref(
            CLAUDE_PACK,
            "always-further/claude"
        ));
        assert!(is_official_package_ref(
            CLAUDE_PACK,
            "always-further/claude@1.2.3"
        ));
        assert!(!is_official_package_ref(CODEX_PACK, "always-further/codex"));
    }

    #[test]
    fn claude_pack_installed_under_the_legacy_namespace_selects_claude_code() {
        with_isolated_config_home(|config_home| {
            write_pack_profile(config_home, "always-further", "claude", "claude", &["cc"]);

            assert!(selects_claude_code("claude"));
            assert!(selects_claude_code("cc"));
            assert!(loads_claude_pack("claude"));
        });
    }

    #[test]
    fn claude_code_detection_covers_every_documented_profile_form() {
        with_isolated_config_home(|_config_home| {
            assert!(selects_claude_code("nolabs-ai/claude"));
            assert!(selects_claude_code("nolabs-ai/claude@1.2.3"));
            assert!(selects_claude_code("claude"));
            assert!(selects_claude_code("claude-code"));

            assert!(!selects_claude_code("default"));
            assert!(!selects_claude_code("codex"));
            assert!(!selects_claude_code("nolabs-ai/codex"));
            assert!(!selects_claude_code("someone-else/claude"));
        });
    }

    #[test]
    fn claude_code_detection_follows_extends_chain_to_a_pack_ref() {
        with_isolated_config_home(|config_home| {
            write_user_profile(
                config_home,
                "my-agent",
                r#"{
                    "meta": { "name": "my-agent" },
                    "extends": "nolabs-ai/claude"
                }"#,
            );

            assert!(
                selects_claude_code("my-agent"),
                "a user profile extending the pack ref must be treated as Claude Code"
            );
        });
    }

    /// Aliases live in the pack manifest, not in `CLAUDE_PACK.profiles`, so
    /// detection must ask the resolver instead of the hardcoded name list.
    #[test]
    fn claude_code_detection_covers_pack_manifest_aliases() {
        with_isolated_config_home(|config_home| {
            write_pack_profile(
                config_home,
                "nolabs-ai",
                "claude",
                "claude",
                &["claude-code", "cc"],
            );

            assert!(
                selects_claude_code("cc"),
                "an alias the installed claude pack answers to must be treated as Claude Code"
            );
        });
    }

    /// A pack that happens to publish a profile named `claude` is not the
    /// official pack, so its short name must not be mistaken for one.
    #[test]
    fn claude_code_detection_ignores_same_named_profile_from_another_pack() {
        with_isolated_config_home(|config_home| {
            write_pack_profile(config_home, "someone-else", "agent", "agent", &["kodu"]);

            assert!(!selects_claude_code("kodu"));
            assert!(!selects_claude_code("agent"));
        });
    }

    /// An installed pack owns the name it installs, even when that name is one
    /// the official pack is published under: `--profile claude` resolves to
    /// this third-party pack (user file -> pack store -> built-in), so treating
    /// it as Claude Code would relocate `~/.claude.json` for an unrelated
    /// profile.
    #[test]
    fn third_party_pack_installing_the_claude_name_does_not_select_claude_code() {
        with_isolated_config_home(|config_home| {
            write_pack_profile(config_home, "someone-else", "agent", "claude", &["cc"]);

            assert!(
                !selects_claude_code("claude"),
                "a third-party pack installed as `claude` must not be treated as Claude Code"
            );
            assert!(!selects_claude_code("cc"), "nor must one of its aliases");
        });
    }

    /// The published-name fallback still has to fire once the official pack is
    /// the one installed under that name.
    #[test]
    fn official_pack_installing_the_claude_name_selects_claude_code() {
        with_isolated_config_home(|config_home| {
            write_pack_profile(config_home, "nolabs-ai", "claude", "claude", &[]);

            assert!(selects_claude_code("claude"));
        });
    }

    /// A user profile file named after the pack shadows it, so the run never
    /// loads the pack — but it is still a Claude Code run and still needs the
    /// preparation. Regression for the repro in issue #1546, which writes
    /// exactly these files.
    #[test]
    fn user_override_of_a_published_name_still_selects_claude_code() {
        with_isolated_config_home(|config_home| {
            for name in ["claude", "claude-code"] {
                write_user_profile(
                    config_home,
                    name,
                    &format!(r#"{{ "meta": {{ "name": "{name}" }}, "extends": "default" }}"#),
                );

                assert!(
                    selects_claude_code(name),
                    "a user profile named `{name}` still launches Claude Code"
                );
                assert!(
                    !loads_claude_pack(name),
                    "but it shadows the pack, so the run does not load the pack"
                );
            }
        });
    }

    /// The override allowance is scoped to the names the pack publishes: an
    /// unrelated user profile must not be dragged in.
    #[test]
    fn user_override_of_an_unrelated_name_does_not_select_claude_code() {
        with_isolated_config_home(|config_home| {
            write_user_profile(
                config_home,
                "my-agent",
                r#"{ "meta": { "name": "my-agent" }, "extends": "default" }"#,
            );

            assert!(!selects_claude_code("my-agent"));
            assert!(!loads_claude_pack("my-agent"));
        });
    }

    #[test]
    fn user_override_extending_the_pack_still_selects_claude_code() {
        with_isolated_config_home(|config_home| {
            write_user_profile(
                config_home,
                "claude",
                r#"{ "meta": { "name": "claude" }, "extends": "nolabs-ai/claude" }"#,
            );

            assert!(
                selects_claude_code("claude"),
                "an override that extends the pack is still Claude Code"
            );
        });
    }

    /// `--extends` bases are resolved as if prepended to the selected
    /// profile's own `extends`, so a run that only reaches the pack that way
    /// still needs the Claude Code handling (and the pack status gate).
    #[test]
    fn cli_extends_reaching_the_pack_selects_claude_code() {
        with_isolated_config_home(|config_home| {
            write_user_profile(
                config_home,
                "vanilla",
                r#"{ "meta": { "name": "vanilla" }, "extends": "default" }"#,
            );
            write_user_profile(
                config_home,
                "wraps-claude",
                r#"{ "meta": { "name": "wraps-claude" }, "extends": "nolabs-ai/claude" }"#,
            );

            assert!(
                !profile_selects_claude_code("vanilla", NO_EXTENDS),
                "control: the selected profile alone does not reach the pack"
            );
            assert!(
                profile_selects_claude_code("vanilla", &["nolabs-ai/claude".to_string()]),
                "--extends naming the pack ref must be treated as Claude Code"
            );
            assert!(
                profile_selects_claude_code("vanilla", &["wraps-claude".to_string()]),
                "--extends whose own chain reaches the pack must be treated as Claude Code"
            );
            assert!(
                !profile_selects_claude_code(
                    "vanilla",
                    &["default".to_string(), "vanilla".to_string()]
                ),
                "unrelated --extends bases must not be treated as Claude Code"
            );
        });
    }
}
