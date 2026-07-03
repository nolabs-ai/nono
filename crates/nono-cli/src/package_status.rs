//! Runtime checks for security-sensitive official pack status.

use crate::package::{self, PackageRef, PackageStatusResponse};
use crate::profile;
use crate::registry_client::{RegistryClient, resolve_registry_url};
use nono::{NonoError, Result};

#[derive(Clone, Copy, Debug)]
struct OfficialPackStatusTarget {
    namespace: &'static str,
    name: &'static str,
    profiles: &'static [&'static str],
}

const CLAUDE_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nolabs-ai",
    name: "claude",
    profiles: &["claude", "claude-code"],
};

const CODEX_PACK: OfficialPackStatusTarget = OfficialPackStatusTarget {
    namespace: "nolabs-ai",
    name: "codex",
    profiles: &["codex"],
};

const OFFICIAL_PACK_STATUS_TARGETS: &[OfficialPackStatusTarget] = &[CLAUDE_PACK, CODEX_PACK];

impl OfficialPackStatusTarget {
    fn key(self) -> String {
        format!("{}/{}", self.namespace, self.name)
    }

    fn package_ref(self) -> PackageRef {
        PackageRef {
            namespace: self.namespace.to_string(),
            name: self.name.to_string(),
            version: None,
        }
    }
}

pub(crate) fn enforce_for_active_profile(profile_name: Option<&str>, silent: bool) -> Result<()> {
    let Some(profile_name) = profile_name else {
        return Ok(());
    };

    for target in OFFICIAL_PACK_STATUS_TARGETS {
        if depends_on_official_pack_profile(*target, profile_name) {
            enforce_official_pack_status(*target, silent)?;
        }
    }
    Ok(())
}

fn enforce_official_pack_status(target: OfficialPackStatusTarget, silent: bool) -> Result<()> {
    let lockfile = package::read_lockfile()?;
    let key = target.key();
    let Some(locked) = lockfile.packages.get(&key) else {
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

fn depends_on_official_pack_profile(target: OfficialPackStatusTarget, name_or_path: &str) -> bool {
    if is_official_package_ref(target, name_or_path) {
        return true;
    }
    if is_official_profile_name(target, name_or_path) && !profile::is_user_override(name_or_path) {
        return true;
    }
    depends_on_official_pack_profile_inner(target, name_or_path, &mut Vec::new())
}

fn depends_on_official_pack_profile_inner(
    target: OfficialPackStatusTarget,
    name_or_path: &str,
    visited: &mut Vec<String>,
) -> bool {
    if is_official_profile_name(target, name_or_path) {
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
        .any(|base| depends_on_official_pack_profile_inner(target, base, visited))
}

fn is_official_profile_name(target: OfficialPackStatusTarget, name: &str) -> bool {
    target.profiles.contains(&name)
}

fn is_official_package_ref(target: OfficialPackStatusTarget, value: &str) -> bool {
    let key = target.key();
    value == key || value.starts_with(&format!("{key}@"))
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
