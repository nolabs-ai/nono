//! Pack update hints for `nono run`.
//!
//! After the capabilities block, checks whether any pack-provided profile in
//! the active extends chain has a newer version available, and prints a one-line
//! hint if so. Results are cached per pack for 24 hours in the state directory
//! so the registry check never blocks startup. A background thread refreshes
//! stale entries for the next run.
//!
//! Respects the same opt-out as the CLI update check: `NONO_NO_UPDATE_CHECK=1`
//! or `[updates] check = false` in `~/.config/nono/config.toml`.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::thread;

const HINTS_STATE_FILE: &str = "pack-update-hints.json";
const CHECK_INTERVAL_SECS: i64 = 86400;

/// Per-pack cache entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PackHintEntry {
    last_check: DateTime<Utc>,
    /// The installed version recorded at the time of the last check.
    installed_at_check: String,
    /// Latest registry version at check time. `None` if the check failed.
    latest: Option<String>,
}

/// Full cache state stored on disk.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct PackHintsState {
    /// Keyed by `"namespace/name"`.
    #[serde(default)]
    entries: HashMap<String, PackHintEntry>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Print update hints for every pack-provided profile in the active extends
/// chain, reading from a 24-hour local cache.
///
/// Silently no-ops on any error (network, I/O, parse). A background thread
/// refreshes stale cache entries without blocking the current run.
pub fn show_pack_update_hints(profile_name: &str, silent: bool) {
    if silent || is_opted_out() {
        return;
    }

    let packs = collect_profile_packs(profile_name);
    if packs.is_empty() {
        return;
    }

    let cache_existed = state_file_path().is_some_and(|p| p.exists());
    let mut state = load_state();
    let now = Utc::now();

    let mut hints: Vec<(String, String, String)> = Vec::new(); // (pack_ref, installed, latest)
    let mut stale: Vec<(String, String)> = Vec::new(); // (pack_ref, installed)

    for (pack_ref, installed) in &packs {
        match state.entries.get(pack_ref) {
            Some(entry)
                if now.signed_duration_since(entry.last_check).num_seconds()
                    < CHECK_INTERVAL_SECS =>
            {
                // Cache is fresh — use it.
                if let Some(ref latest) = entry.latest {
                    if is_newer(installed, latest) {
                        hints.push((pack_ref.clone(), installed.clone(), latest.clone()));
                    }
                }
            }
            _ => {
                stale.push((pack_ref.clone(), installed.clone()));
            }
        }
    }

    if !stale.is_empty() {
        if !cache_existed {
            // No cache file at all — first run after install or CLI upgrade.
            // Do a synchronous check so the hint is visible immediately rather
            // than silently deferring to the next run.
            refresh_synchronous(&stale, &mut state);
            save_state(&state);
            for (pack_ref, installed) in &stale {
                if let Some(entry) = state.entries.get(pack_ref) {
                    if let Some(ref latest) = entry.latest {
                        if is_newer(installed, latest) {
                            hints.push((pack_ref.clone(), installed.clone(), latest.clone()));
                        }
                    }
                }
            }
        } else {
            // Cache exists but some entries are stale — refresh in background
            // so startup latency is unaffected.
            let shared = Arc::new(Mutex::new(state));
            refresh_in_background(stale, shared);
        }
    }

    print_hints(&hints);
}

// ---------------------------------------------------------------------------
// Extends-chain pack collection
// ---------------------------------------------------------------------------

/// Walk the extends chain from `profile_name` and return
/// `(pack_ref, installed_version)` for each pack-provided profile encountered.
///
/// User and builtin profiles in the chain are walked but not collected — only
/// entries that map to an installed pack are returned.
fn collect_profile_packs(profile_name: &str) -> Vec<(String, String)> {
    let pack_map: HashMap<String, String> = crate::profile::list_pack_store_profiles()
        .into_iter()
        .collect();

    let lockfile = match crate::package::read_lockfile() {
        Ok(lf) => lf,
        Err(_) => return Vec::new(),
    };

    let mut result: Vec<(String, String)> = Vec::new();
    let mut seen_packs: HashSet<String> = HashSet::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue = vec![profile_name.to_string()];

    while let Some(name) = queue.pop() {
        if !visited.insert(name.clone()) {
            continue;
        }
        if let Some(pack_ref) = pack_map.get(&name) {
            if seen_packs.insert(pack_ref.clone()) {
                if let Some(locked) = lockfile.packages.get(pack_ref) {
                    result.push((pack_ref.clone(), locked.version.clone()));
                }
            }
        }
        // Walk extends for all profiles, pack-provided or not, so a user
        // profile that extends a pack profile is handled correctly.
        if let Some(bases) = crate::profile::load_profile_extends(&name) {
            queue.extend(bases);
        }
    }

    result
}

// ---------------------------------------------------------------------------
// Background refresh
// ---------------------------------------------------------------------------

fn refresh_synchronous(packs: &[(String, String)], state: &mut PackHintsState) {
    let registry_url = crate::registry_client::resolve_registry_url(None);
    let client = crate::registry_client::RegistryClient::new(registry_url);
    for (pack_ref, installed) in packs {
        let pkg_ref = match crate::package::parse_package_ref(pack_ref) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let latest = client
            .fetch_package_status(&pkg_ref, Some(installed))
            .ok()
            .and_then(|s| s.latest);
        state.entries.insert(
            pack_ref.clone(),
            PackHintEntry {
                last_check: Utc::now(),
                installed_at_check: installed.clone(),
                latest,
            },
        );
    }
}

fn refresh_in_background(stale: Vec<(String, String)>, state: Arc<Mutex<PackHintsState>>) {
    let registry_url = crate::registry_client::resolve_registry_url(None);
    let _ = thread::spawn(move || {
        let client = crate::registry_client::RegistryClient::new(registry_url);
        let mut changed = false;

        for (pack_ref, installed) in stale {
            let pkg_ref = match crate::package::parse_package_ref(&pack_ref) {
                Ok(r) => r,
                Err(_) => continue,
            };
            let latest = client
                .fetch_package_status(&pkg_ref, Some(&installed))
                .ok()
                .and_then(|s| s.latest_version);

            if let Ok(mut guard) = state.lock() {
                guard.entries.insert(
                    pack_ref,
                    PackHintEntry {
                        last_check: Utc::now(),
                        installed_at_check: installed,
                        latest,
                    },
                );
                changed = true;
            }
        }

        if changed {
            if let Ok(guard) = state.lock() {
                save_state(&guard);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

fn print_hints(hints: &[(String, String, String)]) {
    if hints.is_empty() {
        return;
    }
    let t = crate::theme::current();
    for (pack_ref, installed, latest) in hints {
        eprintln!(
            "  {} {}  {} {} {}",
            crate::theme::fg("update available", t.yellow),
            crate::theme::fg(pack_ref, t.text),
            crate::theme::fg(&format!("{installed} →"), t.subtext),
            crate::theme::fg(latest, t.green),
            crate::theme::fg(" run: nono update", t.subtext),
        );
    }
    eprintln!();
}

// ---------------------------------------------------------------------------
// Cache I/O
// ---------------------------------------------------------------------------

fn state_file_path() -> Option<std::path::PathBuf> {
    crate::package::nono_config_dir()
        .ok()
        .map(|d| d.join(HINTS_STATE_FILE))
}

fn load_state() -> PackHintsState {
    let path = match state_file_path() {
        Some(p) => p,
        None => return PackHintsState::default(),
    };
    std::fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(state: &PackHintsState) {
    let path = match state_file_path() {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(state) {
        let _ = std::fs::write(&path, json);
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn is_opted_out() -> bool {
    if std::env::var("NONO_NO_UPDATE_CHECK").is_ok() {
        return true;
    }
    match crate::config::user::load_user_config() {
        Ok(Some(config)) => !config.updates.check,
        _ => false,
    }
}

fn is_newer(installed: &str, latest: &str) -> bool {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let mut parts = s.splitn(4, '.');
        let major: u64 = parts.next()?.parse().ok()?;
        let minor: u64 = parts.next()?.parse().ok()?;
        let patch: u64 = parts.next()?.parse().ok()?;
        Some((major, minor, patch))
    };
    match (parse(installed), parse(latest)) {
        (Some(i), Some(l)) => l > i,
        _ => false,
    }
}
