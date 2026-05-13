//! Version tracking for downgrade protection
//!
//! Prevents attackers from replacing current security lists with older
//! (but still validly signed) versions.

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use nono::{NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

/// Version state file name
const VERSION_STATE_FILE: &str = "versions.json";

/// Version tracking for a single config source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionState {
    /// Monotonic version number (must never decrease)
    pub version: u64,
    /// When this version was last seen
    pub last_seen: DateTime<Utc>,
    /// Source of the config (embedded, system, user)
    pub source: String,
}

/// All tracked version states
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct VersionTracker {
    /// Map of config name to version state
    #[serde(flatten)]
    pub configs: HashMap<String, VersionState>,
}

impl VersionTracker {
    /// Load version tracker from state directory
    pub fn load() -> Result<Self> {
        let path = Self::state_file_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(&path).map_err(|e| NonoError::ConfigRead {
            path: path.clone(),
            source: e,
        })?;

        serde_json::from_str(&content)
            .map_err(|e| NonoError::ConfigParse(format!("Failed to parse version state: {}", e)))
    }

    /// Save version tracker to state directory
    pub fn save(&self) -> Result<()> {
        let path = Self::state_file_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| NonoError::ConfigWrite {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let content = serde_json::to_string_pretty(self).map_err(|e| {
            NonoError::ConfigParse(format!("Failed to serialize version state: {}", e))
        })?;

        fs::write(&path, content).map_err(|e| NonoError::ConfigWrite { path, source: e })?;

        Ok(())
    }

    /// Check if a version is allowed (not a downgrade)
    ///
    /// Returns Ok(()) if version is acceptable, Err if it's a downgrade attack.
    pub fn check_version(&self, name: &str, version: u64) -> Result<()> {
        if let Some(state) = self.configs.get(name)
            && version < state.version
        {
            return Err(NonoError::VersionDowngrade {
                config: name.to_string(),
                current: state.version,
                attempted: version,
            });
        }
        Ok(())
    }

    /// Update tracked version for a config
    pub fn update_version(&mut self, name: &str, version: u64, source: &str) {
        let now = Utc::now();

        // Only update if version is >= current (already validated by check_version)
        self.configs.insert(
            name.to_string(),
            VersionState {
                version,
                last_seen: now,
                source: source.to_string(),
            },
        );
    }

    /// Get the state file path
    fn state_file_path() -> Result<PathBuf> {
        let state_dir = super::user_state_dir().ok_or_else(|| {
            NonoError::ConfigParse("Could not determine user state directory".to_string())
        })?;

        Ok(state_dir.join(VERSION_STATE_FILE))
    }
}

/// Check version and update tracker atomically
pub fn check_and_update_version(name: &str, version: u64, source: &str) -> Result<()> {
    let mut tracker = VersionTracker::load()?;

    // Check for downgrade
    tracker.check_version(name, version)?;

    // Update and save
    tracker.update_version(name, version, source);
    tracker.save()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_check_new() {
        let tracker = VersionTracker::default();

        // New config should always pass
        assert!(tracker.check_version("test", 1).is_ok());
        assert!(tracker.check_version("test", 100).is_ok());
    }

    #[test]
    fn test_version_check_upgrade() {
        let mut tracker = VersionTracker::default();
        tracker.update_version("test", 5, "embedded");

        // Same or higher version should pass
        assert!(tracker.check_version("test", 5).is_ok());
        assert!(tracker.check_version("test", 6).is_ok());
        assert!(tracker.check_version("test", 100).is_ok());
    }

    #[test]
    fn test_version_check_downgrade() {
        let mut tracker = VersionTracker::default();
        tracker.update_version("test", 5, "embedded");

        // Lower version should fail
        let result = tracker.check_version("test", 4);
        assert!(result.is_err());

        if let Err(NonoError::VersionDowngrade {
            config,
            current,
            attempted,
        }) = result
        {
            assert_eq!(config, "test");
            assert_eq!(current, 5);
            assert_eq!(attempted, 4);
        } else {
            panic!("Expected VersionDowngrade error");
        }
    }

    #[test]
    fn test_update_version() {
        let mut tracker = VersionTracker::default();

        tracker.update_version("test", 1, "embedded");
        assert_eq!(
            tracker
                .configs
                .get("test")
                .expect("config not found")
                .version,
            1
        );

        tracker.update_version("test", 5, "system");
        assert_eq!(
            tracker
                .configs
                .get("test")
                .expect("config not found")
                .version,
            5
        );
        assert_eq!(
            tracker
                .configs
                .get("test")
                .expect("config not found")
                .source,
            "system"
        );
    }
}
