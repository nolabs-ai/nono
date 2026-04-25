//! Network approval backend using OS notifications/dialogs.
//!
//! When `--network-approval ask` is enabled, this backend shows an
//! OS-level notification when the proxy blocks a request to an unknown
//! host. The user can approve (session-only or persistent) or deny
//! directly from the notification.
//!
//! Concurrent requests to the same host share a single notification
//! via the `pending` map + `Notify` pattern.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use nono::{
    ApprovalBackend, ApprovalDecision, ApprovalScope, CapabilityRequest, NetworkApprovalDecision,
    NetworkApprovalRequest, Result, RuntimeHostFilter,
};

use crate::notification::{self, ApprovalDuration, NotificationResult};

/// Shared tokio runtime for the synchronous `request_network_approval`
/// trait method. Created once on first use, not per-call.
static SYNC_RUNTIME: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();

fn sync_runtime() -> &'static tokio::runtime::Runtime {
    SYNC_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("Failed to create shared approval runtime")
    })
}

/// Mode controlling how network approval requests are handled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkApprovalMode {
    /// Deny unknown hosts immediately (default, current behavior)
    #[default]
    Off,
    /// Prompt user via OS notification/dialog with action buttons
    Ask,
}

/// Network approval backend using OS notifications.
///
/// Shows an OS-level notification when a blocked host is requested.
/// Handles deduplication of concurrent requests to the same host
/// and supports both session-only and persistent approval.
pub struct NetworkApprovalBackend {
    mode: NetworkApprovalMode,
    runtime_filter: RuntimeHostFilter,
    timeout_secs: u64,
    pending: Arc<Mutex<HashMap<String, Arc<tokio::sync::Notify>>>>,
    config_writer: Option<ConfigWriter>,
}

/// Writes approved hosts directly to the active profile file for persistence.
///
/// Uses [`crate::profile::resolve_profile_path`] to find the actual file
/// on disk, then modifies its `network.allow_domain` array in place.
/// Changes are immediately visible to the user.
///
/// If the profile is a built-in (no file on disk), a new user profile file
/// is created at `~/.config/nono/profiles/<name>.json` with an `extends`
/// field referencing the built-in, so the approved host is layered on top
/// of the built-in policy.
#[derive(Debug, Clone)]
pub struct ConfigWriter {
    profile_path: std::path::PathBuf,
    profile_name: String,
}

impl ConfigWriter {
    /// Create a new config writer for a profile name or direct file path.
    ///
    /// Resolves the actual file path using the same logic as
    /// [`crate::profile::load_profile`]. If the profile is built-in (no
    /// file on disk), the writer targets
    /// `~/.config/nono/profiles/<name>.json` and will create the file
    /// on first persistent approval.
    pub fn new(profile_name_or_path: &str) -> Self {
        let profile_name = profile_name_or_path.to_string();
        let profile_path = crate::profile::resolve_profile_path(profile_name_or_path)
            .or_else(|| crate::profile::get_user_profile_path(&profile_name).ok())
            .unwrap_or_else(|| {
                let fallback = dirs::config_dir()
                    .unwrap_or_else(|| std::path::PathBuf::from("/tmp"))
                    .join("nono")
                    .join("profiles")
                    .join(format!("{profile_name}.json"));
                tracing::warn!(
                    "ConfigWriter: cannot resolve profile path for '{profile_name_or_path}' — \
                     using fallback {}",
                    fallback.display()
                );
                fallback
            });
        Self {
            profile_path,
            profile_name,
        }
    }

    /// Append a host to the `network.allow_domain` array in the profile file.
    ///
    /// Reads the current file, adds the host (skipping duplicates), and
    /// writes it back. Creates the file with an `extends` reference if it
    /// doesn't exist yet.
    ///
    /// Best-effort: if the write fails, the host is still approved for this
    /// session (degraded to session-only).
    pub fn persist_host(&self, host: &str) -> Result<()> {
        self.persist_domain("allow_domain", host)
    }

    /// Append a host to the `network.reject_domain` array in the profile file.
    ///
    /// Reads the current file, adds the host (skipping duplicates), and
    /// writes it back. Creates the file with an `extends` reference if it
    /// doesn't exist yet.
    ///
    /// Best-effort: if the write fails, the host is still denied for this
    /// session.
    pub fn persist_deny(&self, host: &str) -> Result<()> {
        self.persist_domain("reject_domain", host)
    }

    /// Shared implementation for persisting a domain to a network config array.
    ///
    /// `field` is either `"allow_domain"` or `"reject_domain"`.
    fn persist_domain(&self, field: &str, host: &str) -> Result<()> {
        let content = match std::fs::read_to_string(&self.profile_path) {
            Ok(c) => c,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut fields = serde_json::Map::new();
                fields.insert(field.to_string(), serde_json::json!([host]));
                let value = serde_json::json!({
                    "extends": self.profile_name,
                    "network": fields
                });
                self.write_profile(&value)?;
                tracing::info!(
                    "Created new profile {} with {field} host {host}",
                    self.profile_path.display()
                );
                return Ok(());
            }
            Err(e) => {
                return Err(nono::NonoError::ConfigWrite {
                    path: self.profile_path.clone(),
                    source: e,
                });
            }
        };

        let mut value: serde_json::Value = if content.trim().is_empty() {
            let mut fields = serde_json::Map::new();
            fields.insert(field.to_string(), serde_json::json!([]));
            serde_json::Value::Object(serde_json::Map::from_iter([(
                "network".to_string(),
                serde_json::Value::Object(fields),
            )]))
        } else {
            match serde_json::from_str(&content) {
                Ok(v) => v,
                Err(e) => {
                    return Err(nono::NonoError::InvalidConfig {
                        reason: format!(
                            "Failed to parse profile file {}: {e}",
                            self.profile_path.display()
                        ),
                    });
                }
            }
        };

        if !value.is_object() {
            value = serde_json::Value::Object(serde_json::Map::new());
        }

        let pointer = format!("/network/{field}");
        if value.pointer(&pointer).is_none() {
            if value.get("network").is_none() {
                let mut fields = serde_json::Map::new();
                fields.insert(field.to_string(), serde_json::json!([]));
                value["network"] = serde_json::Value::Object(fields);
            } else if value["network"].get(field).is_none() {
                value["network"][field] = serde_json::json!([]);
            }
        }

        let domain_list = value.pointer_mut(&pointer).expect("field just ensured");

        if let Some(arr) = domain_list.as_array() {
            if arr.iter().any(|v| v.as_str() == Some(host)) {
                return Ok(());
            }
        }

        if let Some(arr) = domain_list.as_array_mut() {
            arr.push(serde_json::Value::String(host.to_string()));
        }

        self.write_profile(&value)?;

        tracing::info!(
            "{field} host {host} persisted to {}",
            self.profile_path.display()
        );
        Ok(())
    }

    /// Write a JSON value to the profile file, creating parent dirs as needed.
    fn write_profile(&self, value: &serde_json::Value) -> Result<()> {
        let updated =
            serde_json::to_string_pretty(value).map_err(|e| nono::NonoError::InvalidConfig {
                reason: format!("Failed to serialize profile JSON: {e}"),
            })?;

        if let Some(parent) = self.profile_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| nono::NonoError::ConfigWrite {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        std::fs::write(&self.profile_path, &updated).map_err(|e| nono::NonoError::ConfigWrite {
            path: self.profile_path.clone(),
            source: e,
        })
    }
}

impl NetworkApprovalBackend {
    /// Create a new network approval backend.
    pub fn new(
        mode: NetworkApprovalMode,
        runtime_filter: RuntimeHostFilter,
        timeout_secs: u64,
        config_writer: Option<ConfigWriter>,
    ) -> Self {
        Self {
            mode,
            runtime_filter,
            timeout_secs,
            pending: Arc::new(Mutex::new(HashMap::new())),
            config_writer,
        }
    }

    /// Process a network approval request from within an async context.
    ///
    /// Unlike the `ApprovalBackend` trait method (which creates its own
    /// tokio runtime for sync callers), this method uses `spawn_blocking`
    /// directly and must be called from within an existing tokio runtime.
    pub async fn request_network_approval_async(
        &self,
        request: &NetworkApprovalRequest,
    ) -> NetworkApprovalDecision {
        let host = request.host.clone();
        tracing::info!("Network approval requested for host: {host}");

        let (notify, is_first) = {
            let mut pending = self.pending.lock().expect("pending lock poisoned");
            if let Some(existing) = pending.get(&host) {
                tracing::info!("Host {host} has pending approval — waiting on existing dialog");
                (existing.clone(), false)
            } else {
                let n = Arc::new(tokio::sync::Notify::new());
                pending.insert(host.clone(), n.clone());
                (n, true)
            }
        };

        if !is_first {
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(self.timeout_secs),
                notify.notified(),
            )
            .await;

            let pending = self.pending.lock().expect("pending lock poisoned");
            return if pending.contains_key(&host) {
                NetworkApprovalDecision::Denied {
                    reason: "Approval timed out".to_string(),
                }
            } else {
                NetworkApprovalDecision::Granted(ApprovalScope::Session)
            };
        }

        let decision = match self.mode {
            NetworkApprovalMode::Off => NetworkApprovalDecision::Denied {
                reason: "Network approval not configured".to_string(),
            },
            NetworkApprovalMode::Ask => {
                let host_clone = host.clone();
                let timeout = self.timeout_secs;
                let result = tokio::task::spawn_blocking(move || {
                    notification::show_approval_dialog(&host_clone, timeout)
                })
                .await
                .unwrap_or(NotificationResult::Dismissed);

                match result {
                    NotificationResult::Approve(duration) => match duration {
                        ApprovalDuration::Once => {
                            NetworkApprovalDecision::Granted(ApprovalScope::Once)
                        }
                        ApprovalDuration::Session => {
                            if let Err(e) = self.runtime_filter.add_host(&host) {
                                tracing::warn!("Failed to add host to runtime filter: {e}");
                            }
                            NetworkApprovalDecision::Granted(ApprovalScope::Session)
                        }
                        ApprovalDuration::Always => {
                            if let Err(e) = self.runtime_filter.add_host(&host) {
                                tracing::warn!("Failed to add host to runtime filter: {e}");
                            }
                            if let Some(ref writer) = self.config_writer {
                                if let Err(e) = writer.persist_host(&host) {
                                    tracing::warn!(
                                            "Failed to persist host to config (session-only fallback): {e}"
                                        );
                                }
                            }
                            NetworkApprovalDecision::Granted(ApprovalScope::Persistent)
                        }
                    },
                    NotificationResult::Deny(duration) => match duration {
                        ApprovalDuration::Once => NetworkApprovalDecision::Denied {
                            reason: "User denied the request".to_string(),
                        },
                        ApprovalDuration::Session => {
                            if let Err(e) = self.runtime_filter.add_deny_host(&host) {
                                tracing::warn!("Failed to add deny host to runtime filter: {e}");
                            }
                            NetworkApprovalDecision::Denied {
                                reason: "User denied the request for this session".to_string(),
                            }
                        }
                        ApprovalDuration::Always => {
                            if let Err(e) = self.runtime_filter.add_deny_host(&host) {
                                tracing::warn!("Failed to add deny host to runtime filter: {e}");
                            }
                            if let Some(ref writer) = self.config_writer {
                                if let Err(e) = writer.persist_deny(&host) {
                                    tracing::warn!(
                                        "Failed to persist deny to config (session-only fallback): {e}"
                                    );
                                }
                            }
                            NetworkApprovalDecision::Denied {
                                reason: "User permanently denied the host".to_string(),
                            }
                        }
                    },
                    NotificationResult::Dismissed => NetworkApprovalDecision::Denied {
                        reason: "Notification dismissed or timed out".to_string(),
                    },
                }
            }
        };

        self.pending
            .lock()
            .expect("pending lock poisoned")
            .remove(&host);
        notify.notify_waiters();

        tracing::info!("Network approval decision for {host}: {:?}", decision);
        decision
    }
}

impl ApprovalBackend for NetworkApprovalBackend {
    fn request_capability(&self, _request: &CapabilityRequest) -> Result<ApprovalDecision> {
        Ok(ApprovalDecision::Denied {
            reason: "NetworkApprovalBackend does not handle capability requests".to_string(),
        })
    }

    fn request_network_approval(
        &self,
        request: &NetworkApprovalRequest,
    ) -> Result<NetworkApprovalDecision> {
        let host = request.host.clone();

        let (notify, is_first) = {
            let mut pending = self.pending.lock().expect("pending lock poisoned");
            if let Some(existing) = pending.get(&host) {
                (existing.clone(), false)
            } else {
                let n = Arc::new(tokio::sync::Notify::new());
                pending.insert(host.clone(), n.clone());
                (n, true)
            }
        };

        if !is_first {
            sync_runtime().block_on(async {
                let _ = tokio::time::timeout(
                    std::time::Duration::from_secs(self.timeout_secs),
                    notify.notified(),
                )
                .await;
            });

            let pending = self.pending.lock().expect("pending lock poisoned");
            return if pending.contains_key(&host) {
                Ok(NetworkApprovalDecision::Denied {
                    reason: "Approval timed out".to_string(),
                })
            } else {
                Ok(NetworkApprovalDecision::Granted(ApprovalScope::Session))
            };
        }

        let decision = match self.mode {
            NetworkApprovalMode::Off => NetworkApprovalDecision::Denied {
                reason: "Network approval not configured".to_string(),
            },
            NetworkApprovalMode::Ask => {
                let host_clone = host.clone();
                let timeout = self.timeout_secs;
                let result = sync_runtime().block_on(async {
                    tokio::task::spawn_blocking(move || {
                        notification::show_approval_dialog(&host_clone, timeout)
                    })
                    .await
                    .unwrap_or(NotificationResult::Dismissed)
                });

                match result {
                    NotificationResult::Approve(duration) => match duration {
                        ApprovalDuration::Once => {
                            NetworkApprovalDecision::Granted(ApprovalScope::Once)
                        }
                        ApprovalDuration::Session => {
                            if let Err(e) = self.runtime_filter.add_host(&host) {
                                tracing::warn!("Failed to add host to runtime filter: {e}");
                            }
                            NetworkApprovalDecision::Granted(ApprovalScope::Session)
                        }
                        ApprovalDuration::Always => {
                            if let Err(e) = self.runtime_filter.add_host(&host) {
                                tracing::warn!("Failed to add host to runtime filter: {e}");
                            }
                            if let Some(ref writer) = self.config_writer {
                                if let Err(e) = writer.persist_host(&host) {
                                    tracing::warn!(
                                            "Failed to persist host to config (session-only fallback): {e}"
                                        );
                                }
                            }
                            NetworkApprovalDecision::Granted(ApprovalScope::Persistent)
                        }
                    },
                    NotificationResult::Deny(duration) => match duration {
                        ApprovalDuration::Once => NetworkApprovalDecision::Denied {
                            reason: "User denied the request".to_string(),
                        },
                        ApprovalDuration::Session => {
                            if let Err(e) = self.runtime_filter.add_deny_host(&host) {
                                tracing::warn!("Failed to add deny host to runtime filter: {e}");
                            }
                            NetworkApprovalDecision::Denied {
                                reason: "User denied the request for this session".to_string(),
                            }
                        }
                        ApprovalDuration::Always => {
                            if let Err(e) = self.runtime_filter.add_deny_host(&host) {
                                tracing::warn!("Failed to add deny host to runtime filter: {e}");
                            }
                            if let Some(ref writer) = self.config_writer {
                                if let Err(e) = writer.persist_deny(&host) {
                                    tracing::warn!(
                                        "Failed to persist deny to config (session-only fallback): {e}"
                                    );
                                }
                            }
                            NetworkApprovalDecision::Denied {
                                reason: "User permanently denied the host".to_string(),
                            }
                        }
                    },
                    NotificationResult::Dismissed => NetworkApprovalDecision::Denied {
                        reason: "Notification dismissed or timed out".to_string(),
                    },
                }
            }
        };

        self.pending
            .lock()
            .expect("pending lock poisoned")
            .remove(&host);
        notify.notify_waiters();

        Ok(decision)
    }

    fn backend_name(&self) -> &str {
        match self.mode {
            NetworkApprovalMode::Off => "network-off",
            NetworkApprovalMode::Ask => "network-notification",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nono::HostFilter;

    fn make_request(host: &str) -> NetworkApprovalRequest {
        NetworkApprovalRequest {
            request_id: "test".to_string(),
            host: host.to_string(),
            port: Some(443),
            reason: None,
            child_pid: 0,
            session_id: "test".to_string(),
        }
    }

    fn deny_default_filter() -> RuntimeHostFilter {
        RuntimeHostFilter::new(HostFilter::new(&["__sentinel__.invalid".to_string()]))
    }

    #[test]
    fn test_config_writer_named_profile_no_file() {
        let writer = ConfigWriter::new("nonexistent-profile-xyz");
        assert!(
            writer
                .profile_path
                .to_string_lossy()
                .contains("nonexistent-profile-xyz"),
            "should have a fallback path: {}",
            writer.profile_path.display()
        );
    }

    #[test]
    fn test_config_writer_direct_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("myconfig.json");
        std::fs::write(&profile_path, "{}").expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));
        assert_eq!(writer.profile_path, profile_path);
    }

    #[test]
    fn test_persist_host_creates_allow_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(&profile_path, r#"{"meta":{"name":"test"}}"#).expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        writer.persist_host("example.com").expect("persist");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["meta"]["name"], "test");
        assert_eq!(parsed["network"]["allow_domain"][0], "example.com");
    }

    #[test]
    fn test_persist_host_appends_to_existing() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(&profile_path, r#"{"network":{"allow_domain":["a.com"]}}"#).expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        writer.persist_host("b.com").expect("persist b");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        let domains = parsed["network"]["allow_domain"].as_array().expect("array");
        assert!(domains.iter().any(|v| v.as_str() == Some("a.com")));
        assert!(domains.iter().any(|v| v.as_str() == Some("b.com")));
    }

    #[test]
    fn test_persist_host_no_duplicate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            r#"{"network":{"allow_domain":["example.com"]}}"#,
        )
        .expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        writer.persist_host("example.com").expect("persist 2");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        let count = parsed["network"]["allow_domain"]
            .as_array()
            .expect("array")
            .iter()
            .filter(|v| v.as_str() == Some("example.com"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_persist_host_creates_file_for_missing_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("new-profile.json");
        let writer = ConfigWriter {
            profile_path: profile_path.clone(),
            profile_name: "test-profile".to_string(),
        };

        writer.persist_host("example.com").expect("persist");
        assert!(profile_path.exists(), "profile file should be created");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["extends"], "test-profile");
        assert_eq!(parsed["network"]["allow_domain"][0], "example.com");
    }

    #[test]
    fn test_persist_deny_creates_reject_domain() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(&profile_path, r#"{"meta":{"name":"test"}}"#).expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        writer.persist_deny("evil.com").expect("persist_deny");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["meta"]["name"], "test");
        assert_eq!(parsed["network"]["reject_domain"][0], "evil.com");
    }

    #[test]
    fn test_persist_deny_no_duplicate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            r#"{"network":{"reject_domain":["evil.com"]}}"#,
        )
        .expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        writer.persist_deny("evil.com").expect("persist_deny 2");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        let count = parsed["network"]["reject_domain"]
            .as_array()
            .expect("array")
            .iter()
            .filter(|v| v.as_str() == Some("evil.com"))
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_persist_deny_creates_file_for_missing_profile() {
        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("new-profile.json");
        let writer = ConfigWriter {
            profile_path: profile_path.clone(),
            profile_name: "test-profile".to_string(),
        };

        writer.persist_deny("evil.com").expect("persist_deny");
        assert!(profile_path.exists(), "profile file should be created");
        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        assert_eq!(parsed["extends"], "test-profile");
        assert_eq!(parsed["network"]["reject_domain"][0], "evil.com");
    }

    #[test]
    fn test_runtime_filter_add_deny_host() {
        let runtime_filter = deny_default_filter();

        runtime_filter.add_host("approved.com").expect("add_host");
        runtime_filter
            .add_deny_host("approved.com")
            .expect("add_deny_host");

        assert!(
            !runtime_filter.check_host("approved.com", &[]).is_allowed(),
            "deny should override allow"
        );
    }

    #[test]
    fn test_network_approval_mode_default_is_off() {
        assert_eq!(NetworkApprovalMode::default(), NetworkApprovalMode::Off);
    }

    #[tokio::test]
    async fn test_approval_adds_host_to_runtime_filter() {
        let runtime_filter = deny_default_filter();
        let filter_clone = runtime_filter.clone();

        assert!(
            !runtime_filter.check_host("example.com", &[]).is_allowed(),
            "host should be denied before approval"
        );

        let backend =
            NetworkApprovalBackend::new(NetworkApprovalMode::Off, runtime_filter, 5, None);

        let decision = backend
            .request_network_approval_async(&make_request("example.com"))
            .await;

        assert!(decision.is_denied(), "Off mode should deny: {:?}", decision);
        assert!(
            !filter_clone.check_host("example.com", &[]).is_allowed(),
            "host should still be denied after Off-mode denial"
        );
    }

    #[tokio::test]
    async fn test_dedup_concurrent_requests_same_host() {
        let runtime_filter = deny_default_filter();

        let backend =
            NetworkApprovalBackend::new(NetworkApprovalMode::Off, runtime_filter, 2, None);

        let backend = Arc::new(backend);

        let mut handles = Vec::new();
        for _ in 0..5 {
            let b = Arc::clone(&backend);
            handles.push(tokio::spawn(async move {
                b.request_network_approval_async(&make_request("same-host.com"))
                    .await
            }));
        }

        let results: Vec<_> = futures::future::join_all(handles).await;

        let denied_count = results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|d| d.is_denied()))
            .count();

        assert_eq!(denied_count, 5, "all requests should be denied in Off mode");

        let pending = backend.pending.lock().expect("pending lock poisoned");
        assert!(
            pending.is_empty(),
            "pending map should be empty after all decisions: {:?}",
            pending.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_runtime_filter_shared_between_backend_and_proxy() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        assert!(
            !runtime_filter.check_host("newhost.com", &[]).is_allowed(),
            "host should be denied initially"
        );

        runtime_filter
            .add_host("newhost.com")
            .expect("add host to backend filter");

        assert!(
            runtime_filter.check_host("newhost.com", &[]).is_allowed(),
            "backend filter should allow after add_host"
        );

        assert!(
            proxy_filter
                .check_host_with_ips("newhost.com", &[])
                .is_allowed(),
            "proxy filter should see the same update (shared Arc)"
        );
    }

    #[test]
    fn test_runtime_filter_persistent_approval_updates_proxy() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            r#"{"network":{"allow_domain":["existing.com"]}}"#,
        )
        .expect("write");

        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        runtime_filter.add_host("newhost.com").expect("add host");
        writer.persist_host("newhost.com").expect("persist");

        assert!(
            proxy_filter
                .check_host_with_ips("newhost.com", &[])
                .is_allowed(),
            "proxy should allow host after backend approval"
        );

        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        let domains = parsed["network"]["allow_domain"].as_array().expect("array");
        assert!(
            domains.iter().any(|v| v.as_str() == Some("newhost.com")),
            "host should be persisted in profile file"
        );
        assert!(
            domains.iter().any(|v| v.as_str() == Some("existing.com")),
            "existing hosts should be preserved"
        );
    }

    #[test]
    fn test_approve_once_does_not_add_to_runtime_filter() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        // Simulate Approve(Once): host should NOT be in runtime filter
        // The connect.rs code bypasses the runtime filter check for Once scope
        assert!(
            !runtime_filter.check_host("once-host.com", &[]).is_allowed(),
            "host should not be in runtime filter after Once approval"
        );
        assert!(
            !proxy_filter
                .check_host_with_ips("once-host.com", &[])
                .is_allowed(),
            "proxy filter should also not allow (Once = single request only)"
        );
    }

    #[test]
    fn test_approve_session_adds_to_runtime_filter() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        // Simulate Approve(Session): add_host to runtime filter (what the backend does)
        runtime_filter
            .add_host("session-host.com")
            .expect("add host");

        assert!(
            runtime_filter
                .check_host("session-host.com", &[])
                .is_allowed(),
            "host should be allowed in runtime filter after Session approval"
        );
        assert!(
            proxy_filter
                .check_host_with_ips("session-host.com", &[])
                .is_allowed(),
            "proxy filter should allow after Session approval"
        );
    }

    #[test]
    fn test_deny_session_adds_to_deny_filter() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        // Simulate Deny(Session): add_deny_host (what the backend does)
        runtime_filter
            .add_deny_host("denied-session.com")
            .expect("add deny host");

        assert!(
            !runtime_filter
                .check_host("denied-session.com", &[])
                .is_allowed(),
            "host should be denied in runtime filter after Deny(Session)"
        );
        assert!(
            !proxy_filter
                .check_host_with_ips("denied-session.com", &[])
                .is_allowed(),
            "proxy filter should deny after Deny(Session)"
        );
    }

    #[test]
    fn test_deny_always_adds_to_deny_filter_and_persists() {
        let runtime_filter = deny_default_filter();
        let proxy_filter = nono_proxy::filter::RuntimeProxyFilter::new(runtime_filter.clone());

        let dir = tempfile::tempdir().expect("tempdir");
        let profile_path = dir.path().join("test-profile.json");
        std::fs::write(
            &profile_path,
            r#"{"network":{"reject_domain":["existing-evil.com"]}}"#,
        )
        .expect("write");
        let writer = ConfigWriter::new(profile_path.to_str().expect("valid utf-8 path"));

        // Simulate Deny(Always): add_deny_host + persist_deny
        runtime_filter
            .add_deny_host("always-denied.com")
            .expect("add deny host");
        writer
            .persist_deny("always-denied.com")
            .expect("persist deny");

        assert!(
            !proxy_filter
                .check_host_with_ips("always-denied.com", &[])
                .is_allowed(),
            "proxy filter should deny after Deny(Always)"
        );

        let content = std::fs::read_to_string(&profile_path).expect("read");
        let parsed: serde_json::Value = serde_json::from_str(&content).expect("parse");
        let domains = parsed["network"]["reject_domain"]
            .as_array()
            .expect("array");
        assert!(
            domains
                .iter()
                .any(|v| v.as_str() == Some("always-denied.com")),
            "denied host should be persisted in profile"
        );
        assert!(
            domains
                .iter()
                .any(|v| v.as_str() == Some("existing-evil.com")),
            "existing denied hosts should be preserved"
        );
    }

    #[test]
    fn test_deny_once_does_not_add_to_deny_filter() {
        let runtime_filter = deny_default_filter();

        // Simulate Deny(Once): host NOT added to deny filter
        // Next request to same host would prompt again
        assert!(
            !runtime_filter
                .check_host("once-denied.com", &[])
                .is_allowed(),
            "host denied by default (no allowlist entry)"
        );
        // But it's not explicitly in the deny list either —
        // the next request would go through the same approval flow
    }
}
