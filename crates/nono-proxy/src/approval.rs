//! Approval backend routing for proxy endpoint-policy approvals.

use nono::{ApprovalBackend, NonoError};
use std::collections::BTreeMap;
use std::sync::Arc;

/// Prepare an approval reason for a human-readable tracing event. Structured
/// audit records retain the original reason; terminal-facing logs must not
/// carry control sequences or unbounded webhook output.
pub(crate) fn sanitize_reason_for_log(reason: &str) -> String {
    const MAX_LOG_REASON_CHARS: usize = 1024;
    const ELLIPSIS_CHARS: usize = 3;

    let mut chars = reason.chars().peekable();
    let mut sanitized = String::with_capacity(reason.len().min(MAX_LOG_REASON_CHARS));
    for _ in 0..MAX_LOG_REASON_CHARS - ELLIPSIS_CHARS {
        let Some(ch) = chars.next() else {
            return sanitized;
        };
        sanitized.push(if ch.is_control() { ' ' } else { ch });
    }
    if chars.peek().is_some() {
        sanitized.push_str("...");
    }
    sanitized
}

/// Named approval backend registry used by endpoint-policy `approve` routes.
#[derive(Clone, Default)]
pub struct ApprovalBackendRegistry {
    default_backend: Option<String>,
    backends: Arc<BTreeMap<String, Arc<dyn ApprovalBackend>>>,
}

impl ApprovalBackendRegistry {
    /// Build a registry from named backends and an optional default route.
    #[must_use]
    pub fn new(
        default_backend: Option<String>,
        backends: BTreeMap<String, Arc<dyn ApprovalBackend>>,
    ) -> Self {
        Self {
            default_backend,
            backends: Arc::new(backends),
        }
    }

    /// Build a compatibility registry for callers that have one backend.
    #[must_use]
    pub fn singleton(backend: Arc<dyn ApprovalBackend>) -> Self {
        let name = backend.backend_name().to_string();
        let mut backends = BTreeMap::new();
        backends.insert(name.clone(), backend);
        Self::new(Some(name), backends)
    }

    /// Resolve an explicit backend name or the registry default.
    ///
    /// # Errors
    ///
    /// Returns an error when no explicit/default backend exists or when the
    /// resolved backend name is not registered.
    pub fn resolve(
        &self,
        backend: Option<&str>,
    ) -> nono::Result<(String, Arc<dyn ApprovalBackend>)> {
        let name = backend
            .map(str::to_string)
            .or_else(|| self.default_backend.clone())
            .ok_or_else(|| NonoError::SandboxInit("missing approval backend".to_string()))?;
        let backend =
            self.backends.get(&name).cloned().ok_or_else(|| {
                NonoError::SandboxInit(format!("unknown approval backend '{name}'"))
            })?;
        Ok((name, backend))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestBackend {
        name: &'static str,
    }

    impl ApprovalBackend for TestBackend {
        fn request_approval(
            &self,
            _request: &nono::supervisor::ApprovalRequest,
        ) -> nono::Result<nono::ApprovalDecision> {
            Ok(nono::ApprovalDecision::Granted)
        }

        fn backend_name(&self) -> &str {
            self.name
        }
    }

    #[test]
    fn registry_resolves_explicit_and_default_backends() -> nono::Result<()> {
        let mut backends: BTreeMap<String, Arc<dyn ApprovalBackend>> = BTreeMap::new();
        backends.insert(
            "default".to_string(),
            Arc::new(TestBackend { name: "default" }),
        );
        backends.insert(
            "review".to_string(),
            Arc::new(TestBackend { name: "review" }),
        );
        let registry = ApprovalBackendRegistry::new(Some("default".to_string()), backends);

        let (name, _) = registry.resolve(None)?;
        assert_eq!(name, "default");
        let (name, _) = registry.resolve(Some("review"))?;
        assert_eq!(name, "review");

        Ok(())
    }

    #[test]
    fn registry_rejects_missing_default() {
        let registry = ApprovalBackendRegistry::new(None, BTreeMap::new());
        assert!(registry.resolve(None).is_err());
    }

    #[test]
    fn sanitize_reason_for_log_removes_controls_and_bounds_length() {
        let reason = format!("prefix\x1b]52;c;Y29weQ==\x07{}", "x".repeat(2000));

        let sanitized = sanitize_reason_for_log(&reason);

        assert!(!sanitized.chars().any(char::is_control));
        assert!(sanitized.chars().count() <= 1024);
        assert!(sanitized.ends_with("..."));
    }
}
