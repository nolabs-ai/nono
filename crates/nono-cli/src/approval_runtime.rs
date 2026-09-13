use crate::command_policy::{
    ApprovalBackendConfig, ApprovalBackendType, ApprovalChainMode, CommandPoliciesConfig,
};
use crate::network_approval::NetworkApprovalBackend;
use crate::terminal_approval::TerminalApproval;
use nono::supervisor::ApprovalRequest;
use nono::{ApprovalBackend, ApprovalDecision, NonoError, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

const WEBHOOK_RESPONSE_LIMIT_BYTES: u64 = 64 * 1024;

pub(crate) fn build_proxy_approval_registry(
    config: Option<&CommandPoliciesConfig>,
) -> Result<Option<nono_proxy::approval::ApprovalBackendRegistry>> {
    let Some(config) = config else {
        return Ok(None);
    };
    if config.approval_backends.is_empty() {
        return Ok(None);
    }

    Ok(Some(build_approval_registry_from(
        &config.approval_backends,
        config.approval_defaults.backend.clone(),
    )?))
}

pub(crate) fn build_approval_registry(
    config: &CommandPoliciesConfig,
) -> Result<nono_proxy::approval::ApprovalBackendRegistry> {
    build_approval_registry_from(
        &config.approval_backends,
        config.approval_defaults.backend.clone(),
    )
}

/// Build an approval registry from a raw backend map and an optional default
/// backend name. Shared by the `command_policies` path and the profile
/// `security.approval_backends` path so both surfaces resolve backends through
/// the same builder (including chain-cycle detection and webhook construction).
pub(crate) fn build_approval_registry_from(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    default_backend_name: Option<String>,
) -> Result<nono_proxy::approval::ApprovalBackendRegistry> {
    let built = build_approval_backends_from(backends)?;
    Ok(nono_proxy::approval::ApprovalBackendRegistry::new(
        default_backend_name,
        built,
    ))
}

/// Work out which approval backend should answer supervised-mode file and
/// capability prompts, based on the profile `security` section.
///
/// Returns `Ok(None)` when nothing is configured, so the caller keeps the
/// interactive terminal prompt (existing behavior is unchanged). When a backend
/// IS configured, any failure to build it or pick the default is a hard error —
/// we never quietly fall back to the weaker terminal prompt.
pub(crate) fn resolve_supervised_approval_backend(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    default_backend_name: Option<String>,
) -> Result<Option<Arc<dyn ApprovalBackend>>> {
    if backends.is_empty() {
        return Ok(None);
    }
    let registry = build_approval_registry_from(backends, default_backend_name)?;
    let (_name, backend) = registry.resolve(None)?;
    Ok(Some(backend))
}

/// Routes supervised-mode approval requests between the two backend kinds.
///
/// Capability/file prompts go to the profile-configured backend (or the
/// terminal when none is configured); network prompts go to the interactive
/// `NetworkApprovalBackend`. This keeps the two features composable when both
/// are active at once.
struct SupervisedApprovalRouter {
    capability_backend: Option<Arc<dyn ApprovalBackend>>,
    network_backend: Arc<NetworkApprovalBackend>,
    terminal_fallback: Arc<dyn ApprovalBackend>,
}

impl ApprovalBackend for SupervisedApprovalRouter {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        match &self.capability_backend {
            Some(backend) => backend.request_approval(request),
            None => self.terminal_fallback.request_approval(request),
        }
    }

    fn request_network_approval(
        &self,
        request: &nono::NetworkApprovalRequest,
    ) -> Result<nono::NetworkApprovalDecision> {
        self.network_backend.request_network_approval(request)
    }

    fn backend_name(&self) -> &str {
        "supervised-router"
    }
}

/// Combine the profile-configured capability backend with the interactive
/// network approval backend for supervised execution.
///
/// Returns `None` when neither is configured so the caller can fall back to
/// the plain terminal prompt, preserving pre-existing behavior.
pub(crate) fn build_supervised_approval_backend(
    capability_backend: Option<Arc<dyn ApprovalBackend>>,
    network_backend: Option<Arc<NetworkApprovalBackend>>,
) -> Option<Arc<dyn ApprovalBackend>> {
    match (capability_backend, network_backend) {
        (None, None) => None,
        (Some(capability), None) => Some(capability),
        (capability, Some(network)) => Some(Arc::new(SupervisedApprovalRouter {
            capability_backend: capability,
            network_backend: network,
            terminal_fallback: Arc::new(TerminalApproval),
        })),
    }
}

fn build_approval_backends_from(
    backends: &BTreeMap<String, ApprovalBackendConfig>,
) -> Result<BTreeMap<String, Arc<dyn ApprovalBackend>>> {
    let mut built = BTreeMap::new();
    let mut visiting = BTreeSet::new();
    for name in backends.keys() {
        build_approval_backend(name, backends, &mut built, &mut visiting)?;
    }
    Ok(built)
}

fn build_approval_backend(
    name: &str,
    backends: &BTreeMap<String, ApprovalBackendConfig>,
    built: &mut BTreeMap<String, Arc<dyn ApprovalBackend>>,
    visiting: &mut BTreeSet<String>,
) -> Result<Arc<dyn ApprovalBackend>> {
    if let Some(backend) = built.get(name) {
        return Ok(Arc::clone(backend));
    }
    if !visiting.insert(name.to_string()) {
        return Err(NonoError::ConfigParse(format!(
            "approval backend chain contains a cycle at '{name}'"
        )));
    }

    let backend_config = backends
        .get(name)
        .ok_or_else(|| NonoError::ConfigParse(format!("unknown approval backend '{name}'")))?;
    let backend: Arc<dyn ApprovalBackend> = match backend_config.backend_type {
        ApprovalBackendType::Terminal => Arc::new(NamedTerminalApproval {
            name: name.to_string(),
        }),
        ApprovalBackendType::Webhook => Arc::new(WebhookApproval::new(name, backend_config)?),
        ApprovalBackendType::Chain => {
            let mode = backend_config.mode.ok_or_else(|| {
                NonoError::ConfigParse(format!("approval backend '{name}' chain missing mode"))
            })?;
            let mut children = Vec::with_capacity(backend_config.backends.len());
            for child in &backend_config.backends {
                children.push(build_approval_backend(child, backends, built, visiting)?);
            }
            Arc::new(ChainApproval {
                name: name.to_string(),
                mode,
                backends: children,
            })
        }
    };

    visiting.remove(name);
    built.insert(name.to_string(), Arc::clone(&backend));
    Ok(backend)
}

struct NamedTerminalApproval {
    name: String,
}

impl ApprovalBackend for NamedTerminalApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        TerminalApproval.request_approval(request)
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

struct WebhookApproval {
    name: String,
    url: String,
    timeout: Duration,
    http: ureq::Agent,
}

#[derive(Serialize)]
struct WebhookApprovalRequest<'a> {
    backend: &'a str,
    request: &'a ApprovalRequest,
}

#[derive(Deserialize)]
struct WebhookDecisionResponse {
    decision: String,
    #[serde(default)]
    reason: Option<String>,
}

impl WebhookApproval {
    fn new(name: &str, config: &ApprovalBackendConfig) -> Result<Self> {
        let url = config.url.clone().ok_or_else(|| {
            NonoError::ConfigParse(format!("approval backend '{name}' webhook missing url"))
        })?;
        let timeout = Duration::from_secs(config.timeout_secs.unwrap_or(60));
        let tls_config = ureq::tls::TlsConfig::builder()
            .root_certs(ureq::tls::RootCerts::PlatformVerifier)
            .build();
        let http = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .tls_config(tls_config)
            .build()
            .new_agent();
        Ok(Self {
            name: name.to_string(),
            url,
            timeout,
            http,
        })
    }

    fn parse_response(&self, body: &str) -> Result<ApprovalDecision> {
        if let Ok(decision) = serde_json::from_str::<ApprovalDecision>(body) {
            return Ok(decision);
        }

        let response: WebhookDecisionResponse = serde_json::from_str(body).map_err(|e| {
            NonoError::SandboxInit(format!(
                "approval webhook '{}' returned invalid JSON: {e}",
                self.name
            ))
        })?;
        match response.decision.trim().to_ascii_lowercase().as_str() {
            "grant" | "granted" | "approve" | "approved" | "allow" | "allowed" => {
                Ok(ApprovalDecision::Granted)
            }
            "deny" | "denied" | "reject" | "rejected" | "block" | "blocked" => {
                Ok(ApprovalDecision::Denied {
                    reason: response.reason.unwrap_or_else(|| {
                        format!("approval webhook '{}' denied request", self.name)
                    }),
                })
            }
            "timeout" | "timed_out" => Ok(ApprovalDecision::Timeout),
            other => Err(NonoError::SandboxInit(format!(
                "approval webhook '{}' returned unknown decision '{other}'",
                self.name
            ))),
        }
    }
}

impl ApprovalBackend for WebhookApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        let body = serde_json::to_vec(&WebhookApprovalRequest {
            backend: &self.name,
            request,
        })
        .map_err(|e| {
            NonoError::SandboxInit(format!(
                "failed to serialize approval webhook request '{}': {e}",
                self.name
            ))
        })?;

        let mut response = self
            .http
            .post(&self.url)
            .config()
            .http_status_as_error(false)
            .build()
            .header("Content-Type", "application/json")
            .header(
                "User-Agent",
                &format!("nono-cli/{}", env!("CARGO_PKG_VERSION")),
            )
            .send(body)
            .map_err(|e| {
                NonoError::SandboxInit(format!("approval webhook '{}' failed: {e}", self.name))
            })?;

        let status = response.status().as_u16();
        let response_body = response
            .body_mut()
            .with_config()
            .limit(WEBHOOK_RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|e| {
                NonoError::SandboxInit(format!(
                    "failed to read approval webhook '{}' response: {e}",
                    self.name
                ))
            })?;

        if !(200..300).contains(&status) {
            return Ok(ApprovalDecision::Denied {
                reason: format!(
                    "approval webhook '{}' returned HTTP {} after {:?}",
                    self.name, status, self.timeout
                ),
            });
        }

        self.parse_response(&response_body)
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

struct ChainApproval {
    name: String,
    mode: ApprovalChainMode,
    backends: Vec<Arc<dyn ApprovalBackend>>,
}

impl ApprovalBackend for ChainApproval {
    fn request_approval(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        match self.mode {
            ApprovalChainMode::All => self.request_all(request),
            ApprovalChainMode::Any => Ok(self.request_any(request)),
        }
    }

    fn backend_name(&self) -> &str {
        &self.name
    }
}

impl ChainApproval {
    fn request_all(&self, request: &ApprovalRequest) -> Result<ApprovalDecision> {
        for backend in &self.backends {
            match backend.request_approval(request)? {
                ApprovalDecision::Granted => {}
                ApprovalDecision::Denied { reason } => {
                    return Ok(ApprovalDecision::Denied {
                        reason: format!(
                            "{} denied via {}: {reason}",
                            self.name,
                            backend.backend_name()
                        ),
                    });
                }
                ApprovalDecision::Timeout => {
                    return Ok(ApprovalDecision::Denied {
                        reason: format!("{} timed out via {}", self.name, backend.backend_name()),
                    });
                }
            }
        }
        Ok(ApprovalDecision::Granted)
    }

    fn request_any(&self, request: &ApprovalRequest) -> ApprovalDecision {
        let mut reasons = Vec::new();
        for backend in &self.backends {
            match backend.request_approval(request) {
                Ok(ApprovalDecision::Granted) => return ApprovalDecision::Granted,
                Ok(ApprovalDecision::Denied { reason }) => {
                    reasons.push(format!("{} denied: {reason}", backend.backend_name()));
                }
                Ok(ApprovalDecision::Timeout) => {
                    reasons.push(format!("{} timed out", backend.backend_name()));
                }
                Err(err) => {
                    reasons.push(format!("{} errored: {err}", backend.backend_name()));
                }
            }
        }
        ApprovalDecision::Denied {
            reason: format!(
                "{} had no granting backend ({})",
                self.name,
                reasons.join("; ")
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct StaticBackend {
        name: &'static str,
        decision: ApprovalDecision,
    }

    impl ApprovalBackend for StaticBackend {
        fn request_approval(&self, _request: &ApprovalRequest) -> Result<ApprovalDecision> {
            Ok(self.decision.clone())
        }

        fn backend_name(&self) -> &str {
            self.name
        }
    }

    fn request() -> ApprovalRequest {
        ApprovalRequest::Endpoint {
            request_id: "req-1".to_string(),
            route_id: "internal-api".to_string(),
            upstream: "https://api.internal.example".to_string(),
            method: "POST".to_string(),
            path: "/v1/tasks/1/comments".to_string(),
            rule_label: "endpoint_policy.approve[POST /v1/tasks/*/comments]".to_string(),
            reason: None,
            child_pid: 0,
            session_id: "proxy".to_string(),
        }
    }

    #[test]
    fn chain_all_requires_every_backend_to_grant() {
        let chain = ChainApproval {
            name: "all".to_string(),
            mode: ApprovalChainMode::All,
            backends: vec![
                Arc::new(StaticBackend {
                    name: "a",
                    decision: ApprovalDecision::Granted,
                }),
                Arc::new(StaticBackend {
                    name: "b",
                    decision: ApprovalDecision::Denied {
                        reason: "no".to_string(),
                    },
                }),
            ],
        };

        assert!(chain.request_approval(&request()).unwrap().is_denied());
    }

    #[test]
    fn chain_any_grants_if_one_backend_grants() {
        let chain = ChainApproval {
            name: "any".to_string(),
            mode: ApprovalChainMode::Any,
            backends: vec![
                Arc::new(StaticBackend {
                    name: "a",
                    decision: ApprovalDecision::Denied {
                        reason: "no".to_string(),
                    },
                }),
                Arc::new(StaticBackend {
                    name: "b",
                    decision: ApprovalDecision::Granted,
                }),
            ],
        };

        assert!(chain.request_approval(&request()).unwrap().is_granted());
    }

    #[test]
    fn supervised_backend_resolves_configured_webhook() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "security-review".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Webhook,
                url: Some("https://approval.example".to_string()),
                timeout_secs: Some(5),
                mode: None,
                backends: Vec::new(),
            },
        );

        let resolved =
            resolve_supervised_approval_backend(&backends, Some("security-review".to_string()))
                .unwrap();
        match resolved {
            Some(backend) => assert_eq!(backend.backend_name(), "security-review"),
            None => panic!("configured backend should resolve to Some"),
        }
    }

    #[test]
    fn supervised_backend_resolves_single_backend_without_explicit_default() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "gate".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Terminal,
                url: None,
                timeout_secs: None,
                mode: None,
                backends: Vec::new(),
            },
        );

        // No default name given, but the registry default must be present for a
        // supervised resolve to succeed — a lone backend is not auto-selected,
        // so resolve(None) fails closed rather than guess. `Ok(Option<Arc<dyn
        // ApprovalBackend>>)` is not `Debug`, so assert on the `Err` arm directly.
        match resolve_supervised_approval_backend(&backends, None) {
            Ok(_) => panic!("a lone backend without a default must fail closed"),
            Err(err) => assert!(err.to_string().contains("missing approval backend")),
        }
    }

    #[test]
    fn supervised_backend_none_when_unconfigured() {
        let backends = BTreeMap::new();
        let resolved = resolve_supervised_approval_backend(&backends, None).unwrap();
        assert!(
            resolved.is_none(),
            "no configured backends must fall back to terminal (None)"
        );
    }

    #[test]
    fn supervised_backend_unknown_default_is_hard_error() {
        let mut backends = BTreeMap::new();
        backends.insert(
            "gate".to_string(),
            ApprovalBackendConfig {
                backend_type: ApprovalBackendType::Terminal,
                url: None,
                timeout_secs: None,
                mode: None,
                backends: Vec::new(),
            },
        );

        match resolve_supervised_approval_backend(&backends, Some("missing".to_string())) {
            Ok(_) => panic!("an unknown default backend must be a hard error"),
            Err(err) => assert!(err.to_string().contains("unknown approval backend")),
        }
    }

    #[test]
    fn webhook_response_parser_accepts_simple_decision_shape() {
        let backend = WebhookApproval {
            name: "security-review".to_string(),
            url: "https://approval.example".to_string(),
            timeout: Duration::from_secs(1),
            http: ureq::Agent::new_with_defaults(),
        };

        assert!(
            backend
                .parse_response(r#"{"decision":"granted"}"#)
                .unwrap()
                .is_granted()
        );
        assert!(
            backend
                .parse_response(r#"{"decision":"denied","reason":"policy"}"#)
                .unwrap()
                .is_denied()
        );
    }
}
