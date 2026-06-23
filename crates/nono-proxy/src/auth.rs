// Adding a new auth mechanism: add a variant here and a corresponding handler
// branch in reverse.rs (handle_spiffe_route / handle_oauth2_like).

use crate::error::{ProxyError, Result};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Auth material resolved for a single upstream request.
pub enum UpstreamAuthMaterial {
    /// Token to inject into a request header. `credential_format` is a template
    /// where `{}` is replaced by the token (e.g. `Bearer {}`).
    BearerToken {
        header: String,
        token: Zeroizing<String>,
        workload_spiffe_id: String,
        /// Format applied to the token when building the header value.
        credential_format: String,
    },
}

impl UpstreamAuthMaterial {
    pub fn spiffe_audit_context(&self) -> nono::undo::SpiffeAuditContext {
        let UpstreamAuthMaterial::BearerToken {
            workload_spiffe_id,
            token,
            ..
        } = self;
        nono::undo::SpiffeAuditContext {
            trust_domain: extract_trust_domain(workload_spiffe_id),
            workload_spiffe_id: workload_spiffe_id.clone(),
            svid_type: "jwt".to_string(),
            source: "spire-workload-api".to_string(),
            upstream_spiffe_id: None,
            delegation: crate::spiffe::delegation_from_jwt(token.as_str()),
        }
    }
}

/// A live credential source that can produce [`UpstreamAuthMaterial`] on demand.
///
/// Built once at proxy startup (fail-closed if the source is unreachable) and
/// consulted on every upstream request. Each variant owns its own cache and
/// refresh logic.
pub enum ManagedUpstreamAuth {
    /// JWT-SVID fetched from the SPIRE Workload API and injected as a bearer token.
    SpiffeJwt(Arc<crate::spiffe::SpiffeJwtSource>),
}

impl ManagedUpstreamAuth {
    /// Acquire the material needed for one upstream request.
    #[must_use = "dropping credential material without using it wastes an SVID fetch"]
    pub async fn acquire(&self) -> Result<UpstreamAuthMaterial> {
        match self {
            ManagedUpstreamAuth::SpiffeJwt(src) => {
                let (token, spiffe_id) = src
                    .fetch_token(&src.audience)
                    .await
                    .map_err(|e| ProxyError::Credential(e.to_string()))?;
                let fmt = crate::config::resolved_credential_format(&src.inject_header, None);
                Ok(UpstreamAuthMaterial::BearerToken {
                    header: src.inject_header.clone(),
                    token,
                    workload_spiffe_id: spiffe_id,
                    credential_format: fmt,
                })
            }
        }
    }

    pub fn audit_mechanism(&self) -> nono::undo::NetworkAuditAuthMechanism {
        match self {
            ManagedUpstreamAuth::SpiffeJwt(_) => {
                nono::undo::NetworkAuditAuthMechanism::SpiffeJwtBearer
            }
        }
    }

    pub fn audit_injection_mode(&self) -> Option<nono::undo::NetworkAuditInjectionMode> {
        match self {
            ManagedUpstreamAuth::SpiffeJwt(_) => {
                Some(nono::undo::NetworkAuditInjectionMode::SpiffeJwt)
            }
        }
    }
}

/// `spiffe://prod.example/workload` → `"prod.example"`.
/// Returns `""` and logs a warning for malformed IDs.
pub fn extract_trust_domain(spiffe_id: &str) -> String {
    match spiffe_id
        .strip_prefix("spiffe://")
        .and_then(|s| s.split('/').next())
    {
        Some(domain) => domain.to_string(),
        None => {
            tracing::warn!(
                "extract_trust_domain: malformed SPIFFE ID (missing spiffe:// prefix): \
                 audit trust_domain will be empty"
            );
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_trust_domain_valid() {
        assert_eq!(
            extract_trust_domain("spiffe://prod.example/workload"),
            "prod.example"
        );
    }

    #[test]
    fn extract_trust_domain_no_path() {
        assert_eq!(
            extract_trust_domain("spiffe://prod.example"),
            "prod.example"
        );
    }

    #[test]
    fn extract_trust_domain_invalid() {
        assert_eq!(extract_trust_domain("not-a-spiffe-id"), "");
    }

    #[test]
    fn extract_trust_domain_empty() {
        assert_eq!(extract_trust_domain(""), "");
    }
}
