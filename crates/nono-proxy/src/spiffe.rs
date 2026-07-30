//! SPIFFE/SPIRE Workload API credential sources.
//!
//! - [`SpiffeJwtSource`] — fetches JWT-SVIDs on demand, refreshes before expiry.
//!
//! X.509-SVID support (mTLS connector with atomic rotation) is planned as a
//! future `SpiffeAuthConfig` variant once the TLS-intercept CONNECT path is
//! wired to support it for HTTPS upstreams.
//!
//! SVID private key material is never written to disk or logged.

use crate::error::{ProxyError, Result};
use base64::Engine as _;
use spiffe_workload::{JwtSource, SpiffeId};
use std::sync::Arc;
use tracing::{debug, warn};
use zeroize::Zeroizing;

// Warn when a freshly-fetched JWT-SVID has fewer than this many seconds left —
// indicates SPIRE JWT TTL is too short. Refresh is per-request via the agent cache.
const JWT_REFRESH_SECS: i64 = 60;

/// JWT-SVID source backed by the SPIRE Workload API.
///
/// Tokens are fetched on demand via the agent cache; a warning is logged when
/// fewer than `JWT_REFRESH_SECS` remain (see `fetch_token`).
pub struct SpiffeJwtSource {
    inner: Arc<JwtSource>,
    pub audience: Vec<String>,
    pub inject_header: String,
    pub credential_format: Option<String>,
    pub svid_hint: Option<SpiffeId>,
}

impl std::fmt::Debug for SpiffeJwtSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpiffeJwtSource").finish()
    }
}

impl SpiffeJwtSource {
    /// Fails closed if the socket is unreachable.
    pub async fn connect(
        socket_path: &str,
        audience: Vec<String>,
        inject_header: String,
        credential_format: Option<String>,
        svid_hint: Option<&str>,
    ) -> Result<Self> {
        let endpoint = format!("unix:{socket_path}");
        let source = JwtSource::builder()
            .endpoint(&endpoint)
            .initial_sync_timeout(std::time::Duration::from_secs(10))
            .build()
            .await
            .map_err(|e| {
                ProxyError::Config(format!(
                    "SPIFFE JWT source failed to connect to '{socket_path}': {e}"
                ))
            })?;

        let svid_hint = svid_hint
            .map(|h| {
                SpiffeId::new(h).map_err(|e| {
                    ProxyError::Config(format!("invalid svid_hint SPIFFE ID '{h}': {e}"))
                })
            })
            .transpose()?;

        debug!("SPIFFE JWT source connected to {}", socket_path);
        Ok(Self {
            inner: Arc::new(source),
            audience,
            inject_header,
            credential_format,
            svid_hint,
        })
    }

    /// Returns `(token, spiffe_id)` for the requested audience.
    pub async fn fetch_token(&self, audience: &[String]) -> Result<(Zeroizing<String>, String)> {
        let svid = self
            .inner
            .fetch_jwt_svid_with_id(audience.iter().map(String::as_str), self.svid_hint.as_ref())
            .await
            .map_err(|e| ProxyError::Credential(format!("SPIFFE JWT-SVID fetch failed: {e}")))?;

        let now_ts = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            Err(e) => i64::try_from(e.duration().as_secs())
                .map(|s| -s)
                .unwrap_or(i64::MIN),
        };
        let exp_ts = svid.expiry().unix_timestamp();
        let remaining = exp_ts - now_ts;

        if remaining <= 0 {
            return Err(ProxyError::Credential(format!(
                "SPIFFE JWT-SVID has already expired ({}s ago); \
                 check SPIRE JWT TTL and system clock skew",
                -remaining
            )));
        }

        check_nbf(svid.token(), now_ts)?;

        if remaining < JWT_REFRESH_SECS {
            warn!(
                "SPIFFE JWT-SVID expires in {}s, below the {}s refresh threshold; \
                 check SPIRE JWT TTL configuration",
                remaining, JWT_REFRESH_SECS
            );
        }

        let spiffe_id = svid.spiffe_id().to_string();
        Ok((Zeroizing::new(svid.token().to_string()), spiffe_id))
    }
}

/// Rejects a JWT whose `nbf` claim is in the future.
///
/// SPIRE does not expose `nbf` via a dedicated SDK accessor, so we parse the
/// raw base64url payload. If the token has no `nbf` claim we pass — SPIRE
/// typically omits it when `nbf == iat`.
fn check_nbf(token: &str, now_ts: i64) -> crate::error::Result<()> {
    let Some(payload_b64) = token.split('.').nth(1) else {
        return Ok(());
    };
    let Ok(decoded) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(payload_b64) else {
        return Ok(());
    };
    let Ok(claims) = serde_json::from_slice::<serde_json::Value>(&decoded) else {
        return Ok(());
    };
    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64())
        && now_ts < nbf
    {
        return Err(ProxyError::Credential(format!(
            "SPIFFE JWT-SVID is not yet valid (nbf={nbf}, now={now_ts}); \
             check system clock skew"
        )));
    }
    Ok(())
}

/// Parses the `act` claim from a JWT-SVID payload for audit context.
///
/// SPIRE has already verified the signature; this is JSON parsing only.
/// Returns `None` when no `act` claim is present.
pub fn delegation_from_jwt(token: &str) -> Option<nono::undo::SpiffeDelegationContext> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;

    let act = claims.get("act")?;
    let authorized_by = act.get("sub")?.as_str()?.to_string();
    let on_behalf_of = claims
        .get("sub")
        .and_then(|s| s.as_str())
        .map(str::to_string);

    let mut depth: u32 = 1;
    let mut cursor = act;
    while let Some(nested) = cursor.get("act") {
        depth = depth.saturating_add(1);
        cursor = nested;
    }

    Some(nono::undo::SpiffeDelegationContext {
        authorized_by,
        on_behalf_of,
        chain_depth: depth,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use spiffe_workload::JwtSource;

    #[tokio::test]
    async fn test_jwt_source_fails_closed_on_missing_socket() {
        let endpoint = "unix:/tmp/nono-test-nonexistent-spire-agent.sock";
        let result = JwtSource::builder()
            .endpoint(endpoint)
            .initial_sync_timeout(std::time::Duration::from_secs(1))
            .build()
            .await;
        assert!(result.is_err(), "should fail when socket does not exist");
    }
}
