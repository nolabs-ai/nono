//! Minimal self-hosted agent-provider token issuance. No enrollment service.

use super::{AGENT_METADATA_DOC, ALGORITHM, public_jwk};
use crate::error::{ProxyError, Result};
use aauth_core::keys::PrivateKey;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use zeroize::Zeroizing;

pub(super) fn issue(
    key: &PrivateKey,
    kid: &str,
    issuer: &str,
    agent_id: &str,
    created: i64,
) -> Result<(Zeroizing<String>, i64)> {
    let expires = created
        .checked_add(3600)
        .ok_or_else(|| ProxyError::Credential("aauth agent token expiry overflow".to_string()))?;
    let header = json!({"alg": ALGORITHM, "typ": "aa-agent+jwt", "kid": kid});
    let claims = json!({
        "iss": issuer,
        "sub": agent_id,
        "dwk": AGENT_METADATA_DOC,
        "jti": uuid::Uuid::new_v4().to_string(),
        "iat": created,
        "exp": expires,
        "cnf": {"jwk": public_jwk(key, Some(kid))},
    });
    // aauth-core 0.1.2's JWT encoder insists on the obsolete EdDSA identifier.
    // Serialize compact JWS here, using its existing Ed25519 signing primitive.
    let encode = |value: &serde_json::Value| {
        serde_json::to_vec(value)
            .map(|bytes| URL_SAFE_NO_PAD.encode(bytes))
            .map_err(|_| ProxyError::Credential("aauth agent token encoding failed".to_string()))
    };
    let mut jwt = Zeroizing::new(format!("{}.{}", encode(&header)?, encode(&claims)?));
    let signature = key.sign(jwt.as_bytes());
    jwt.push('.');
    jwt.push_str(&URL_SAFE_NO_PAD.encode(signature));
    Ok((jwt, expires))
}
