//! Open managed-policy v1 contract; mirrored in nono-cli.
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "1";
pub const REFRESH_PATH: &str = "/api/v1/policy/refresh";
pub const TRUST_PATH: &str = "/api/v1/policy/trust-root";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTrustRoot {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRefreshRequest {
    pub protocol_version: String,
    pub platform: String,
    pub home: String,
    pub workdir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeliveredPolicy {
    pub profile_id: String,
    pub revision: i64,
    pub delta_version: i64,
    pub content_digest: String,
    pub profile_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyClaims {
    pub protocol_version: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub request_id: String,
    pub issued_at: DateTime<Utc>,
    pub management_mode: String,
    pub assignment_version: String,
    pub resolved_via: serde_json::Value,
    pub policy: Option<DeliveredPolicy>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPolicyResponse {
    pub algorithm: String,
    pub key_id: String,
    /// Base64url JSON claims; the signature covers the decoded bytes.
    pub payload: String,
    pub signature: String,
}
