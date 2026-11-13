//! Open local-policy contract; mirrored by platform-protocol.
use serde::{Deserialize, Serialize};

pub(crate) const POLICY_PATH: &str = "/api/v1/policy/local";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyClaims {
    pub protocol_version: String,
    pub tenant_id: String,
    pub subject_id: String,
    pub request_id: String,
    pub issued_at: chrono::DateTime<chrono::Utc>,
    pub source: String,
    pub source_name: Option<String>,
    pub policy: Option<PolicyDocument>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PolicyDocument {
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    pub revision: i64,
    pub content_digest: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub profile_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedPolicy {
    pub algorithm: String,
    pub key_id: String,
    pub public_key: String,
    pub payload: String,
    pub signature: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn claims_match_shared_wire_fixture() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../tests/fixtures/local-policy-v1.json"))
                .expect("fixture");
        for fixture in [&fixture, &fixture["not_modified"]] {
            let claims: PolicyClaims =
                serde_json::from_value(fixture["claims"].clone()).expect("claims");
            assert_eq!(
                serde_json::to_string(&claims).expect("canonical"),
                fixture["canonical"].as_str().expect("bytes")
            );
            let signed: SignedPolicy =
                serde_json::from_value(fixture["signed"].clone()).expect("signed response");
            assert_eq!(
                serde_json::to_value(signed).expect("serialize"),
                fixture["signed"]
            );
        }
    }
}
