//! Login-authorized device enrollment, independent of the OAuth session key.

use serde::{Deserialize, Serialize};

pub(crate) const ENROLLMENT_PATH: &str = "/api/v1/auth/oauth/enroll";
pub(crate) const ENROLLMENT_SCOPE: &str = "nono:enroll";
pub(crate) const REENROLLMENT_SCOPE: &str = "nono:reenroll";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EnrollmentIntent {
    pub protocol_version: String,
    pub issuer: String,
    pub tenant_id: String,
    pub user_id: String,
    pub login_key_thumbprint: String,
    pub public_key: String,
    pub display_name: String,
    pub timestamp_ms: i64,
    pub request_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_subject_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group_id: Option<String>,
}

impl EnrollmentIntent {
    pub(crate) fn signing_bytes(&self) -> std::result::Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(&("nono-login-enrollment-v1", "POST", ENROLLMENT_PATH, self))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LoginEnrollmentRequest {
    pub refresh_token: String,
    pub intent: EnrollmentIntent,
    pub signature: String,
}

impl Drop for LoginEnrollmentRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.refresh_token.zeroize();
    }
}

#[derive(Serialize)]
pub(crate) struct EnrollmentOptionsRequest {
    pub refresh_token: String,
    pub tenant_id: String,
    pub user_id: String,
    pub public_key: String,
}

impl Drop for EnrollmentOptionsRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.refresh_token.zeroize();
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct EnrollmentOptions {
    pub protocol_version: String,
    pub tenant_id: String,
    pub groups: Vec<crate::enrollment_group::EnrollmentGroup>,
    pub existing: Option<ExistingEnrollment>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ExistingEnrollment {
    pub subject_id: String,
    pub groups: Vec<crate::enrollment_group::EnrollmentGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum GroupAction {
    List,
    Memberships,
    Add { group_id: String },
    Remove { group_id: String },
    Move { from: String, to: String },
}

#[derive(Serialize)]
pub(crate) struct GroupRequest {
    pub refresh_token: String,
    pub tenant_id: String,
    pub user_id: String,
    pub subject_id: Option<String>,
    pub action: GroupAction,
}

impl Drop for GroupRequest {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.refresh_token.zeroize();
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct GroupResponse {
    pub protocol_version: String,
    pub tenant_id: String,
    pub subject_id: Option<String>,
    pub groups: Vec<crate::enrollment_group::EnrollmentGroup>,
    pub memberships: Vec<crate::enrollment_group::EnrollmentGroup>,
    pub changed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn group_management_matches_the_shared_contract() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/login-enrollment-v1.json"
        ))
        .expect("fixture");
        let expected = &fixture["group_request"];
        let request = GroupRequest {
            refresh_token: expected["refresh_token"].as_str().expect("token").into(),
            tenant_id: expected["tenant_id"].as_str().expect("tenant").into(),
            user_id: expected["user_id"].as_str().expect("user").into(),
            subject_id: Some(expected["subject_id"].as_str().expect("subject").into()),
            action: GroupAction::Move {
                from: expected["action"]["from"].as_str().expect("from").into(),
                to: expected["action"]["to"].as_str().expect("to").into(),
            },
        };
        assert_eq!(serde_json::to_value(&request).expect("request"), *expected);
        let response: GroupResponse =
            serde_json::from_value(fixture["group_response"].clone()).expect("response");
        assert!(response.changed);
        assert_eq!(response.tenant_id, request.tenant_id);
        assert_eq!(response.subject_id, request.subject_id);
    }

    #[test]
    fn signing_bytes_match_the_shared_contract() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/login-enrollment-v1.json"
        ))
        .expect("fixture");
        for (intent, canonical) in [
            ("intent", "canonical"),
            ("replacement_intent", "replacement_canonical"),
            ("group_intent", "group_canonical"),
        ] {
            let intent: EnrollmentIntent =
                serde_json::from_value(fixture[intent].clone()).expect("intent");
            assert_eq!(
                intent.signing_bytes().expect("canonical"),
                fixture[canonical].as_str().expect("bytes").as_bytes()
            );
        }
    }
}
