//! Login-authorized device enrollment, independent of the OAuth session key.

use serde::{Deserialize, Serialize};

pub(crate) const ENROLLMENT_PATH: &str = "/api/v1/auth/oauth/enroll";
pub(crate) const ENROLLMENT_SCOPE: &str = "nono:enroll";

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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_bytes_match_the_shared_contract() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/login-enrollment-v1.json"
        ))
        .expect("fixture");
        let intent: EnrollmentIntent =
            serde_json::from_value(fixture["intent"].clone()).expect("intent");
        assert_eq!(
            intent.signing_bytes().expect("canonical"),
            fixture["canonical"].as_str().expect("bytes").as_bytes()
        );
    }
}
