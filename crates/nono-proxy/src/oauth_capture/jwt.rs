use crate::error::{ProxyError, Result};
use base64::Engine;

pub(super) fn jwt_shaped_phantom(phantom: &str) -> Result<String> {
    let header =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#);
    let payload = serde_json::json!({
        "iss": "nono",
        "sub": phantom,
        "aud": "nono",
        "iat": 0,
        "exp": 4_102_444_800_u64
    });
    let payload = serde_json::to_vec(&payload).map_err(|err| {
        ProxyError::HttpParse(format!("failed to encode JWT phantom payload: {err}"))
    })?;
    let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload);
    Ok(format!("{header}.{payload}.{phantom}"))
}
