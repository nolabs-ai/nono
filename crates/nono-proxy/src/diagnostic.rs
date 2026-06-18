//! Proxy startup diagnostics (credential load and OAuth exchange failures).

use serde::{Deserialize, Serialize};

/// Severity of a proxy diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProxyDiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Stable diagnostic code for proxy credential and route issues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProxyDiagnosticCode {
    CredentialNotFound,
    CredentialUnavailable,
    OAuthClientIdUnavailable,
    OAuthClientSecretUnavailable,
    OAuthTokenExchangeFailed,
}

impl ProxyDiagnosticCode {
    /// Stable snake_case label matching JSON serialization.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialNotFound => "credential_not_found",
            Self::CredentialUnavailable => "credential_unavailable",
            Self::OAuthClientIdUnavailable => "oauth_client_id_unavailable",
            Self::OAuthClientSecretUnavailable => "oauth_client_secret_unavailable",
            Self::OAuthTokenExchangeFailed => "oauth_token_exchange_failed",
        }
    }
}

/// One proxy startup diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyDiagnostic {
    pub code: ProxyDiagnosticCode,
    pub severity: ProxyDiagnosticSeverity,
    pub route_prefix: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_ref: Option<String>,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
}

impl ProxyDiagnostic {
    #[must_use]
    pub fn warning(
        code: ProxyDiagnosticCode,
        route_prefix: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            code,
            severity: ProxyDiagnosticSeverity::Warning,
            route_prefix: route_prefix.into(),
            credential_ref: None,
            message: message.into(),
            hint: None,
        }
    }

    #[must_use]
    pub fn with_credential_ref(mut self, credential_ref: impl Into<String>) -> Self {
        self.credential_ref = Some(credential_ref.into());
        self
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_diagnostic_serializes_stable_code() {
        let diagnostic = ProxyDiagnostic::warning(
            ProxyDiagnosticCode::CredentialNotFound,
            "openai",
            "Credential not found",
        )
        .with_credential_ref("op://vault/item/secret");
        let json = serde_json::to_string(&diagnostic).expect("json");
        assert!(json.contains("\"credential_not_found\""));
        assert!(json.contains("\"openai\""));
    }
}
